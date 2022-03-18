// Copyright (C) 2019-2022 Aleo Systems Inc.
// This file is part of the snarkOS library.

// The snarkOS library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// The snarkOS library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with the snarkOS library. If not, see <https://www.gnu.org/licenses/>.

#[cfg(feature = "postgres")]
use crate::storage::PostgresOpts;
use crate::{constants::*, known_network::KnownNetwork, metrics::NetworkMetrics};
use snarkos_environment::{
    helpers::{NodeType, State},
    CurrentNetwork,
};
use snarkos_network::Data;
use snarkos_storage::BlockLocators;
use snarkos_synthetic_node::{ClientMessage, SynthNode, MESSAGE_LENGTH_PREFIX_SIZE};
use snarkvm::traits::Network;

use clap::Parser;
use pea2pea::{
    protocols::{Disconnect, Handshake, Reading, Writing},
    Config,
    Node as Pea2PeaNode,
    Pea2Pea,
};
use rand::{rngs::SmallRng, seq::IteratorRandom, SeedableRng};
use std::{
    convert::TryInto,
    io::{self, Read},
    net::SocketAddr,
    ops::Deref,
    sync::Arc,
    time::Duration,
};
use time::OffsetDateTime;
use tokio::{sync::Mutex, task};
#[cfg(feature = "postgres")]
use tokio_postgres::Client as StorageClient;
use tracing::*;

#[cfg(not(feature = "postgres"))]
pub struct StorageClient;

// CLI
#[derive(Debug, Parser)]
pub struct Opts {
    /// Specify the IP address and port for the node server.
    #[clap(long = "addr", short = 'a', parse(try_from_str), default_value = "0.0.0.0:4132")]
    pub addr: SocketAddr,
    #[cfg(feature = "postgres")]
    #[clap(flatten)]
    pub postgres: PostgresOpts,
}

/// Represents the crawler together with network metrics it has collected.
#[derive(Clone)]
pub struct Crawler {
    synth_node: SynthNode,
    pub known_network: Arc<KnownNetwork>,
    pub storage: Option<Arc<Mutex<StorageClient>>>,
}

impl Pea2Pea for Crawler {
    fn node(&self) -> &Pea2PeaNode {
        self.synth_node.node()
    }
}

impl Deref for Crawler {
    type Target = SynthNode;

    fn deref(&self) -> &Self::Target {
        &self.synth_node
    }
}

impl Crawler {
    /// Creates the crawler with the given configuration.
    pub async fn new(opts: Opts, storage: Option<StorageClient>) -> Self {
        let config = Config {
            name: Some("snarkOS crawler".into()),
            listener_ip: Some(opts.addr.ip()),
            desired_listening_port: Some(opts.addr.port()),
            max_connections: MAXIMUM_NUMBER_OF_PEERS as u16,
            max_handshake_time_ms: MAX_HANDSHAKE_TIME_MS,
            read_buffer_size: READ_BUFFER_SIZE,
            ..Default::default()
        };

        let pea2pea_node = Pea2PeaNode::new(Some(config)).await.unwrap();
        let client_state = Default::default();
        let node = Self {
            synth_node: SynthNode::new(pea2pea_node, client_state),
            known_network: Arc::new(KnownNetwork::default()),
            storage: storage.map(|s| Arc::new(Mutex::new(s))),
        };

        node.enable_disconnect().await;
        node.enable_handshake().await;
        node.enable_reading().await;
        node.enable_writing().await;

        node
    }

    /// Returns the randomness used by the crawler.
    fn rng(&self) -> SmallRng {
        // TODO: should be good enough, but double-check if it's not too slow
        SmallRng::from_entropy()
    }

    /// Checks whether the crawler is already connected or connecting to the given address.
    pub fn is_connected(&self, addr: SocketAddr) -> bool {
        // Handshakes can take a while, so check connecting addresses too.
        // note: these take care of connected addresses
        if self.node().is_connecting(addr) || self.node().is_connected(addr) {
            return true;
        }

        // note: this takes care of listening addresses
        self.state.peers.read().contains_key(&addr)
    }

    /// Spawns a task dedicated to peer maintenance.
    pub fn update_peers(&self) {
        let node = self.clone();
        task::spawn(async move {
            loop {
                info!(parent: node.node().span(), "crawling the network for more peers; asking peers for their peers");
                node.send_broadcast(ClientMessage::PeerRequest).unwrap();

                // Disconnect from peers that we've collected sufficient information on or that have become stale.
                let addrs_to_disconnect = node.known_network.addrs_to_disconnect();
                for addr in &addrs_to_disconnect {
                    if let Some(addr) = node.get_peer_connected_addr(*addr) {
                        let node_clone = node.clone();
                        task::spawn(async move {
                            node_clone.node().disconnect(addr).await;
                        });
                    }
                }

                // Connect to peers we haven't crawled in a while.
                let addrs_to_connect = node.known_network.addrs_to_connect();
                for addr in addrs_to_connect
                    .into_iter()
                    // FIXME: Figure out how to get rid of this overlap.
                    .filter(|addr| !addrs_to_disconnect.contains(addr))
                    .choose_multiple(&mut node.rng(), NUM_CONCURRENT_CONNECTION_ATTEMPTS as usize)
                {
                    if !node.is_connected(addr) {
                        let node_clone = node.clone();
                        task::spawn(async move {
                            let connection_init_timestamp = OffsetDateTime::now_utc();
                            if node_clone.node().connect(addr).await.is_ok() {
                                // Immediately ask for the new peer's peers.
                                let _ = node_clone.send_direct_message(addr, ClientMessage::PeerRequest);
                                node_clone.known_network.connected_to_node(addr, connection_init_timestamp, true);
                            } else {
                                node_clone.known_network.connected_to_node(addr, connection_init_timestamp, false);
                            }
                        });
                    }
                }

                tokio::time::sleep(Duration::from_secs(PEER_UPDATE_INTERVAL_SECS)).await;
            }
        });
    }

    /// Spawns a task periodically storing crawling information in a database.
    #[cfg(feature = "postgres")]
    fn store_known_network(&self) {
        let node = self.clone();
        tokio::spawn(async move {
            loop {
                let nodes = node.known_network.nodes();
                let connections = node.known_network.connections();
                let conns = connections.clone();
                let metrics = task::spawn_blocking(move || NetworkMetrics::new(conns, nodes)).await.unwrap();

                if let Err(e) = node.write_crawling_data(connections, metrics).await {
                    error!(parent: node.node().span(), "storage write error: {}", e);
                }
                tokio::time::sleep(Duration::from_secs(DB_WRITE_INTERVAL_SECS.into())).await;
            }
        });
    }

    /// Spawns a task printing the desired crawling information in the logs.
    #[cfg(not(feature = "postgres"))]
    fn log_known_network(&self) {
        let node = self.clone();
        tokio::spawn(async move {
            loop {
                let connections = node.known_network.connections();
                let nodes = node.known_network.nodes();
                let summary = task::spawn_blocking(move || NetworkMetrics::new(connections, nodes).map(|metrics| metrics.summary()))
                    .await
                    .unwrap();
                if let Some(summary) = summary {
                    info!(parent: node.node().span(), "{}", summary);
                }
                tokio::time::sleep(Duration::from_secs(LOG_INTERVAL_SECS)).await;
            }
        });
    }

    /// Starts the usual periodic activities of a crawler node.
    pub fn run_periodic_tasks(&self) {
        #[cfg(feature = "postgres")]
        self.store_known_network();
        #[cfg(not(feature = "postgres"))]
        self.log_known_network();
        self.update_peers();
    }
}

/// A wrapper type for inbound messages, allowing the crawler to immediately reject undesired ones.
pub enum InboundMessage {
    Handled(Box<ClientMessage>),
    Unhandled(u16),
}

/// Inbound message processing logic for the crawler nodes.
#[async_trait::async_trait]
impl Reading for Crawler {
    type Message = InboundMessage;

    // This implementation is slightly low-level in order to discard unwanted messages without a performance penalty.
    fn read_message<R: io::Read>(&self, source: SocketAddr, reader: &mut R) -> io::Result<Option<Self::Message>> {
        // The read buffer should be just enough to read the longest expected message.
        let mut buf = [0u8; READ_BUFFER_SIZE];

        // Read the length of the inbound message.
        let read_len = reader.read(&mut buf[..MESSAGE_LENGTH_PREFIX_SIZE])?;

        // This is unlikely, but mark the message as incomplete if too few bytes are available.
        if read_len < 2 {
            return Ok(None);
        }

        // Read the message's length.
        let len = u32::from_le_bytes(buf[..MESSAGE_LENGTH_PREFIX_SIZE].try_into().unwrap()) as usize;

        // Only read the message ID first.
        let read_len = reader.read(&mut buf[..2])?;

        // This is unlikely, but mark the message as incomplete if too few bytes are available.
        if read_len < 2 {
            return Ok(None);
        }

        // Read the message ID to filter out undesirable messages.
        let message_id: u16 = bincode::deserialize(&buf[..2]).map_err(|_| io::ErrorKind::InvalidData)?;

        // Discard unwanted messages and those longer than the buffer's capacity.
        if !ACCEPTED_MESSAGE_IDS.contains(&message_id) || len > buf.len() {
            // Advance the reader to discard the unwanted bytes.
            let read_len = io::copy(&mut reader.take(len as u64 - 2), &mut io::sink())?;
            if read_len != len as u64 - 2 {
                return Ok(None);
            }
            return Ok(Some(InboundMessage::Unhandled(message_id)));
        }

        // Read the remaining number of bytes indicated by the length prefix.
        let read_len = reader.read(&mut buf[2..][..len - 2])?;

        // This one is likely: mark the message as incomplete if it's lacking bytes.
        if read_len != len - 2 {
            return Ok(None);
        }

        // Only deserialize the desired messages.
        match ClientMessage::deserialize(&mut io::Cursor::new(&buf[..len])) {
            Ok(msg) => {
                debug!(parent: self.node().span(), "received a {} from {}", msg.name(), source);
                Ok(Some(InboundMessage::Handled(Box::new(msg))))
            }
            Err(e) => {
                error!(parent: self.node().span(), "a message from {} failed to deserialize: {}", source, e);
                Err(io::ErrorKind::InvalidData.into())
            }
        }
    }

    async fn process_message(&self, source: SocketAddr, message: Self::Message) -> io::Result<()> {
        if let InboundMessage::Handled(message) = message {
            match *message {
                ClientMessage::Disconnect(reason) => {
                    debug!(parent: self.node().span(), "peer {} disconnected for the following reason: {:?}", source, reason);
                    Ok(())
                }
                ClientMessage::PeerRequest => {
                    self.process_peer_request(source)?;
                    Ok(())
                }
                ClientMessage::PeerResponse(peer_ips) => {
                    self.process_peer_response(source, peer_ips)?;
                    Ok(())
                }
                ClientMessage::Ping(version, _fork_depth, node_type, state, _block_hash, block_header) => {
                    // TODO: we should probably manually deserialize the header, as we only need the
                    // height, and we need to be able to quickly handle any number of such messages
                    let block_header = block_header.deserialize().await.map_err(|_| io::ErrorKind::InvalidData)?;
                    self.process_ping(source, node_type, version, state, block_header.height())
                }
                _ => {
                    unreachable!();
                }
            }
        } else if let InboundMessage::Unhandled(id) = message {
            if ACCEPTED_MESSAGE_IDS.contains(&id) {
                warn!(parent: self.node().span(), "rejected an unexpected message (ID: {}); double-check the buffer size", id);
            }

            Ok(())
        } else {
            unreachable!();
        }
    }
}

// Helper methods.
impl Crawler {
    fn process_peer_request(&self, source: SocketAddr) -> io::Result<()> {
        let peers = self
            .known_network
            .nodes()
            .into_iter()
            .filter(|(_, meta)| meta.state.is_some())
            .map(|(addr, _)| addr)
            .choose_multiple(&mut self.rng(), SHARED_PEER_COUNT);

        debug!(parent: self.node().span(), "sending a PeerResponse to {}", source);
        self.send_direct_message(source, ClientMessage::PeerResponse(peers))?;

        Ok(())
    }

    fn process_peer_response(&self, source: SocketAddr, mut peer_addrs: Vec<SocketAddr>) -> io::Result<()> {
        let node = self.clone();
        task::spawn(async move {
            peer_addrs.retain(|addr| node.node().listening_addr().unwrap() != *addr);

            // Insert the address into the known network and update the crawl state.
            if let Some(listening_addr) = node.get_peer_listening_addr(source) {
                node.known_network.received_peers(listening_addr, peer_addrs.clone());
            }

            for addr in peer_addrs {
                if !node.is_connected(addr) {
                    debug!(parent: node.node().span(), "trying to connect to {}'s peer {}", source, addr);

                    // Only connect if this address needs to be crawled.
                    if node.known_network.should_be_connected_to(addr) {
                        let node_clone = node.clone();
                        task::spawn(async move {
                            let connection_init_timestamp = OffsetDateTime::now_utc();
                            if node_clone.node().connect(addr).await.is_ok() {
                                node_clone.known_network.connected_to_node(addr, connection_init_timestamp, true);

                                // Immediately ask for the new peer's peers.
                                let _ = node_clone.send_direct_message(addr, ClientMessage::PeerRequest);
                            } else {
                                node_clone.known_network.connected_to_node(addr, connection_init_timestamp, false);
                            }
                        });
                    }
                }
            }
        });

        Ok(())
    }

    fn process_ping(&self, source: SocketAddr, node_type: NodeType, version: u32, state: State, block_height: u32) -> io::Result<()> {
        // Don't reject non-compliant peers in order to have the fullest image of the network.

        debug!(parent: self.node().span(), "peer {} is at height {}", source, block_height);

        // Update the known network nodes and update the crawl state.
        if let Some(listening_addr) = self.get_peer_listening_addr(source) {
            self.known_network
                .received_ping(listening_addr, node_type, version, state, block_height);
        }

        let genesis = CurrentNetwork::genesis_block();
        let msg = ClientMessage::Pong(
            None,
            // TODO: we'll be sending this out very often, so we might as well create this
            // object just once and copy it over whenever needed.
            Data::Object(
                BlockLocators::<CurrentNetwork>::from(vec![(genesis.height(), (genesis.hash(), None))].into_iter().collect()).unwrap(),
            ),
        );

        debug!(parent: self.node().span(), "sending a Pong to {}", source);
        self.send_direct_message(source, msg)?;

        Ok(())
    }
}
