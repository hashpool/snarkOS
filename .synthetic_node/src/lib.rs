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

use snarkos_environment::{
    helpers::{NodeType, State},
    Client,
    CurrentNetwork,
    Environment,
};
use snarkos_network::{Data, Message};
use snarkvm::traits::Network;

use parking_lot::RwLock;
use pea2pea::{
    protocols::{Disconnect, Handshake, Writing},
    Connection,
    Node as Pea2PeaNode,
    Pea2Pea,
};
use rand::{thread_rng, Rng};
use std::{collections::HashMap, convert::TryInto, io, net::SocketAddr, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::*;
use tracing_subscriber::filter::LevelFilter;

/// The number of bytes indicating the length of network messages.
pub const MESSAGE_LENGTH_PREFIX_SIZE: usize = 4;

/// These 3 values are checked during the handshake.
pub const MESSAGE_VERSION: u32 = <Client<CurrentNetwork>>::MESSAGE_VERSION;
pub const MAXIMUM_FORK_DEPTH: u32 = CurrentNetwork::ALEO_MAXIMUM_FORK_DEPTH;

// Type aliases.
pub type ClientMessage = Message<CurrentNetwork, Client<CurrentNetwork>>;
pub type ClientNonce = u64;

/// The test node; it consists of a `Pea2PeaNode` that handles networking and `State`
/// that can be extended freely based on test requirements.
#[derive(Clone)]
pub struct SynthNode {
    node: Pea2PeaNode,
    pub state: ClientState,
}

/// Represents a connected snarkOS client peer.
pub struct ClientPeer {
    pub connected_addr: SocketAddr,
    pub nonce: ClientNonce,
    pub node_type: NodeType,
    pub cumulative_weight: u128,
    pub peer_version: u32,
}

/// snarkOS client state required for test purposes.
#[derive(Clone)]
pub struct ClientState {
    /// The random nonce used during the handshake.
    pub local_nonce: ClientNonce,
    /// The map of listening addresses to the corresponding peers.
    /// `Pea2Pea` includes its own internal peer handling, but snarkOS nodes
    /// must discover the listening address and unique nonce of each peer; this
    /// collection facilitates the snarkOS peering experience to align with snarkOS logic.
    pub peers: Arc<RwLock<HashMap<SocketAddr, ClientPeer>>>,
    /// A map from connected addresses to listening addresses.
    pub address_map: Arc<RwLock<HashMap<SocketAddr, SocketAddr>>>,
}

impl Default for ClientState {
    fn default() -> Self {
        Self {
            local_nonce: thread_rng().gen(),
            peers: Default::default(),
            address_map: Default::default(),
        }
    }
}

impl Pea2Pea for SynthNode {
    fn node(&self) -> &Pea2PeaNode {
        &self.node
    }
}

impl SynthNode {
    /// Creates a test node using the given `Pea2Pea` node and with the given `State`.
    pub fn new(node: Pea2PeaNode, state: ClientState) -> Self {
        Self { node, state }
    }

    /// Returns the peer's connected address when provided with the listening address.
    pub fn get_peer_connected_addr(&self, addr: SocketAddr) -> Option<SocketAddr> {
        debug_assert!(self.node().connected_addrs().contains(&addr));

        self.state.peers.read().get(&addr).map(|peer| peer.connected_addr)
    }

    /// Returns the peer's listening address when provided with the connected address.
    pub fn get_peer_listening_addr(&self, addr: SocketAddr) -> Option<SocketAddr> {
        debug_assert!(self.state.peers.read().contains_key(&addr));

        self.state.address_map.read().get(&addr).copied()
    }
}

/// Automated handshake handling for the test nodes.
#[async_trait::async_trait]
impl Handshake for SynthNode {
    async fn perform_handshake(&self, mut connection: Connection) -> io::Result<Connection> {
        let own_ip = self.node().listening_addr()?;
        let peer_addr = connection.addr;

        // An immediate duplicate connection check.
        if self.state.address_map.read().contains_key(&peer_addr) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }

        // The genesis block header is used in the handshake.
        let genesis_block_header = CurrentNetwork::genesis_block().header();

        // Send a challenge request to the peer.
        let own_request = ClientMessage::ChallengeRequest(
            MESSAGE_VERSION,
            MAXIMUM_FORK_DEPTH,
            NodeType::Client,
            State::Ready,
            own_ip.port(),
            self.state.local_nonce,
            0,
        );
        trace!(parent: self.node().span(), "sending a challenge request to {}", peer_addr);
        let mut msg = Vec::new();
        own_request.serialize_into(&mut msg).unwrap();
        let len = u32::to_le_bytes(msg.len() as u32);
        connection.writer().write_all(&len).await?;
        connection.writer().write_all(&msg).await?;

        // A buffer for reading handshake messages.
        let mut buf = [0u8; 1024];

        // Read the challenge request from the peer.
        connection.reader().read_exact(&mut buf[..MESSAGE_LENGTH_PREFIX_SIZE]).await?;
        let len = u32::from_le_bytes(buf[..MESSAGE_LENGTH_PREFIX_SIZE].try_into().unwrap()) as usize;
        connection.reader().read_exact(&mut buf[..len]).await?;
        let peer_request = ClientMessage::deserialize(&mut io::Cursor::new(&buf[..len]));

        // Register peer's nonce.
        let (peer_listening_addr, peer_nonce, peer_node_type, cumulative_weight, peer_version) = if let Ok(Message::ChallengeRequest(
            peer_version,
            _peer_fork_depth,
            peer_node_type,
            _peer_status,
            peer_listening_port,
            peer_nonce,
            cumulative_weight,
        )) = peer_request
        {
            // Don't reject peers due to the client version in order to keep track of non-compliant peers.

            let peer_listening_addr = SocketAddr::from((peer_addr.ip(), peer_listening_port));

            if self.state.peers.read().contains_key(&peer_listening_addr) {
                return Err(io::ErrorKind::AlreadyExists.into());
            }

            trace!(parent: self.node().span(), "received a challenge request from {}", peer_addr);

            (peer_listening_addr, peer_nonce, peer_node_type, cumulative_weight, peer_version)
        } else if let Ok(Message::Disconnect(reason)) = peer_request {
            warn!(parent: self.node().span(), "{} disconnected: {:?}", peer_addr, reason);
            return Err(io::ErrorKind::NotConnected.into());
        } else {
            error!(parent: self.node().span(), "invalid challenge request from {}", peer_addr);
            return Err(io::ErrorKind::InvalidData.into());
        };

        // Respond with own challenge request.
        let own_response = ClientMessage::ChallengeResponse(Data::Object(genesis_block_header.clone()));
        trace!(parent: self.node().span(), "sending a challenge response to {}", peer_addr);
        let mut msg = Vec::new();
        own_response.serialize_into(&mut msg).unwrap();
        let len = u32::to_le_bytes(msg.len() as u32);
        connection.writer().write_all(&len).await?;
        connection.writer().write_all(&msg).await?;

        // Wait for the challenge response to come in.
        connection.reader().read_exact(&mut buf[..MESSAGE_LENGTH_PREFIX_SIZE]).await?;
        let len = u32::from_le_bytes(buf[..MESSAGE_LENGTH_PREFIX_SIZE].try_into().unwrap()) as usize;
        connection.reader().read_exact(&mut buf[..len]).await?;
        let peer_response = ClientMessage::deserialize(&mut io::Cursor::new(&buf[..len]));

        if let Ok(Message::ChallengeResponse(block_header)) = peer_response {
            let block_header = block_header.deserialize().await.unwrap();

            trace!(parent: self.node().span(), "received a challenge response from {}", peer_addr);
            if &block_header == genesis_block_header {
                let mut locked_peers = self.state.peers.write();
                let mut locked_addr_map = self.state.address_map.write();

                if locked_addr_map.contains_key(&peer_addr) || locked_peers.contains_key(&peer_listening_addr) {
                    return Err(io::ErrorKind::AlreadyExists.into());
                }

                locked_addr_map.insert(peer_addr, peer_listening_addr);

                // Register the newly connected snarkOS peer.
                locked_peers.insert(peer_listening_addr, ClientPeer {
                    connected_addr: peer_addr,
                    nonce: peer_nonce,
                    node_type: peer_node_type,
                    cumulative_weight,
                    peer_version,
                });

                drop(locked_addr_map);
                drop(locked_peers);

                debug!(parent: self.node().span(), "connected to {} (listening addr: {})", peer_addr, peer_listening_addr);

                Ok(connection)
            } else {
                error!(parent: self.node().span(), "invalid challenge response from {}", peer_addr);
                Err(io::ErrorKind::InvalidData.into())
            }
        } else if let Ok(Message::Disconnect(reason)) = peer_response {
            warn!(parent: self.node().span(), "{} disconnected: {:?}", peer_addr, reason);
            return Err(io::ErrorKind::NotConnected.into());
        } else {
            error!(parent: self.node().span(), "invalid challenge response from {}", peer_addr);
            Err(io::ErrorKind::InvalidData.into())
        }
    }
}

/// Outbound message processing logic for the test nodes.
impl Writing for SynthNode {
    type Message = ClientMessage;

    fn write_message<W: io::Write>(&self, _target: SocketAddr, payload: &Self::Message, writer: &mut W) -> io::Result<()> {
        let mut msg = Vec::new();
        payload.serialize_into(&mut msg).unwrap();
        let len = u32::to_le_bytes(msg.len() as u32);

        writer.write_all(&len)?;
        writer.write_all(&msg)
    }
}

/// Disconnect logic for the test nodes.
#[async_trait::async_trait]
impl Disconnect for SynthNode {
    async fn handle_disconnect(&self, disconnecting_addr: SocketAddr) {
        debug_assert_eq!(self.state.address_map.read().len(), self.state.peers.read().len());

        if let Some(listening_addr) = self.state.address_map.write().remove(&disconnecting_addr) {
            self.state.peers.write().remove(&listening_addr);
        }
    }
}

/// Enables tracing for all synth node instances (usually scoped by test).
pub fn enable_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};

    let env_filter = match EnvFilter::try_from_default_env() {
        Ok(filter) => filter
            .add_directive("mio=off".parse().unwrap())
            .add_directive("pea2pea::protocols::handshake=off".parse().unwrap()),
        _ => EnvFilter::default()
            .add_directive(LevelFilter::INFO.into())
            .add_directive("mio=off".parse().unwrap())
            .add_directive("pea2pea::protocols::handshake=off".parse().unwrap()),
    };

    fmt().with_test_writer().with_env_filter(env_filter).init();
}
