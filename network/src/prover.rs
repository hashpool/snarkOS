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

use crate::{Data, LedgerReader, LedgerRequest, LedgerRouter, Message, PeersRequest, PeersRouter};
use snarkos_environment::{
    helpers::{NodeType, State},
    Data, Environment, LedgerReader, LedgerRouter, Message, PeersRequest, PeersRouter,
};
use snarkos_storage::{storage::Storage, ProverState};
use snarkvm::dpc::{posw::PoSWProof, prelude::*};

use anyhow::{anyhow, Result};
use rand::thread_rng;
use rayon::{ThreadPool, ThreadPoolBuilder};
use std::{
    net::SocketAddr,
    path::Path,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot, RwLock},
    task,
};

/// Shorthand for the parent half of the `Prover` message channel.
pub type ProverRouter<N> = mpsc::Sender<ProverRequest<N>>;
#[allow(unused)]
/// Shorthand for the child half of the `Prover` message channel.
type ProverHandler<N> = mpsc::Receiver<ProverRequest<N>>;

///
/// An enum of requests that the `Prover` struct processes.
///
#[derive(Debug)]
pub enum ProverRequest<N: Network> {
    /// PoolRequest := (peer_ip, share_difficulty, block_template)
    PoolRequest(SocketAddr, u64, BlockTemplate<N>),
    /// MemoryPoolClear := (block)
    MemoryPoolClear(Option<Block<N>>),
    /// UnconfirmedTransaction := (peer_ip, transaction)
    UnconfirmedTransaction(SocketAddr, Transaction<N>),
    OperatorConnected(SocketAddr),
}

///
/// A prover for a specific network on the node server.
///
#[derive(Debug)]
pub struct Prover<N: Network, E: Environment> {
    /// The state storage of the prover.
    state: Arc<ProverState<N>>,
    /// The Aleo address of the prover.
    address: Option<Address<N>>,
    /// The IP address of the connected pool.
    pool: Option<SocketAddr>,
    /// The thread pool for the prover.
    thread_pool: Arc<ThreadPool>,
    /// The prover router of the node.
    prover_router: ProverRouter<N>,
    /// The pool of unconfirmed transactions.
    memory_pool: Arc<RwLock<MemoryPool<N>>>,
    /// The peers router of the node.
    peers_router: PeersRouter<N, E>,
    /// The ledger state of the node.
    ledger_reader: LedgerReader<N>,
    /// The ledger router of the node.
    _ledger_router: LedgerRouter<N>,
    current_block: Arc<RwLock<u32>>,
}

impl<N: Network, E: Environment> Prover<N, E> {
    /// Initializes a new instance of the prover.
    pub async fn open<S: Storage, P: AsRef<Path> + Copy>(
        path: P,
        address: Option<Address<N>>,
        _local_ip: SocketAddr,
        pool_ip: Option<SocketAddr>,
        peers_router: PeersRouter<N, E>,
        ledger_reader: LedgerReader<N>,
        ledger_router: LedgerRouter<N>,
    ) -> Result<Arc<Self>> {
        // Initialize an mpsc channel for sending requests to the `Prover` struct.
        let (prover_router, mut prover_handler) = mpsc::channel(1024);
        // Initialize the prover thread pool.
        let thread_pool = ThreadPoolBuilder::new()
            .stack_size(8 * 1024 * 1024)
            .num_threads(num_cpus::get())
            .build()?;

        // Initialize the prover.
        let prover = Arc::new(Self {
            state: Arc::new(ProverState::open::<S, P>(path, false)?),
            address,
            pool: pool_ip,
            thread_pool: Arc::new(thread_pool),
            prover_router,
            memory_pool: Arc::new(RwLock::new(MemoryPool::new())),
            peers_router,
            ledger_reader,
            _ledger_router: ledger_router,
            current_block: Arc::new(RwLock::new(0)),
        });

        // Initialize the handler for the prover.
        {
            let prover = prover.clone();
            let (router, handler) = oneshot::channel();
            E::resources().register_task(
                None, // No need to provide an id, as the task will run indefinitely.
                task::spawn(async move {
                    // Notify the outer function that the task is ready.
                    let _ = router.send(());
                    // Asynchronously wait for a prover request.
                    while let Some(request) = prover_handler.recv().await {
                        // Update the state of the prover.
                        prover.update(request).await;
                    }
                }),
            );

            // Wait until the prover handler is ready.
            let _ = handler.await;
        }

        // terminator init
        task::spawn(async move {
            let mut counter = false;
            loop {
                if E::prover_terminator().load(Ordering::SeqCst) {
                    if counter {
                        E::prover_terminator().store(false, Ordering::SeqCst);
                        counter = false;
                    } else {
                        counter = true;
                    }
                } else {
                    counter = false;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        Ok(prover)
    }

    /// Returns an instance of the prover router.
    pub fn router(&self) -> ProverRouter<N> {
        self.prover_router.clone()
    }

    /// Returns an instance of the memory pool.
    pub fn memory_pool(&self) -> Arc<RwLock<MemoryPool<N>>> {
        self.memory_pool.clone()
    }

    /// Returns all coinbase records in storage.
    pub fn to_coinbase_records(&self) -> Vec<(u32, Record<N>)> {
        self.state.to_coinbase_records()
    }

    ///
    /// Performs the given `request` to the prover.
    /// All requests must go through this `update`, so that a unified view is preserved.
    ///
    pub(super) async fn update(&self, request: ProverRequest<N>) {
        match request {
            ProverRequest::PoolRequest(operator_ip, share_difficulty, block_template) => {
                // Process the pool request message.
                self.process_pool_request(operator_ip, share_difficulty, block_template).await;
            }
            ProverRequest::MemoryPoolClear(block) => match block {
                Some(block) => self.memory_pool.write().await.remove_transactions(block.transactions()),
                None => *self.memory_pool.write().await = MemoryPool::new(),
            },
            ProverRequest::UnconfirmedTransaction(peer_ip, transaction) => {
                // Ensure the node is not peering.
                if !E::status().is_peering() {
                    // Process the unconfirmed transaction.
                    self.add_unconfirmed_transaction(peer_ip, transaction).await
                }
            }
            ProverRequest::OperatorConnected(peer_ip) => {
                if let Some(pool_ip) = self.pool {
                    if pool_ip == peer_ip {
                        self.send_pool_register().await;
                    }
                }
            }
        }
    }

    ///
    /// Sends a `PoolRegister` message to the pool IP address.
    ///
    async fn send_pool_register(&self) {
        if E::NODE_TYPE == NodeType::Prover {
            if let Some(recipient) = self.address {
                if let Some(pool_ip) = self.pool {
                    // Proceed to register the prover to receive a block template.
                    let request = PeersRequest::MessageSend(pool_ip, Message::PoolRegister(recipient));
                    if let Err(error) = self.peers_router.send(request).await {
                        warn!("[PoolRegister] {}", error);
                    }
                } else {
                    error!("Missing pool IP address. Please specify a pool IP address in order to run the prover");
                }
            } else {
                error!("Missing prover address. Please specify an Aleo address in order to prove");
            }
        }
    }

    ///
    /// Processes a `PoolRequest` message from a pool operator.
    ///
    async fn process_pool_request(&self, operator_ip: SocketAddr, share_difficulty: u64, block_template: BlockTemplate<N>) {
        if E::NODE_TYPE == NodeType::Prover {
            if let Some(recipient) = self.address {
                if let Some(pool_ip) = self.pool {
                    // Refuse work from any pool other than the registered one.
                    if pool_ip == operator_ip {
                        let thread_pool = self.thread_pool.clone();
                        let peers_router = self.peers_router.clone();
                        let block_height = block_template.block_height();
                        let current_block = self.current_block.clone();
                        *(current_block.write().await) = block_height;
                        task::spawn(async move {
                            info!("[PoolRequest] Received a block template {} from the pool operator", block_height);
                            E::prover_terminator().store(true, Ordering::SeqCst);
                            while E::prover_terminator().load(Ordering::SeqCst) {
                                // Wait until the prover terminator is set to false.
                                tokio::time::sleep(Duration::from_millis(50)).await;
                            }
                            trace!("[PoolRequest] Starting to process the block template for block {}", block_height);

                            // Set the status to `Mining`.
                            E::status().update(State::Mining);

                            while !E::prover_terminator().load(Ordering::SeqCst) {
                                let block_template = block_template.clone();
                                let block_height = block_template.block_height();
                                let thread_pool = thread_pool.clone();
                                if block_height != *(current_block.try_read().unwrap()) {
                                    info!(
                                        "Terminating stale work: current {} latest {}",
                                        block_height,
                                        *(current_block.try_read().unwrap())
                                    );
                                    break;
                                }

                                let result = task::spawn_blocking(move || {
                                    thread_pool.install(move || {
                                        loop {
                                            let block_header = BlockHeader::mine_once_unchecked(
                                                &block_template,
                                                E::prover_terminator(),
                                                &mut thread_rng(),
                                            )?;

                                            // Ensure the share difficulty target is met.
                                            if N::posw().verify(
                                                block_header.height(),
                                                share_difficulty,
                                                &[*block_header.to_header_root().unwrap(), *block_header.nonce()],
                                                block_header.proof(),
                                            ) {
                                                return Ok::<(N::PoSWNonce, PoSWProof<N>, u64), anyhow::Error>((
                                                    block_header.nonce(),
                                                    block_header.proof().clone(),
                                                    block_header.proof().to_proof_difficulty()?,
                                                ));
                                            }
                                        }
                                    })
                                })
                                .await;

                                match result {
                                    Ok(Ok((nonce, proof, proof_difficulty))) => {
                                        info!(
                                            "Prover successfully mined a share for unconfirmed block {} with proof difficulty of {}",
                                            block_height, proof_difficulty
                                        );

                                        // Send a `PoolResponse` to the operator.
                                        let message = Message::PoolResponse(recipient, nonce, Data::Object(proof));
                                        if let Err(error) = peers_router.send(PeersRequest::MessageSend(operator_ip, message)).await {
                                            warn!("[PoolResponse] {}", error);
                                        }
                                    }
                                    Ok(Err(error)) => trace!("{}", error),
                                    Err(error) => trace!("{}", anyhow!("Failed to mine the next block {}", error)),
                                }
                            }

                            E::status().update(State::Ready);
                            E::prover_terminator().store(false, Ordering::SeqCst);
                        });
                    }
                } else {
                    error!("Missing pool IP address. Please specify a pool IP address in order to run the prover");
                }
            } else {
                error!("Missing prover address. Please specify an Aleo address in order to prove");
            }
        }
    }

    ///
    /// Adds the given unconfirmed transaction to the memory pool.
    ///
    async fn add_unconfirmed_transaction(&self, peer_ip: SocketAddr, transaction: Transaction<N>) {
        // Process the unconfirmed transaction.
        trace!("Received unconfirmed transaction {} from {}", transaction.transaction_id(), peer_ip);
        // Ensure the unconfirmed transaction is new.
        if let Ok(false) = self.ledger_reader.contains_transaction(&transaction.transaction_id()) {
            debug!("Adding unconfirmed transaction {} to memory pool", transaction.transaction_id());
            // Attempt to add the unconfirmed transaction to the memory pool.
            match self.memory_pool.write().await.add_transaction(&transaction) {
                Ok(()) => {
                    // Upon success, propagate the unconfirmed transaction to the connected peers.
                    let request = PeersRequest::MessagePropagate(peer_ip, Message::UnconfirmedTransaction(Data::Object(transaction)));
                    if let Err(error) = self.peers_router.send(request).await {
                        warn!("[UnconfirmedTransaction] {}", error);
                    }
                }
                Err(error) => error!("{}", error),
            }
        }
    }
}
