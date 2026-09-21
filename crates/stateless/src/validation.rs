use crate::{
    ExecutionWitness,
    recover_block::{UncompressedPublicKey, recover_block_with_public_keys},
    witness_db::WitnessDatabase,
};
use alloc::{
    collections::BTreeMap,
    fmt::Debug,
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use alloy_consensus::{
    Block as GenericBlock, BlockHeader, Header, TxReceipt,
    proofs::{calculate_receipt_root, calculate_transaction_root},
};
use alloy_eips::eip7685::EMPTY_REQUESTS_HASH;
use alloy_eips::eip7928::{
    BlockAccessList, ITEM_COST, compute_block_access_list_hash, total_bal_items,
};
use alloy_primitives::{B256, keccak256};
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_consensus::ConsensusError;
use reth_consensus::{Consensus, HeaderValidator};
use reth_ethereum_consensus::{EthBeaconConsensus, validate_block_post_execution};
use reth_ethereum_primitives::{Block, EthPrimitives, EthereumReceipt};
use reth_evm::{
    ConfigureEvm, Evm,
    block::BlockExecutor,
    execute::{BlockExecutionOutput, Executor},
};
use reth_primitives_traits::{
    NodePrimitives, RecoveredBlock, SealedHeader, SignedTransaction, logs_bloom,
};
use reth_trie_common::{HashedPostState, KeccakKeyHasher};
use revm::database::{BundleState, State, states::bundle_state::BundleRetention};
use tries::{StatelessTrie, StatelessTrieError, default::StatelessSparseTrie};

/// BLOCKHASH ancestor lookup window limit per EVM (number of most recent blocks accessible).
const BLOCKHASH_ANCESTOR_LIMIT: usize = 256;

/// Errors that can occur during stateless validation.
#[derive(Debug, thiserror::Error)]
pub enum StatelessValidationError {
    /// Error when the number of ancestor headers exceeds the limit.
    #[error("ancestor header count ({count}) exceeds limit ({limit})")]
    AncestorHeaderLimitExceeded {
        /// The number of headers provided.
        count: usize,
        /// The limit.
        limit: usize,
    },

    /// Error when an ancestor header hash does not match its child's parent hash.
    #[error(
        "invalid ancestor chain: child block {child_number} expects parent hash {expected_parent_hash}, but ancestor block {parent_number} has hash {actual_parent_hash}"
    )]
    InvalidAncestorParentHash {
        /// The child block number whose parent hash was checked.
        child_number: u64,
        /// The ancestor block number provided as the parent.
        parent_number: u64,
        /// The parent hash committed to by the child header.
        expected_parent_hash: B256,
        /// The hash of the provided ancestor header.
        actual_parent_hash: B256,
    },

    /// Error when ancestor header numbers are not contiguous.
    #[error(
        "invalid ancestor chain: ancestor block {parent_number} is not the parent of child block {child_number}; expected parent block {expected_parent_number}"
    )]
    InvalidAncestorNumber {
        /// The child block number whose parent number was checked.
        child_number: u64,
        /// The expected parent block number.
        expected_parent_number: u64,
        /// The ancestor block number provided as the parent.
        parent_number: u64,
    },

    /// Error when revealing the witness data failed.
    #[error("failed to reveal witness data for pre-state root {pre_state_root}")]
    WitnessRevealFailed {
        /// The pre-state root used for verification.
        pre_state_root: B256,
    },

    /// Error during stateless block execution.
    #[error("stateless block execution failed: {0}")]
    StatelessExecutionFailed(String),

    /// Error during consensus validation of the block.
    #[error("consensus validation failed: {0}")]
    ConsensusValidationFailed(#[from] ConsensusError),

    /// Error when the block access list exceeds the per-block item gas limit (EIP-7928).
    #[error("block access list exceeds gas limit, {items} items exceeds limit of {limit}")]
    BlockAccessListGasLimitExceeded {
        /// The number of block access list items produced during execution.
        items: u64,
        /// The maximum number of items allowed, the block gas limit divided by the per item cost.
        limit: u64,
    },

    /// A last-transaction checkpoint matches the block root only if post-execution changes touch no state.
    #[error("post-execution changes are not state-neutral: checkpoint {checkpoint}, block {block}")]
    PostExecutionChangesNotStateNeutral {
        /// Root at the last transaction, before post-execution changes.
        checkpoint: B256,
        /// The block's validated post-state root.
        block: B256,
    },

    /// A block carries a field a candidate cannot reproduce from a prefix.
    #[error("candidate block cannot reproduce {0} from a transaction prefix")]
    CandidateBlockUnsupportedField(&'static str),

    /// Error during stateless state root calculation.
    #[error("stateless state root calculation failed")]
    StatelessStateRootCalculationFailed,

    /// Error calculating the pre-state root from the witness data.
    #[error("stateless pre-state root calculation failed")]
    StatelessPreStateRootCalculationFailed,

    /// Error when required ancestor headers are missing (e.g., parent header for pre-state root).
    #[error("missing required ancestor headers")]
    MissingAncestorHeader,

    /// Error when deserializing ancestor headers
    #[error("could not deserialize ancestor headers")]
    HeaderDeserializationFailed,

    /// Error when the computed state root does not match the one in the block header.
    #[error("mismatched post-state root: {got}\n {expected}")]
    PostStateRootMismatch {
        /// The computed post-state root
        got: B256,
        /// The expected post-state root; in the block header
        expected: B256,
    },

    /// Error when the computed pre-state root does not match the expected one.
    #[error("mismatched pre-state root: {got} \n {expected}")]
    PreStateRootMismatch {
        /// The computed pre-state root
        got: B256,
        /// The expected pre-state root from the previous block
        expected: B256,
    },

    /// Error during signer recovery.
    #[error("signer recovery failed")]
    SignerRecovery,

    /// Error when requested transaction checkpoints are not strictly ordered.
    #[error(
        "transaction checkpoint indices must be strictly increasing, got {previous} before {current}"
    )]
    UnorderedTransactionCheckpoints {
        /// The preceding requested transaction index.
        previous: usize,
        /// The next requested transaction index.
        current: usize,
    },

    /// Error when a requested checkpoint is outside the block's transactions.
    #[error(
        "transaction checkpoint index {index} is outside a block with {transactions} transactions"
    )]
    TransactionCheckpointOutOfBounds {
        /// The requested transaction index.
        index: usize,
        /// The number of transactions in the block.
        transactions: usize,
    },

    /// Error when signature has non-normalized s value in homestead block.
    #[error("signature s value not normalized for homestead block")]
    HomesteadSignatureNotNormalized,

    /// Custom error.
    #[error("{0}")]
    Custom(&'static str),
}

impl From<StatelessTrieError> for StatelessValidationError {
    fn from(err: StatelessTrieError) -> Self {
        match err {
            StatelessTrieError::WitnessRevealFailed { pre_state_root } => {
                Self::WitnessRevealFailed { pre_state_root }
            }
            StatelessTrieError::StatelessStateRootCalculationFailed => {
                Self::StatelessStateRootCalculationFailed
            }
            StatelessTrieError::StatelessPreStateRootCalculationFailed => {
                Self::StatelessPreStateRootCalculationFailed
            }
            StatelessTrieError::PreStateRootMismatch { got, expected } => {
                Self::PreStateRootMismatch { got, expected }
            }
        }
    }
}

/// Output of successful stateless block validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatelessValidationOutput<R = EthereumReceipt> {
    /// Hash of the validated block.
    pub block_hash: B256,
    /// State root from which the validated block was executed.
    pub pre_state_root: B256,
    /// State root recomputed after executing and finalizing the validated block.
    pub post_state_root: B256,
    /// Execution output produced while validating the block.
    pub execution_output: BlockExecutionOutput<R>,
    /// Block access list produced during execution, if available.
    pub block_access_list: Option<BlockAccessList>,
}

/// Selected transaction state checkpoints from one validated block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockStateCheckpoints {
    /// Requested cumulative transaction checkpoints, in transaction order.
    pub transaction_state_checkpoints: Vec<TransactionStateCheckpoint>,
}

/// A cumulative state root immediately after one transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionStateCheckpoint {
    /// Zero-based position of the transaction in the block.
    pub transaction_index: usize,
    /// State root after this transaction and before post-execution changes.
    pub state_root: B256,
    /// Hash of the candidate block for this prefix — what to hold if settlement stops here.
    pub block_hash: B256,
}

/// Successful stateless validation with opt-in execution checkpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatelessValidationWithStateCheckpointsOutput<R = EthereumReceipt> {
    /// The ordinary block validation output.
    pub validation: StatelessValidationOutput<R>,
    /// State roots derived at the block's execution boundaries.
    pub checkpoints: BlockStateCheckpoints,
}

/// Performs stateless validation of a block using the provided witness data.
pub fn stateless_validation<ChainSpec, E>(
    current_block: Block,
    public_keys: Vec<UncompressedPublicKey>,
    witness: ExecutionWitness,
    chain_spec: Arc<ChainSpec>,
    evm_config: E,
) -> Result<StatelessValidationOutput, StatelessValidationError>
where
    ChainSpec: Send + Sync + EthChainSpec<Header = Header> + EthereumHardforks + Debug,
    E: ConfigureEvm<Primitives = EthPrimitives> + Clone + 'static,
{
    stateless_validation_with_trie::<StatelessSparseTrie, ChainSpec, E>(
        current_block,
        public_keys,
        witness,
        chain_spec,
        evm_config,
    )
}

/// Performs stateless validation of a block using a custom `StatelessTrie` implementation.
pub fn stateless_validation_with_trie<T, ChainSpec, E>(
    current_block: Block,
    public_keys: Vec<UncompressedPublicKey>,
    witness: ExecutionWitness,
    chain_spec: Arc<ChainSpec>,
    evm_config: E,
) -> Result<StatelessValidationOutput, StatelessValidationError>
where
    T: StatelessTrie,
    ChainSpec: Send + Sync + EthChainSpec<Header = Header> + EthereumHardforks + Debug,
    E: ConfigureEvm<Primitives = EthPrimitives> + Clone + 'static,
{
    let recovered_block = recover_block_with_public_keys(current_block, public_keys, &*chain_spec)?;

    stateless_validation_recovered_with_trie::<T, ChainSpec, E, EthPrimitives>(
        recovered_block,
        witness,
        chain_spec,
        evm_config,
    )
}

/// Performs stateless validation of an already-recovered block.
///
/// Uses the caller's transaction and receipt types so native rollup transactions
/// retain their execution rules and receipt encoding during witness replay.
/// Callers must authenticate the recovered senders; Ethereum header, body, and
/// post-execution commitment checks still apply.
pub fn stateless_validation_recovered<ChainSpec, E, N>(
    recovered_block: RecoveredBlock<GenericBlock<<N as NodePrimitives>::SignedTx>>,
    witness: ExecutionWitness,
    chain_spec: Arc<ChainSpec>,
    evm_config: E,
) -> Result<StatelessValidationOutput<N::Receipt>, StatelessValidationError>
where
    ChainSpec: Send + Sync + EthChainSpec<Header = Header> + EthereumHardforks + Debug,
    N: NodePrimitives<BlockHeader = Header, Block = GenericBlock<<N as NodePrimitives>::SignedTx>>,
    E: ConfigureEvm<Primitives = N> + Clone + 'static,
{
    stateless_validation_recovered_with_trie::<StatelessSparseTrie, ChainSpec, E, N>(
        recovered_block,
        witness,
        chain_spec,
        evm_config,
    )
}

/// Performs stateless validation and derives selected transaction state roots.
///
/// `transaction_indices` must be strictly increasing and within the block. This
/// API reconstructs a fresh stateless trie for every requested checkpoint, so
/// callers should request only boundaries they actually need. Transaction roots
/// are taken before post-execution block changes, so the last transaction root
/// is not required to equal the block's final root.
pub fn stateless_validation_recovered_with_state_checkpoints<ChainSpec, E, N>(
    recovered_block: RecoveredBlock<GenericBlock<<N as NodePrimitives>::SignedTx>>,
    witness: ExecutionWitness,
    chain_spec: Arc<ChainSpec>,
    evm_config: E,
    transaction_indices: &[usize],
) -> Result<StatelessValidationWithStateCheckpointsOutput<N::Receipt>, StatelessValidationError>
where
    ChainSpec: Send + Sync + EthChainSpec<Header = Header> + EthereumHardforks + Debug,
    N: NodePrimitives<BlockHeader = Header, Block = GenericBlock<<N as NodePrimitives>::SignedTx>>,
    E: ConfigureEvm<Primitives = N> + Clone + 'static,
{
    stateless_validation_recovered_with_trie_and_state_checkpoints::<
        StatelessSparseTrie,
        ChainSpec,
        E,
        N,
    >(recovered_block, witness, chain_spec, evm_config, transaction_indices)
}

/// Performs stateless validation with selected checkpoints using a custom trie.
pub fn stateless_validation_recovered_with_trie_and_state_checkpoints<T, ChainSpec, E, N>(
    current_block: RecoveredBlock<GenericBlock<<N as NodePrimitives>::SignedTx>>,
    witness: ExecutionWitness,
    chain_spec: Arc<ChainSpec>,
    evm_config: E,
    transaction_indices: &[usize],
) -> Result<StatelessValidationWithStateCheckpointsOutput<N::Receipt>, StatelessValidationError>
where
    T: StatelessTrie,
    ChainSpec: Send + Sync + EthChainSpec<Header = Header> + EthereumHardforks + Debug,
    N: NodePrimitives<BlockHeader = Header, Block = GenericBlock<<N as NodePrimitives>::SignedTx>>,
    E: ConfigureEvm<Primitives = N> + Clone + 'static,
{
    validate_transaction_indices(transaction_indices, current_block.body().transactions.len())?;
    let (ancestor_hashes, parent_state_root) =
        validate_block_inputs(&current_block, &witness, Arc::clone(&chain_spec))?;
    let witness_template = witness.clone();
    let (trie, bytecode) = T::new(witness, parent_state_root)?;
    let db = WitnessDatabase::new(&trie, bytecode, ancestor_hashes);
    let has_bal = current_block.sealed_header().block_access_list_hash().is_some();
    let mut state = State::builder()
        .with_database(db)
        .with_bundle_update()
        .with_bal_builder_if(has_bal)
        .build();

    let (transaction_state_checkpoints, result) = {
        let mut executor =
            evm_config.executor_for_block(&mut state, current_block.sealed_block()).map_err(
                |error| StatelessValidationError::StatelessExecutionFailed(format!("{error:?}")),
            )?;
        executor.apply_pre_execution_changes().map_err(|error| {
            StatelessValidationError::StatelessExecutionFailed(error.to_string())
        })?;
        if has_bal {
            executor.evm_mut().db_mut().bump_bal_index();
        }

        let mut checkpoints = Vec::with_capacity(transaction_indices.len());
        for (transaction_index, transaction) in current_block.transactions_recovered().enumerate() {
            executor.execute_transaction(transaction).map_err(|error| {
                StatelessValidationError::StatelessExecutionFailed(error.to_string())
            })?;
            if has_bal {
                executor.evm_mut().db_mut().bump_bal_index();
            }
            if transaction_indices.get(checkpoints.len()) == Some(&transaction_index) {
                let state_root = checkpoint_state_root::<T, _>(
                    &witness_template,
                    parent_state_root,
                    executor.evm().db(),
                )?;
                let block_hash = candidate_block_hash::<N>(
                    current_block.sealed_header(),
                    &current_block.body().transactions[..=transaction_index],
                    &executor.receipts()[..=transaction_index],
                    state_root,
                )?;
                checkpoints.push(TransactionStateCheckpoint {
                    transaction_index,
                    state_root,
                    block_hash,
                });
            }
        }
        let result = executor.apply_post_execution_changes().map_err(|error| {
            StatelessValidationError::StatelessExecutionFailed(error.to_string())
        })?;
        (checkpoints, result)
    };

    state.merge_transitions(BundleRetention::Reverts);
    let block_access_list = state.take_built_alloy_bal();
    let output_state = state.take_bundle();
    drop(state);
    let output = BlockExecutionOutput { state: output_state, result };
    let validation = validate_execution_output::<T, ChainSpec, N>(
        &current_block,
        parent_state_root,
        &chain_spec,
        trie,
        output,
        block_access_list,
    )?;

    // Same boundary before vs after post-execution changes; candidates rely on equality.
    if let Some(last) = transaction_state_checkpoints.last()
        && last.transaction_index + 1 == current_block.body().transactions.len()
    {
        let block_root = current_block.sealed_header().state_root();
        if last.state_root != block_root {
            return Err(StatelessValidationError::PostExecutionChangesNotStateNeutral {
                checkpoint: last.state_root,
                block: block_root,
            });
        }
    }

    Ok(StatelessValidationWithStateCheckpointsOutput {
        validation,
        checkpoints: BlockStateCheckpoints { transaction_state_checkpoints },
    })
}

/// Performs stateless validation of an already-recovered block using a custom `StatelessTrie` implementation.
pub fn stateless_validation_recovered_with_trie<T, ChainSpec, E, N>(
    current_block: RecoveredBlock<GenericBlock<<N as NodePrimitives>::SignedTx>>,
    witness: ExecutionWitness,
    chain_spec: Arc<ChainSpec>,
    evm_config: E,
) -> Result<StatelessValidationOutput<N::Receipt>, StatelessValidationError>
where
    T: StatelessTrie,
    ChainSpec: Send + Sync + EthChainSpec<Header = Header> + EthereumHardforks + Debug,
    N: NodePrimitives<BlockHeader = Header, Block = GenericBlock<<N as NodePrimitives>::SignedTx>>,
    E: ConfigureEvm<Primitives = N> + Clone + 'static,
{
    let (ancestor_hashes, parent_state_root) =
        validate_block_inputs(&current_block, &witness, Arc::clone(&chain_spec))?;
    let (trie, bytecode) = T::new(witness, parent_state_root)?;

    let db = WitnessDatabase::new(&trie, bytecode, ancestor_hashes);

    let mut executor = evm_config.executor(db);
    let result = executor
        .execute_one(&current_block)
        .map_err(|e| StatelessValidationError::StatelessExecutionFailed(e.to_string()))?;

    let block_access_list = executor.take_bal();

    let mut state = executor.into_state();
    let output = BlockExecutionOutput { state: state.take_bundle(), result };
    drop(state);

    validate_execution_output::<T, ChainSpec, N>(
        &current_block,
        parent_state_root,
        &chain_spec,
        trie,
        output,
        block_access_list,
    )
}

fn validate_block_inputs<ChainSpec, Tx: SignedTransaction>(
    current_block: &RecoveredBlock<GenericBlock<Tx>>,
    witness: &ExecutionWitness,
    chain_spec: Arc<ChainSpec>,
) -> Result<(BTreeMap<u64, B256>, B256), StatelessValidationError>
where
    ChainSpec: Send + Sync + EthChainSpec<Header = Header> + EthereumHardforks + Debug,
{
    let count = witness.headers.len();
    if count > BLOCKHASH_ANCESTOR_LIMIT {
        return Err(StatelessValidationError::AncestorHeaderLimitExceeded {
            count,
            limit: BLOCKHASH_ANCESTOR_LIMIT,
        });
    }

    let ancestor_headers: Vec<_> = witness
        .headers
        .iter()
        .map(|bytes| {
            let hash = keccak256(bytes);
            alloy_rlp::decode_exact::<Header>(bytes)
                .map(|header| SealedHeader::new(header, hash))
                .map_err(|_| StatelessValidationError::HeaderDeserializationFailed)
        })
        .collect::<Result<_, _>>()?;
    let ancestor_hashes = compute_ancestor_hashes(current_block, &ancestor_headers)?;
    let parent = ancestor_headers.last().ok_or(StatelessValidationError::MissingAncestorHeader)?;
    validate_block_consensus(chain_spec, current_block, parent)?;
    Ok((ancestor_hashes, parent.state_root))
}

/// Validate the sparse checkpoint selection before any witness work begins.
fn validate_transaction_indices(
    transaction_indices: &[usize],
    transactions: usize,
) -> Result<(), StatelessValidationError> {
    if let Some(indices) = transaction_indices.windows(2).find(|indices| indices[0] >= indices[1]) {
        return Err(StatelessValidationError::UnorderedTransactionCheckpoints {
            previous: indices[0],
            current: indices[1],
        });
    }
    if let Some(&index) = transaction_indices.last().filter(|&&index| index >= transactions) {
        return Err(StatelessValidationError::TransactionCheckpointOutOfBounds {
            index,
            transactions,
        });
    }
    Ok(())
}

/// Seal the candidate block for this prefix, field by field — never by updating
/// a clone, so a new `Header` field fails the build instead of being inherited.
///
/// Public so every backend that replays a window seals candidates identically.
pub fn candidate_block_hash<N>(
    settling: &SealedHeader,
    transactions: &[N::SignedTx],
    receipts: &[N::Receipt],
    state_root: B256,
) -> Result<B256, StatelessValidationError>
where
    N: NodePrimitives,
{
    // Neither is reproducible from a prefix, so refuse rather than inherit.
    if settling.block_access_list_hash().is_some() {
        return Err(StatelessValidationError::CandidateBlockUnsupportedField("block access list"));
    }
    if settling.requests_hash().is_some_and(|hash| hash != EMPTY_REQUESTS_HASH) {
        return Err(StatelessValidationError::CandidateBlockUnsupportedField("execution requests"));
    }
    // No blob transactions on an EEZ L2, so no prefix apportioning to get right.
    if settling.blob_gas_used().is_some_and(|used| used != 0) {
        return Err(StatelessValidationError::CandidateBlockUnsupportedField("blob transactions"));
    }

    let header = Header {
        // Prefix-varying.
        state_root,
        transactions_root: calculate_transaction_root(transactions),
        receipts_root: calculate_receipt_root(
            &receipts.iter().map(TxReceipt::with_bloom_ref).collect::<Vec<_>>(),
        ),
        logs_bloom: logs_bloom(receipts.iter().flat_map(TxReceipt::logs)),
        gas_used: receipts.last().map(TxReceipt::cumulative_gas_used).unwrap_or_default(),
        // Zero for every prefix: a non-zero value was refused above.
        blob_gas_used: settling.blob_gas_used(),
        // Fixed by parent + payload attributes, so shared with the settling block.
        parent_hash: settling.parent_hash(),
        ommers_hash: settling.ommers_hash(),
        beneficiary: settling.beneficiary(),
        withdrawals_root: settling.withdrawals_root(),
        difficulty: settling.difficulty(),
        number: settling.number(),
        gas_limit: settling.gas_limit(),
        timestamp: settling.timestamp(),
        extra_data: settling.extra_data().clone(),
        mix_hash: settling.mix_hash().unwrap_or_default(),
        nonce: settling.nonce().unwrap_or_default(),
        base_fee_per_gas: settling.base_fee_per_gas(),
        excess_blob_gas: settling.excess_blob_gas(),
        parent_beacon_block_root: settling.parent_beacon_block_root(),
        requests_hash: settling.requests_hash(),
        block_access_list_hash: None,
        slot_number: settling.slot_number(),
    };
    Ok(header.hash_slow())
}

/// Derive one cumulative root without mutating the live execution state.
fn checkpoint_state_root<T, DB>(
    witness: &ExecutionWitness,
    parent_state_root: B256,
    state: &State<DB>,
) -> Result<B256, StatelessValidationError>
where
    T: StatelessTrie,
{
    // Snapshot pending transitions instead of merging them into the live
    // executor state. Checkpoint derivation must not alter execution or its
    // revert history.
    let mut bundle = state.bundle_state.clone();
    if let Some(transitions) = state.transition_state.clone() {
        bundle.apply_transitions_and_create_reverts(transitions, BundleRetention::PlainState);
    }
    calculate_state_root::<T>(witness.clone(), parent_state_root, &bundle)
}

/// Rebuild the witness trie and apply a cumulative bundle snapshot.
fn calculate_state_root<T>(
    witness: ExecutionWitness,
    parent_state_root: B256,
    bundle: &BundleState,
) -> Result<B256, StatelessValidationError>
where
    T: StatelessTrie,
{
    let (mut trie, _) = T::new(witness, parent_state_root)?;
    let hashed_state = HashedPostState::from_bundle_state::<KeccakKeyHasher>(&bundle.state);
    trie.calculate_state_root(hashed_state).map_err(Into::into)
}

/// Apply the same post-execution consensus and commitment checks as the ordinary path.
fn validate_execution_output<T, ChainSpec, N>(
    current_block: &RecoveredBlock<GenericBlock<<N as NodePrimitives>::SignedTx>>,
    pre_state_root: B256,
    chain_spec: &Arc<ChainSpec>,
    mut trie: T,
    output: BlockExecutionOutput<N::Receipt>,
    block_access_list: Option<BlockAccessList>,
) -> Result<StatelessValidationOutput<N::Receipt>, StatelessValidationError>
where
    T: StatelessTrie,
    N: NodePrimitives<BlockHeader = Header, Block = GenericBlock<<N as NodePrimitives>::SignedTx>>,
    ChainSpec: Send + Sync + EthChainSpec<Header = Header> + EthereumHardforks + Debug,
{
    if let Some(bal) = block_access_list.as_ref() {
        let items = total_bal_items(bal.as_slice());
        let limit = current_block.sealed_header().gas_limit() / ITEM_COST as u64;
        if items > limit {
            return Err(StatelessValidationError::BlockAccessListGasLimitExceeded { items, limit });
        }
    }
    let block_access_list_hash = block_access_list.as_deref().map(compute_block_access_list_hash);
    validate_block_post_execution(
        current_block,
        chain_spec,
        &output.result,
        None,
        block_access_list_hash,
    )
    .map_err(StatelessValidationError::ConsensusValidationFailed)?;

    let hashed_state = HashedPostState::from_bundle_state::<KeccakKeyHasher>(&output.state.state);
    let post_state_root = trie.calculate_state_root(hashed_state)?;
    if post_state_root != current_block.state_root {
        return Err(StatelessValidationError::PostStateRootMismatch {
            got: post_state_root,
            expected: current_block.state_root,
        });
    }

    Ok(StatelessValidationOutput {
        block_hash: current_block.hash(),
        pre_state_root,
        post_state_root,
        execution_output: output,
        block_access_list,
    })
}

fn validate_block_consensus<ChainSpec, Tx: SignedTransaction>(
    chain_spec: Arc<ChainSpec>,
    block: &RecoveredBlock<GenericBlock<Tx>>,
    parent: &SealedHeader<Header>,
) -> Result<(), StatelessValidationError>
where
    ChainSpec: Send + Sync + EthChainSpec<Header = Header> + EthereumHardforks + Debug,
{
    let consensus = EthBeaconConsensus::new(chain_spec);

    consensus.validate_header(block.sealed_header())?;
    consensus.validate_header_against_parent(block.sealed_header(), parent)?;

    consensus.validate_block_pre_execution(block)?;

    Ok(())
}

fn compute_ancestor_hashes<Tx: SignedTransaction>(
    current_block: &RecoveredBlock<GenericBlock<Tx>>,
    ancestor_headers: &[SealedHeader],
) -> Result<BTreeMap<u64, B256>, StatelessValidationError> {
    let mut ancestor_hashes = BTreeMap::new();

    let mut child_header = current_block.sealed_header();

    for parent_header in ancestor_headers.iter().rev() {
        let parent_hash = child_header.parent_hash();
        ancestor_hashes.insert(parent_header.number, parent_hash);

        if parent_hash != parent_header.hash() {
            return Err(StatelessValidationError::InvalidAncestorParentHash {
                child_number: child_header.number,
                parent_number: parent_header.number,
                expected_parent_hash: parent_hash,
                actual_parent_hash: parent_header.hash(),
            });
        }

        if parent_header.number + 1 != child_header.number {
            return Err(StatelessValidationError::InvalidAncestorNumber {
                child_number: child_header.number,
                expected_parent_number: child_header.number.saturating_sub(1),
                parent_number: parent_header.number,
            });
        }

        child_header = parent_header
    }

    Ok(ancestor_hashes)
}

#[cfg(test)]
mod tests {
    use alloc::{sync::Arc, vec, vec::Vec};
    use alloy_primitives::Bytes;
    use reth_chainspec::ChainSpec;
    use reth_ethereum_primitives::Block;
    use reth_primitives_traits::RecoveredBlock;

    use super::{
        BLOCKHASH_ANCESTOR_LIMIT, StatelessValidationError, calculate_receipt_root,
        calculate_transaction_root, candidate_block_hash, logs_bloom, validate_block_inputs,
        validate_transaction_indices,
    };
    use crate::ExecutionWitness;
    use alloy_consensus::TxReceipt;
    use alloy_consensus::{Header, TxLegacy, TxType};
    use alloy_primitives::{Address, B256, Bloom, Log, Signature, U256};
    use reth_ethereum_primitives::{
        EthPrimitives, EthereumReceipt, Transaction, TransactionSigned,
    };
    use reth_primitives_traits::SealedHeader;

    fn tx(nonce: u64) -> TransactionSigned {
        TransactionSigned::new_unhashed(
            Transaction::Legacy(TxLegacy { nonce, ..Default::default() }),
            Signature::new(U256::from(1), U256::from(1), false),
        )
    }

    fn receipt(cumulative_gas_used: u64) -> EthereumReceipt {
        logging_receipt(cumulative_gas_used, Vec::new())
    }

    fn logging_receipt(cumulative_gas_used: u64, logs: Vec<Log>) -> EthereumReceipt {
        EthereumReceipt { tx_type: TxType::Legacy, success: true, cumulative_gas_used, logs }
    }

    /// Vary one prefix-varying input at a time; an inherited field would tie.
    #[test]
    fn every_prefix_varying_field_changes_the_candidate() {
        let settling = SealedHeader::seal_slow(Header::default());
        let txs = [tx(0), tx(1)];
        let receipts = [receipt(21_000), receipt(42_000)];
        let root = B256::repeat_byte(0xab);

        let base =
            candidate_block_hash::<EthPrimitives>(&settling, &txs[..1], &receipts[..1], root)
                .unwrap();

        // transactions_root
        assert_ne!(
            base,
            candidate_block_hash::<EthPrimitives>(&settling, &txs[..2], &receipts[..1], root)
                .unwrap(),
            "a longer transaction prefix must seal a different candidate",
        );
        // receipts_root, logs_bloom and gas_used all move together here
        assert_ne!(
            base,
            candidate_block_hash::<EthPrimitives>(&settling, &txs[..1], &receipts[..2], root)
                .unwrap(),
            "a longer receipt prefix must seal a different candidate",
        );
        // state_root
        assert_ne!(
            base,
            candidate_block_hash::<EthPrimitives>(
                &settling,
                &txs[..1],
                &receipts[..1],
                B256::repeat_byte(0xcd)
            )
            .unwrap(),
            "a different state root must seal a different candidate",
        );
    }

    /// Inequality between calls misses a uniformly wrong field, so pin the header.
    #[test]
    fn the_candidate_header_is_exactly_this() {
        let settling = SealedHeader::seal_slow(Header {
            // Unequal to the prefix's values, so inheriting shows up.
            gas_used: 999_999,
            transactions_root: B256::repeat_byte(0xf1),
            receipts_root: B256::repeat_byte(0xf2),
            logs_bloom: Bloom::repeat_byte(0xf3),
            number: 7,
            gas_limit: 30_000_000,
            timestamp: 1_234,
            ..Default::default()
        });
        let txs = [tx(0)];
        // A real log: with none, the computed bloom equals a default header's.
        let receipts = [logging_receipt(
            21_000,
            vec![Log::new_unchecked(
                Address::repeat_byte(0x42),
                vec![B256::repeat_byte(0x01)],
                Default::default(),
            )],
        )];
        let root = B256::repeat_byte(0xab);

        let expected = Header {
            state_root: root,
            transactions_root: calculate_transaction_root(&txs),
            receipts_root: calculate_receipt_root(
                &receipts.iter().map(TxReceipt::with_bloom_ref).collect::<Vec<_>>(),
            ),
            logs_bloom: logs_bloom(receipts.iter().flat_map(TxReceipt::logs)),
            gas_used: 21_000,
            number: 7,
            gas_limit: 30_000_000,
            timestamp: 1_234,
            ..Default::default()
        };

        assert_eq!(
            candidate_block_hash::<EthPrimitives>(&settling, &txs, &receipts, root).unwrap(),
            expected.hash_slow(),
        );
    }

    /// Fields a prefix cannot reproduce are refused, not inherited.
    #[test]
    fn unreproducible_fields_are_refused() {
        let with_bal = SealedHeader::seal_slow(Header {
            block_access_list_hash: Some(B256::repeat_byte(0x11)),
            ..Default::default()
        });
        assert!(matches!(
            candidate_block_hash::<EthPrimitives>(&with_bal, &[], &[], B256::ZERO),
            Err(StatelessValidationError::CandidateBlockUnsupportedField("block access list")),
        ));

        let with_requests = SealedHeader::seal_slow(Header {
            requests_hash: Some(B256::repeat_byte(0x22)),
            ..Default::default()
        });
        assert!(matches!(
            candidate_block_hash::<EthPrimitives>(&with_requests, &[], &[], B256::ZERO),
            Err(StatelessValidationError::CandidateBlockUnsupportedField("execution requests")),
        ));

        let with_blobs =
            SealedHeader::seal_slow(Header { blob_gas_used: Some(131_072), ..Default::default() });
        assert!(matches!(
            candidate_block_hash::<EthPrimitives>(&with_blobs, &[], &[], B256::ZERO),
            Err(StatelessValidationError::CandidateBlockUnsupportedField("blob transactions")),
        ));

        // Cancun without blob transactions is the ordinary case and must pass.
        let cancun =
            SealedHeader::seal_slow(Header { blob_gas_used: Some(0), ..Default::default() });
        assert!(candidate_block_hash::<EthPrimitives>(&cancun, &[], &[], B256::ZERO).is_ok());
    }

    #[test]
    fn accepts_empty_and_strictly_ordered_checkpoint_indices() {
        assert!(validate_transaction_indices(&[], 0).is_ok());
        assert!(validate_transaction_indices(&[0, 2, 4], 5).is_ok());
    }

    #[test]
    fn rejects_duplicate_or_descending_checkpoint_indices() {
        for indices in [&[1, 1][..], &[2, 1][..]] {
            assert!(matches!(
                validate_transaction_indices(indices, 3),
                Err(StatelessValidationError::UnorderedTransactionCheckpoints { .. })
            ));
        }
    }

    #[test]
    fn rejects_out_of_bounds_checkpoint_indices() {
        assert!(matches!(
            validate_transaction_indices(&[0, 3], 3),
            Err(StatelessValidationError::TransactionCheckpointOutOfBounds {
                index: 3,
                transactions: 3,
            })
        ));
    }

    #[test]
    fn rejects_excess_ancestor_headers_before_decoding_them() {
        let block = RecoveredBlock::new_unhashed(Block::default(), Vec::new());
        let witness = ExecutionWitness {
            headers: vec![Bytes::from_static(&[0xff]); BLOCKHASH_ANCESTOR_LIMIT + 1],
            ..Default::default()
        };

        assert!(matches!(
            validate_block_inputs(&block, &witness, Arc::new(ChainSpec::default())),
            Err(StatelessValidationError::AncestorHeaderLimitExceeded {
                count,
                limit: BLOCKHASH_ANCESTOR_LIMIT,
            }) if count == BLOCKHASH_ANCESTOR_LIMIT + 1
        ));
    }

    #[test]
    fn exact_ancestor_header_limit_reaches_header_decoding() {
        let block = RecoveredBlock::new_unhashed(Block::default(), Vec::new());
        let witness = ExecutionWitness {
            headers: vec![Bytes::from_static(&[0xff]); BLOCKHASH_ANCESTOR_LIMIT],
            ..Default::default()
        };

        assert!(matches!(
            validate_block_inputs(&block, &witness, Arc::new(ChainSpec::default())),
            Err(StatelessValidationError::HeaderDeserializationFailed)
        ));
    }
}
