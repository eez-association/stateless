//! Conformance coverage for selected transaction state checkpoints.

use std::sync::Arc;

use alloy_consensus::Header;
use alloy_genesis::{ChainConfig, Genesis};
use alloy_primitives::{B256, hex};
use reth_chainspec::ChainSpec;
use reth_ethereum_primitives::Block;
use reth_evm_ethereum::EthEvmConfig;
use reth_primitives_traits::RecoveredBlock;
use stateless::{
    ExecutionWitness, stateless_validation_recovered,
    stateless_validation_recovered_with_state_checkpoints,
};

const BLOCK_RLP: &str = include_str!("fixtures/checkpoint-block-2175.rlp.hex");
const WITNESS: &str = include_str!("fixtures/checkpoint-witness-2175.json");
const CHAIN_CONFIG: &str = include_str!("fixtures/checkpoint-chain-config.json");
const ORACLE: &str = include_str!("fixtures/checkpoint-oracle-2175.json");

#[derive(serde::Deserialize)]
struct CheckpointOracle {
    block_number: u64,
    block_hash: B256,
    parent_state_root: B256,
    expected_checkpoint_indices: Vec<usize>,
    transaction_state_roots: Vec<B256>,
}

#[test]
fn selected_transaction_checkpoints_match_the_recorded_full_state_roots() {
    let oracle: CheckpointOracle = serde_json::from_str(ORACLE).unwrap();
    let block_rlp = hex::decode(BLOCK_RLP.trim()).unwrap();
    let block = alloy_rlp::decode_exact::<Block>(&block_rlp).unwrap();
    assert_eq!(block.header.number, oracle.block_number);
    assert_eq!(block.body.transactions.len(), 3);
    let expected_post_state_root = block.header.state_root;

    let recovered = RecoveredBlock::try_recover(block).unwrap();
    let witness: ExecutionWitness = serde_json::from_str(WITNESS).unwrap();
    let parent_header = alloy_rlp::decode_exact::<Header>(
        witness.headers.last().expect("fixture has a parent header"),
    )
    .unwrap();
    assert_eq!(parent_header.state_root, oracle.parent_state_root);

    let config: ChainConfig = serde_json::from_str(CHAIN_CONFIG).unwrap();
    let chain_spec = Arc::new(ChainSpec::from_genesis(Genesis { config, ..Default::default() }));
    let evm_config = EthEvmConfig::new(Arc::clone(&chain_spec));

    let ordinary = stateless_validation_recovered(
        recovered.clone(),
        witness.clone(),
        Arc::clone(&chain_spec),
        evm_config.clone(),
    )
    .unwrap();
    let detailed = stateless_validation_recovered_with_state_checkpoints(
        recovered.clone(),
        witness.clone(),
        Arc::clone(&chain_spec),
        evm_config.clone(),
        &oracle.expected_checkpoint_indices,
    )
    .unwrap();
    let sparse = stateless_validation_recovered_with_state_checkpoints(
        recovered,
        witness,
        chain_spec,
        evm_config,
        &[0, 2],
    )
    .unwrap();

    assert_eq!(detailed.validation, ordinary);
    assert_eq!(detailed.validation.block_hash, oracle.block_hash);
    assert_eq!(detailed.validation.pre_state_root, oracle.parent_state_root);
    assert_eq!(detailed.validation.post_state_root, expected_post_state_root);
    assert_eq!(sparse.validation, ordinary);
    assert_eq!(
        oracle.expected_checkpoint_indices,
        [0, 1, 2],
        "recorded settling block changed its expected effect boundaries"
    );
    assert_eq!(oracle.expected_checkpoint_indices.len(), oracle.transaction_state_roots.len());
    let expected = oracle
        .transaction_state_roots
        .into_iter()
        .zip(oracle.expected_checkpoint_indices)
        .collect::<Vec<_>>();
    let observed = &detailed.checkpoints.transaction_state_checkpoints;
    assert_eq!(
        observed.iter().map(|c| (c.state_root, c.transaction_index)).collect::<Vec<_>>(),
        expected,
    );
    assert_eq!(sparse.checkpoints.transaction_state_checkpoints, [observed[0], observed[2]]);

    // The candidate at the final transaction holds every transaction, so it IS
    // the block under validation. Its hash must therefore equal the block's own
    // — a value this code did not produce. That check covers the whole
    // prefix-varying field list at once: get transactions_root, receipts_root,
    // logs_bloom or gas_used wrong and this fails.
    let last = observed.last().expect("the fixture selects the final transaction");
    assert_eq!(last.transaction_index, 2, "fixture no longer ends on the last transaction");
    assert_eq!(
        last.block_hash, detailed.validation.block_hash,
        "the full-prefix candidate must be the block itself",
    );

    // Shorter prefixes are different blocks. A candidate that reused the full
    // block's transaction or receipt roots would collide here.
    assert!(
        observed[0].block_hash != last.block_hash && observed[1].block_hash != last.block_hash,
        "a proper prefix must not seal to the full block's hash",
    );
    assert_ne!(observed[0].block_hash, observed[1].block_hash);
}
