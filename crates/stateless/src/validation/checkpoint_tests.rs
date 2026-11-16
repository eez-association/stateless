//! Prefix roots are checked against fresh, stopped executors that never clone BlockState.

use super::*;
use alloc::vec;
use alloy_consensus::{SignableTransaction, TxLegacy, TxReceipt, transaction::Recovered};
use alloy_primitives::{Address, Bytes, Signature, TxKind, U256, bytes};
use evm2::{
    BaseEvmTypes, SpecId,
    env::BlockEnv,
    evm::{BEACON_ROOTS_ADDRESS, Db},
};
use reth_chainspec::ChainSpecBuilder;
use reth_ethereum_primitives::TransactionSigned;
use reth_evm::BlockExecutorFactory;
use reth_evm_ethereum::{EthBlockExecutionCtx, EthBlockExecutorFactory, EthEvmEnv};
use reth_trie_common::TrieAccount;
use zeth_mpt::Trie;

const SENDER: Address = Address::repeat_byte(0x11);
const BENEFICIARY: Address = Address::repeat_byte(0x22);
const PARENT_BEACON_ROOT: B256 = B256::repeat_byte(0x44);

#[derive(Default)]
struct Account {
    address: Address,
    balance: U256,
    nonce: u64,
    code: Bytes,
    storage: Vec<(U256, U256)>,
}

fn witness(accounts: Vec<Account>) -> (ExecutionWitness, B256) {
    let mut state = Trie::default();
    let mut witness = ExecutionWitness::default();
    for account in accounts {
        let mut storage = Trie::default();
        for (slot, value) in account.storage {
            assert!(!value.is_zero());
            storage.insert(keccak256(B256::from(slot)), alloy_rlp::encode(value));
        }
        witness.state.extend(storage.rlp_nodes());
        let info = TrieAccount {
            nonce: account.nonce,
            balance: account.balance,
            storage_root: storage.hash_slow(),
            code_hash: keccak256(&account.code),
        };
        state.insert(keccak256(account.address), alloy_rlp::encode(info));
        if !account.code.is_empty() {
            witness.codes.push(account.code);
        }
    }
    witness.state.extend(state.rlp_nodes());
    (witness, state.hash_slow())
}

fn sender() -> Account {
    Account { address: SENDER, balance: U256::from(1_000_000_000u64), ..Default::default() }
}

fn call(nonce: u64, to: Address, input: Bytes) -> Recovered<TransactionSigned> {
    let tx = TxLegacy {
        chain_id: Some(1),
        nonce,
        gas_limit: 1_000_000,
        gas_price: 1,
        to: TxKind::Call(to),
        input,
        ..Default::default()
    };
    Recovered::new_unchecked(
        TransactionSigned::Legacy(tx.into_signed(Signature::new(U256::ONE, U256::ONE, false))),
        SENDER,
    )
}

fn assert_prefixes(
    spec: SpecId,
    accounts: Vec<Account>,
    transactions: Vec<Recovered<TransactionSigned>>,
    assert_state: impl Fn(usize, &StatelessSparseTrie),
) {
    let (witness, parent_root) = witness(accounts);
    let chain = match spec {
        SpecId::MERGE => ChainSpecBuilder::mainnet().paris_activated().build(),
        SpecId::OSAKA => ChainSpecBuilder::mainnet().osaka_activated().build(),
        _ => panic!("fixture must select an explicit fork"),
    };
    let factory = EthBlockExecutorFactory::new(Arc::new(chain));
    let env = EthEvmEnv::new(
        spec,
        BlockEnv::<BaseEvmTypes> {
            number: U256::ONE,
            timestamp: U256::from(12),
            beneficiary: BENEFICIARY,
            gas_limit: U256::from(30_000_000),
            basefee: U256::ONE,
            prevrandao: U256::ZERO,
            ..Default::default()
        },
        1,
    );
    let context = EthBlockExecutionCtx {
        tx_count_hint: Some(transactions.len()),
        parent_hash: B256::repeat_byte(0x33),
        parent_beacon_block_root: Some(PARENT_BEACON_ROOT),
        ommers: &[],
        withdrawals: None,
        extra_data: Bytes::new(),
        slot_number: None,
    };
    let (trie, codes) = StatelessSparseTrie::new(witness.clone(), parent_root).unwrap();
    let db = WitnessDatabase::new(&trie, codes, Default::default());
    let mut full =
        factory.create_executor(factory.evm_with_env(Db::new(db), env.clone()), context.clone());
    full.apply_pre_execution_changes().unwrap();
    for count in 0..=transactions.len() {
        if count > 0 {
            full.execute_transaction(transactions[count - 1].clone()).unwrap();
            assert!(
                full.receipts().last().unwrap().status(),
                "transaction {} must succeed",
                count - 1
            );
        }
        let snapshot_root = checkpoint_state_root::<StatelessSparseTrie>(
            &witness,
            parent_root,
            full.checkpoint_state(),
        )
        .unwrap();

        // Consume a fresh executor at the boundary. This oracle neither clones
        // BlockState nor calls the checkpoint helper to derive its expected root.
        let (prefix_trie, codes) = StatelessSparseTrie::new(witness.clone(), parent_root).unwrap();
        let db = WitnessDatabase::new(&prefix_trie, codes, Default::default());
        let mut prefix = factory
            .create_executor(factory.evm_with_env(Db::new(db), env.clone()), context.clone());
        prefix.apply_pre_execution_changes().unwrap();
        for transaction in transactions.iter().take(count) {
            prefix.execute_transaction(transaction.clone()).unwrap();
        }
        let bundle = prefix.into_state();
        let (mut expected, _) = StatelessSparseTrie::new(witness.clone(), parent_root).unwrap();
        let expected_root = apply_bundle_state(&mut expected, &bundle).unwrap();
        assert_eq!(snapshot_root, expected_root, "prefix {count} on {spec:?}");
        assert_state(count, &expected);
    }
    // Repeated snapshots must also leave the finalization path unchanged.
    let output = full.finish().unwrap();
    let (fresh, codes) = StatelessSparseTrie::new(witness.clone(), parent_root).unwrap();
    let db = WitnessDatabase::new(&fresh, codes, Default::default());
    let mut ordinary = factory.create_executor(factory.evm_with_env(Db::new(db), env), context);
    ordinary.apply_pre_execution_changes().unwrap();
    for tx in transactions {
        ordinary.execute_transaction(tx).unwrap();
    }
    assert_eq!(output, ordinary.finish().unwrap());
}

#[test]
fn stopped_prefixes_cover_destroy_recreate_and_slot_restore() {
    let factory_address = Address::repeat_byte(0x55);
    // Empty calldata destroys the child; nonempty calldata writes slot zero.
    let mut runtime = bytes!("3615600c57600035600055005b73").to_vec();
    runtime.extend_from_slice(BENEFICIARY.as_slice());
    runtime.push(0xff);
    let size = u8::try_from(runtime.len()).unwrap();
    let mut initcode = vec![0x60, size, 0x60, 12, 0x60, 0, 0x39, 0x60, size, 0x60, 0, 0xf3];
    initcode.extend(runtime);
    let initcode = Bytes::from(initcode);
    let child = factory_address.create2_from_code(B256::ZERO, &initcode);
    let accounts = vec![
        sender(),
        Account {
            address: factory_address,
            nonce: 1,
            // Copy calldata to memory and CREATE2 it with zero salt/value.
            code: bytes!("36600060003760003660006000f55000"),
            ..Default::default()
        },
    ];
    let txs = vec![
        call(0, factory_address, initcode.clone()),
        call(1, child, U256::from(42).to_be_bytes::<32>().into()),
        call(2, child, Bytes::new()),
        call(3, factory_address, initcode),
        call(4, child, U256::from(7).to_be_bytes::<32>().into()),
        call(5, child, U256::ZERO.to_be_bytes::<32>().into()),
    ];
    // Paris permits deleting an existing contract; Osaka's EIP-6780 does not.
    assert_prefixes(SpecId::MERGE, accounts, txs, |count, trie| {
        let account = trie.account(child).unwrap();
        if count == 0 || count == 3 {
            assert!(account.is_none(), "prefix {count}");
        } else {
            assert_eq!(account.unwrap().nonce, 1);
        }
        let expected = match count {
            2 => 42,
            5 => 7,
            _ => 0,
        };
        assert_eq!(trie.storage(child, U256::ZERO).unwrap(), U256::from(expected));
    });
}

#[test]
fn stopped_prefixes_cover_system_call_overlap_and_restoration() {
    let accounts = vec![
        sender(),
        Account {
            address: BEACON_ROOTS_ADDRESS,
            nonce: 1,
            // Both the pre-execution system call and user calls write slot zero.
            code: bytes!("60003560005500"),
            storage: vec![(U256::ZERO, U256::from(9))],
            ..Default::default()
        },
    ];
    let txs = vec![
        call(0, BEACON_ROOTS_ADDRESS, U256::from(7).to_be_bytes::<32>().into()),
        call(1, BEACON_ROOTS_ADDRESS, PARENT_BEACON_ROOT.as_slice().to_vec().into()),
        call(2, BEACON_ROOTS_ADDRESS, U256::from(9).to_be_bytes::<32>().into()),
    ];
    assert_prefixes(SpecId::OSAKA, accounts, txs, |count, trie| {
        let expected = match count {
            0 | 2 => U256::from_be_bytes(PARENT_BEACON_ROOT.0),
            1 => U256::from(7),
            _ => U256::from(9),
        };
        assert_eq!(trie.storage(BEACON_ROOTS_ADDRESS, U256::ZERO).unwrap(), expected);
    });
}

#[test]
fn stopped_prefixes_cover_empty_account_deletion() {
    let empty = Address::repeat_byte(0x77);
    assert_prefixes(
        SpecId::OSAKA,
        vec![sender(), Account { address: empty, ..Default::default() }],
        vec![call(0, empty, Bytes::new())],
        |count, trie| {
            assert_eq!(trie.account(empty).unwrap().is_some(), count == 0);
        },
    );
}
