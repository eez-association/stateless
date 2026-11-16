//! Provides the [`WitnessDatabase`] type, an implementation of [`evm2::evm::Database`]
//! specifically designed for stateless execution environments.

use alloc::{collections::btree_map::BTreeMap, format};
use alloy_primitives::{Address, B256, Bytes, map::B256IndexMap};
use evm2::{
    bytecode::Bytecode,
    evm::{AccountInfo, Database},
    interpreter::Word,
};
use tries::{StatelessTrie, WitnessDbError};

/// An EVM database implementation backed by witness data.
///
/// This struct implements the [`evm2::evm::Database`] trait, allowing the EVM to execute
/// transactions using:
///  - Account and storage slot data provided by a [`StatelessTrie`] implementation.
///  - Bytecode and ancestor block hashes provided by in-memory maps.
///
/// This is designed for stateless execution scenarios where direct access to a full node's
/// database is not available or desired.
#[derive(Debug)]
pub(crate) struct WitnessDatabase<'a, T>
where
    T: StatelessTrie,
{
    /// Map of block numbers to block hashes.
    /// This is used to service the `BLOCKHASH` opcode.
    block_hashes_by_block_number: BTreeMap<u64, B256>,
    /// Map of code hashes to bytecode.
    /// Used to fetch contract code needed during execution.
    bytecode: B256IndexMap<Bytes>,
    /// The sparse Merkle Patricia Trie containing account and storage state.
    /// This is used to provide account/storage values during EVM execution.
    trie: &'a T,
}

impl<'a, T> WitnessDatabase<'a, T>
where
    T: StatelessTrie,
{
    /// Creates a new [`WitnessDatabase`] instance.
    ///
    /// # Assumptions
    ///
    /// This function assumes:
    /// 1. The provided `trie` has been populated with state data consistent with a known state root
    ///    (e.g., using witness data and verifying against a parent block's state root).
    /// 2. The `bytecode` map contains all bytecode corresponding to code hashes present in the
    ///    account data within the `trie`.
    /// 3. The `ancestor_hashes` map contains the block hashes for the relevant ancestor blocks (up
    ///    to 256 including the current block number). It assumes these hashes correspond to a
    ///    contiguous chain of blocks. The caller is responsible for verifying the contiguity and
    ///    the block limit.
    pub(crate) const fn new(
        trie: &'a T,
        bytecode: B256IndexMap<Bytes>,
        ancestor_hashes: BTreeMap<u64, B256>,
    ) -> Self {
        Self { trie, block_hashes_by_block_number: ancestor_hashes, bytecode }
    }
}

impl<T> Database for WitnessDatabase<'_, T>
where
    T: StatelessTrie,
{
    /// The database error type.
    type Error = WitnessDbError;

    /// Get basic account information by hashing the address and looking up the account RLP
    /// in the underlying [`StatelessTrie`] implementation.
    ///
    /// Returns `Ok(None)` if the account is not found in the trie.
    fn get_account(&mut self, address: &Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.trie.account(*address).map(|opt| {
            opt.map(|account| {
                AccountInfo::new(account.balance, account.nonce, account.code_hash, None)
            })
        })
    }

    /// Get storage value of an account at a specific slot.
    ///
    /// Returns `Word::ZERO` if the slot is not found in the trie.
    fn get_storage(&mut self, address: &Address, slot: &Word) -> Result<Word, Self::Error> {
        self.trie.storage(*address, *slot)
    }

    /// Get account code by its hash from the provided bytecode map.
    ///
    /// Returns an error if the bytecode for the given hash is not found in the map.
    fn get_code_by_hash(&mut self, code_hash: &B256) -> Result<Bytecode, Self::Error> {
        let raw = self.bytecode.get(code_hash).cloned().ok_or_else(|| {
            WitnessDbError::TrieWitness(format!("bytecode for {code_hash} not found"))
        })?;
        // Stored legacy code may start with EF01 without being an EIP-7702 designator.
        Ok(Bytecode::from_stored(raw))
    }

    /// Get block hash by block number from the provided ancestor hashes map.
    ///
    /// Returns an error if the hash for the given block number is not found in the map.
    fn get_block_hash(&mut self, block_number: &Word) -> Result<B256, Self::Error> {
        let block_number = u64::try_from(*block_number).map_err(|_| {
            WitnessDbError::TrieWitness(format!("block number {block_number} exceeds u64"))
        })?;
        self.block_hashes_by_block_number
            .get(&block_number)
            .copied()
            .ok_or(WitnessDbError::StateNotFound(block_number))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use tries::default::StatelessSparseTrie;

    fn load_authenticated_code(raw: Bytes) -> Bytecode {
        let code_hash = alloy_primitives::keccak256(&raw);
        let mut state = zeth_mpt::Trie::default();
        let account = reth_trie_common::TrieAccount { code_hash, ..Default::default() };
        state.insert(alloy_primitives::keccak256(Address::ZERO), alloy_rlp::encode(account));
        let witness = crate::ExecutionWitness {
            state: state.rlp_nodes(),
            codes: alloc::vec![raw],
            ..Default::default()
        };
        let (trie, codes) = StatelessSparseTrie::new(witness, state.hash_slow()).unwrap();
        let mut db = WitnessDatabase::new(&trie, codes, Default::default());
        assert_eq!(db.get_account(&Address::ZERO).unwrap().unwrap().code_hash, code_hash);
        db.get_code_by_hash(&code_hash).unwrap()
    }

    #[test]
    fn authenticated_legacy_ef01_code_loads_without_panicking() {
        // Historical state and genesis can contain an EF01 prefix that is not
        // an EIP-7702 designator. Authentication does not make it a designator.
        for raw in [
            Bytes::from_static(&[0xef, 0x01]),
            alloy_primitives::bytes!("ef01011111111111111111111111111111111111111111"),
            Bytes::from_static(&[0x00]),
        ] {
            let code = load_authenticated_code(raw.clone());
            assert_eq!(code.original_bytes(), raw);
            assert!(code.is_legacy());
        }
    }

    #[test]
    fn authenticated_delegation_code_retains_its_designator() {
        let raw = alloy_primitives::bytes!("ef01001111111111111111111111111111111111111111");
        let code = load_authenticated_code(raw.clone());
        assert_eq!(code.original_bytes(), raw);
        assert!(code.is_eip7702());
    }

    #[test]
    fn missing_and_out_of_range_block_numbers_do_not_become_zero_hashes() {
        let mut state = zeth_mpt::Trie::default();
        state.insert(
            alloy_primitives::keccak256(Address::ZERO),
            alloy_rlp::encode(reth_trie_common::TrieAccount::default()),
        );
        let witness = crate::ExecutionWitness { state: state.rlp_nodes(), ..Default::default() };
        let (trie, codes) = StatelessSparseTrie::new(witness, state.hash_slow()).unwrap();
        let mut db = WitnessDatabase::new(&trie, codes, [(0, B256::with_last_byte(1))].into());
        assert_eq!(db.get_block_hash(&Word::ZERO).unwrap(), B256::with_last_byte(1));
        assert!(matches!(db.get_block_hash(&Word::from(1)), Err(WitnessDbError::StateNotFound(1))));
        let oversized = U256::from(u64::MAX) + U256::from(1);
        assert!(matches!(db.get_block_hash(&oversized), Err(WitnessDbError::TrieWitness(_))));
        assert!(matches!(
            db.get_code_by_hash(&B256::with_last_byte(2)),
            Err(WitnessDbError::TrieWitness(_))
        ));
    }
}
