#[cfg(test)]
pub mod reth_trie_tests;

use alloy_primitives::{keccak256, Address, Bytes, B256};
use alloy_rlp::{Decodable, Encodable};
use reth::primitives::constants::EMPTY_ROOT_HASH;
use reth::primitives::revm::compat::into_reth_acc;
use reth::primitives::trie::nodes::{TrieNode, CHILD_INDEX_RANGE};
use reth::primitives::trie::{AccountProof, HashBuilder, Nibbles, TrieAccount};
use reth::revm::db::BundleAccount;
use reth_trie::prefix_set::TriePrefixSets;
use reth_trie::{HashedPostState, HashedStorage};
use std::collections::HashMap;

#[derive(Debug)]
pub struct ProofHashCalculator {
    account_reverse_lookup: HashMap<B256, Address>,
    storage_reverse_lookup: HashMap<B256, B256>,
    hashed_state: HashedPostState,
    prefix_sets: TriePrefixSets,
}

impl ProofHashCalculator {
    pub fn precalculate_from_block_state<'a>(
        bundle_accounts: impl Iterator<Item = (&'a Address, &'a BundleAccount)>,
    ) -> Self {
        let mut account_reverse_lookup = HashMap::<B256, Address>::default();
        let mut storage_reverse_lookup = HashMap::<B256, B256>::default();
        let mut hashed_state = HashedPostState::default();

        // Reconstruct prefix sets manually to record pre-images for subsequent lookups
        for (address, account) in bundle_accounts {
            let hashed_address = keccak256(address);
            account_reverse_lookup.insert(hashed_address, *address);
            hashed_state
                .accounts
                .insert(hashed_address, account.info.clone().map(into_reth_acc));

            let mut hashed_storage = HashedStorage::new(account.status.was_destroyed());
            for (key, value) in &account.storage {
                let slot = B256::new(key.to_be_bytes());
                let hashed_slot = keccak256(&slot);
                storage_reverse_lookup.insert(hashed_slot, slot);
                hashed_storage
                    .storage
                    .insert(hashed_slot, value.present_value);
            }
            hashed_state.storages.insert(hashed_address, hashed_storage);
        }

        let prefix_sets = hashed_state.construct_prefix_sets();

        Self {
            account_reverse_lookup,
            storage_reverse_lookup,
            hashed_state,
            prefix_sets,
        }
    }

    pub fn get_proofs_to_fetch(&self) -> Vec<(Address, Vec<B256>)> {
        let mut result = Vec::new();

        let mut account_prefix_set_iter = self
            .prefix_sets
            .account_prefix_set
            .keys
            .as_ref()
            .iter()
            .peekable();

        while let Some(account_nibbles) = account_prefix_set_iter.next() {
            let hashed_address = B256::from_slice(&account_nibbles.pack());
            let address = *self.account_reverse_lookup.get(&hashed_address).unwrap();
            let storage_keys = if let Some(storage_prefix_sets) =
                self.prefix_sets.storage_prefix_sets.get(&hashed_address)
            {
                storage_prefix_sets
                    .keys
                    .iter()
                    .map(|nibbles| {
                        *self
                            .storage_reverse_lookup
                            .get(&B256::from_slice(&nibbles.pack()))
                            .unwrap()
                    })
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            result.push((address, storage_keys));
        }
        result
    }

    pub fn calculate_root_hash(
        &mut self,
        proofs: &HashMap<Address, AccountProof>,
    ) -> eyre::Result<B256> {
        let mut rlp_buf = Vec::with_capacity(128);

        let mut hash_builder = HashBuilder::default();
        let mut account_prefix_set_iter = self
            .prefix_sets
            .account_prefix_set
            .keys
            .as_ref()
            .iter()
            .peekable();
        while let Some(account_nibbles) = account_prefix_set_iter.next() {
            let hashed_address = B256::from_slice(&account_nibbles.pack());
            let address = *self.account_reverse_lookup.get(&hashed_address).unwrap();
            let storage_prefix_sets = self
                .prefix_sets
                .storage_prefix_sets
                .remove(&hashed_address)
                .unwrap_or_default();

            let proof = proofs.get(&address).unwrap();

            let storage_root = if storage_prefix_sets.is_empty() {
                proof.storage_root
            } else {
                let mut storage_hash_builder = HashBuilder::default();
                let mut storage_prefix_set_iter =
                    storage_prefix_sets.keys.as_ref().iter().peekable();
                while let Some(storage_nibbles) = storage_prefix_set_iter.next() {
                    let hashed_slot = B256::from_slice(&storage_nibbles.pack());
                    let slot = self.storage_reverse_lookup.get(&hashed_slot).unwrap();
                    let proof = proof
                        .storage_proofs
                        .iter()
                        .find(|p| &p.key.0 == slot)
                        .cloned()
                        .unwrap_or_default();
                    update_hash_builder_from_proof(
                        &mut storage_hash_builder,
                        &proof.proof,
                        Nibbles::default(),
                        storage_nibbles,
                        Some(
                            self.hashed_state
                                .storages
                                .get(&hashed_address)
                                .and_then(|s| s.storage.get(&hashed_slot).cloned())
                                .unwrap_or_default(),
                        )
                        .filter(|v| !v.is_zero())
                        .map(|v| alloy_rlp::encode_fixed_size(&v).to_vec()),
                        storage_prefix_set_iter.peek().copied(),
                    )?;
                }
                storage_hash_builder.root()
            };

            let account = self
                .hashed_state
                .accounts
                .get(&hashed_address)
                .unwrap()
                .unwrap_or_default();
            let encoded = if account.is_empty() && storage_root == EMPTY_ROOT_HASH {
                None
            } else {
                rlp_buf.clear();
                TrieAccount::from((account, storage_root)).encode(&mut rlp_buf);
                Some(rlp_buf.clone())
            };

            update_hash_builder_from_proof(
                &mut hash_builder,
                &proof.proof[..],
                Nibbles::default(),
                &account_nibbles,
                encoded,
                account_prefix_set_iter.peek().copied(),
            )?;
        }

        Ok(hash_builder.root())
    }
}

fn update_hash_builder_from_proof(
    hash_builder: &mut HashBuilder,
    proof: &[Bytes],
    current_key: Nibbles,
    key: &Nibbles,
    value: Option<Vec<u8>>,
    next: Option<&Nibbles>,
) -> eyre::Result<()> {
    let Some(node) = proof.first() else {
        // Add leaf node if any
        if let Some(value) = &value {
            hash_builder.add_leaf(key.clone(), value);
        }
        return Ok(());
    };

    match TrieNode::decode(&mut &node[..])? {
        TrieNode::Branch(branch) => {
            let mut stack_ptr = branch.as_ref().first_child_index();
            for index in CHILD_INDEX_RANGE {
                let mut updated_key = current_key.clone();
                updated_key.push(index);

                let state_mask_bit_set = branch.state_mask.is_bit_set(index);

                if key.starts_with(&updated_key) {
                    update_hash_builder_from_proof(
                        hash_builder,
                        if proof.len() != 0 { &proof[1..] } else { &[] },
                        updated_key,
                        key,
                        value.clone(),
                        next,
                    )?;
                } else if state_mask_bit_set
                    && updated_key > hash_builder.key
                    && next.map_or(true, |n| &updated_key < n && !n.starts_with(&updated_key))
                {
                    hash_builder.add_branch(
                        updated_key,
                        // proofs can only contain hashes
                        B256::from_slice(&branch.stack[stack_ptr][1..]),
                        false,
                    );
                }

                if state_mask_bit_set {
                    stack_ptr += 1;
                }
            }
        }

        TrieNode::Extension(extension) => {
            let mut updated_key = current_key.clone();
            updated_key.extend_from_slice(&extension.key);
            update_hash_builder_from_proof(
                hash_builder,
                if proof.len() == 0 { &[] } else { &proof[1..] },
                updated_key,
                key,
                value.clone(),
                next,
            )?;
        }
        TrieNode::Leaf(leaf) => {
            let mut updated_key = current_key.clone();
            updated_key.extend_from_slice(&leaf.key);

            // Add current leaf node and supplied if any
            let mut leaves = Vec::new();
            if &updated_key != key
                && updated_key > hash_builder.key
                && next.map_or(true, |n| &updated_key < n)
            {
                leaves.push((updated_key, &leaf.value));
            }
            if let Some(value) = &value {
                leaves.push((key.clone(), &value));
            }
            leaves.sort_unstable_by_key(|(key, _)| key.clone());
            for (nibbles, value) in leaves {
                hash_builder.add_leaf(nibbles, value);
            }
        }
    };

    Ok(())
}
