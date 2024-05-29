use crate::ProofHashCalculator;
use alloy_primitives::{address, keccak256, private::proptest, Address, B256, U256};
use eyre::Context;
use proptest::prelude::*;
use reth::primitives::revm_primitives::StorageSlot;
use reth::providers::{StateProvider, StateProviderBox};
use reth::revm::db::{AccountStatus, BundleAccount, StorageWithOriginalValues};
use reth::{
    primitives::{Account, StorageEntry, KECCAK_EMPTY},
    providers::{test_utils::create_test_provider_factory, ProviderFactory},
    revm::primitives::AccountInfo,
};
use reth_db::{
    database::Database,
    tables,
    transaction::{DbTx, DbTxMut},
};
use reth_trie::hashed_cursor::HashedPostStateCursorFactory;
use reth_trie::{HashedPostState, StateRoot};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

fn reference_root_hash_calc<TX: DbTx + 'static>(
    tx: TX,
    hashed_post_state: HashedPostState,
) -> eyre::Result<B256> {
    let sorted_post_state = hashed_post_state.into_sorted();
    let hashed_cursor_factory = HashedPostStateCursorFactory::new(&tx, &sorted_post_state);
    Ok(StateRoot::from_tx(&tx)
        .with_hashed_cursor_factory(hashed_cursor_factory)
        .root()?)
}

fn caching_root_hash_calc(
    state_provider: &StateProviderBox,
    bundle_accounts: &HashMap<Address, BundleAccount>,
) -> eyre::Result<B256> {
    let mut proof_hash_calc =
        ProofHashCalculator::precalculate_from_block_state(bundle_accounts.iter());

    let mut proofs = HashMap::new();
    for (address, keys) in proof_hash_calc.get_proofs_to_fetch() {
        let proof = state_provider.proof(address, &keys)?;
        proofs.insert(address, proof);
    }

    Ok(proof_hash_calc.calculate_root_hash(&proofs)?)
}

#[derive(Debug, Clone)]
struct AccountState {
    address: Address,
    account: Account,
    storage: HashMap<B256, U256>,
}

impl AccountState {
    fn new(address: Address, balance: u64, nonce: u64, bytecode_hash: Option<B256>) -> Self {
        Self {
            address,
            account: Account {
                nonce,
                balance: U256::from(balance),
                bytecode_hash,
            },
            storage: HashMap::new(),
        }
    }

    fn new_empty(address: Address) -> Self {
        Self {
            address,
            account: Account::default(),
            storage: HashMap::new(),
        }
    }
}

fn prepare_trie_initial_state<DB: Database>(
    db: &DB,
    accounts: &[AccountState],
) -> eyre::Result<()> {
    let tx = db.tx_mut().unwrap();
    for account in accounts {
        let hashed_address: B256 = keccak256(account.address.as_slice());
        tx.put::<tables::HashedAccounts>(hashed_address, account.account.clone())?;

        for (k, v) in &account.storage {
            if *v != U256::ZERO {
                tx.put::<tables::HashedStorages>(
                    hashed_address,
                    StorageEntry {
                        key: keccak256(k),
                        value: *v,
                    },
                )?;
            }
        }
    }

    let (_, trie_updates) = StateRoot::from_tx(&tx).root_with_updates().unwrap();

    trie_updates.flush(&tx)?;
    tx.commit()?;

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccountWithChangeSeed {
    address: Address,
    initial_balance: Option<u64>,
    final_balance: Option<u64>,
    initial_storage: Vec<(u64, u64)>,
    new_storage: Vec<(u64, u64)>,
}

#[derive(Debug)]
struct AccountWithChange {
    address: Address,
    initial_state: Option<AccountState>,
    changed_state: Option<AccountState>,
    account_status: AccountStatus,

    seed_data: Option<AccountWithChangeSeed>,
}

impl AccountWithChange {
    fn new(address: Address) -> Self {
        Self {
            address,
            initial_state: None,
            changed_state: None,
            account_status: AccountStatus::LoadedNotExisting,
            seed_data: None,
        }
    }

    fn from_seed(seed: AccountWithChangeSeed) -> Self {
        let mut account = AccountWithChange::new(seed.address);
        account.seed_data = Some(seed.clone());
        if let Some(initial_balance) = seed.initial_balance {
            account = account.with_initial_state(initial_balance, 0, None);
        }
        if let Some(final_balance) = seed.final_balance {
            account = account.with_balance_change(final_balance);
        }
        if !seed.initial_storage.is_empty() {
            account = account.with_initial_storage(seed.initial_storage)
        }
        if !seed.new_storage.is_empty() {
            account = account.with_storage_change(seed.new_storage)
        }
        account.with_account_status(AccountStatus::Changed)
    }

    fn with_initial_state(mut self, balance: u64, nonce: u64, bytecode_hash: Option<B256>) -> Self {
        self.initial_state = Some(AccountState::new(
            self.address,
            balance,
            nonce,
            bytecode_hash,
        ));
        self
    }

    fn with_initial_storage(mut self, storage: impl IntoIterator<Item = (u64, u64)>) -> Self {
        let account_state = self
            .initial_state
            .get_or_insert(AccountState::new_empty(self.address));
        for (key, value) in storage {
            account_state
                .storage
                .insert(U256::from(key).into(), U256::from(value));
        }

        self
    }

    fn with_balance_change(mut self, new_balance: u64) -> Self {
        self.create_changed_account_state();
        let account_state = self.changed_state.as_mut().unwrap();
        account_state.account.balance = U256::from(new_balance);
        self
    }

    fn with_nonce_change(mut self, new_nonce: u64) -> Self {
        self.create_changed_account_state();
        let account_state = self.changed_state.as_mut().unwrap();
        account_state.account.nonce = new_nonce;
        self
    }

    fn with_changed_bytecode_hash(mut self, bytecode_hash: B256) -> Self {
        self.create_changed_account_state();
        let account_state = self.changed_state.as_mut().unwrap();
        account_state.account.bytecode_hash = Some(bytecode_hash);
        self
    }

    fn with_storage_change(mut self, new_storage: impl IntoIterator<Item = (u64, u64)>) -> Self {
        self.create_changed_account_state();
        let account_state = self.changed_state.as_mut().unwrap();
        for (key, value) in new_storage {
            account_state
                .storage
                .insert(U256::from(key).into(), U256::from(value));
        }
        self
    }

    fn with_account_status(mut self, account_status: AccountStatus) -> Self {
        self.account_status = account_status;
        self
    }

    fn initial_account_state(&self) -> Option<AccountState> {
        self.initial_state.clone()
    }

    // @Todo how to create deleted account?
    fn bundle_account(&self) -> Option<BundleAccount> {
        let initial_account_info = self.initial_state.clone().map(|s| AccountInfo {
            balance: s.account.balance,
            nonce: s.account.nonce,
            code_hash: s.account.bytecode_hash.unwrap_or(KECCAK_EMPTY),
            code: None,
        });

        let changed_state = if let Some(changes_state) = &self.changed_state {
            changes_state
        } else {
            return Some(BundleAccount::new(
                initial_account_info,
                None,
                StorageWithOriginalValues::default(),
                self.account_status,
            ));
        };

        let changed_account_info = AccountInfo {
            balance: changed_state.account.balance,
            nonce: changed_state.account.nonce,
            code_hash: changed_state.account.bytecode_hash.unwrap_or(KECCAK_EMPTY),
            code: None,
        };

        let mut storage = StorageWithOriginalValues::default();

        for (key, value) in &changed_state.storage {
            let original_value = self.get_original_storage_value(key);
            let storage_slot = StorageSlot::new_changed(original_value, *value);
            storage.insert((*key).into(), storage_slot);
        }

        Some(BundleAccount::new(
            initial_account_info,
            Some(changed_account_info),
            storage,
            self.account_status,
        ))
    }
}

impl AccountWithChange {
    fn create_changed_account_state(&mut self) {
        self.changed_state.get_or_insert_with(|| {
            if let Some(initial_state) = &self.initial_state {
                AccountState {
                    address: initial_state.address,
                    account: initial_state.account,
                    storage: Default::default(),
                }
            } else {
                AccountState::new_empty(self.address)
            }
        });
    }

    fn get_original_storage_value(&self, key: &B256) -> U256 {
        if let Some(initial_state) = &self.initial_state {
            initial_state.storage.get(key).cloned().unwrap_or_default()
        } else {
            U256::ZERO
        }
    }
}

fn compare_results_for_state<DB: Database + Clone + 'static>(
    accounts: &[AccountWithChange],
    provider_factory: ProviderFactory<DB>,
) -> eyre::Result<()> {
    let initial_state = accounts
        .iter()
        .filter_map(|a| a.initial_account_state())
        .collect::<Vec<_>>();
    prepare_trie_initial_state(provider_factory.db_ref(), &initial_state)
        .context("Prepare inital state")?;

    let bundle_state: HashMap<Address, BundleAccount> = accounts
        .iter()
        .filter_map(|a| a.bundle_account().map(|b| (a.address, b)))
        .collect();
    let hashed_post_state = HashedPostState::from_bundle_state(bundle_state.iter());

    let tx = provider_factory.db_ref().tx()?;
    let expected_hash = reference_root_hash_calc(tx, hashed_post_state.clone()).unwrap();
    dbg!(expected_hash);

    let got_hash = caching_root_hash_calc(&provider_factory.latest()?, &bundle_state).unwrap();
    dbg!(got_hash);
    Ok(())
}

#[test]
fn test_root_hash_changed_account() {
    let provider_factory = create_test_provider_factory();

    let account = AccountWithChange::new(address!("0000000000000000000000000000000000000001"))
        .with_initial_state(0, 0, None)
        .with_initial_storage(vec![(5, 7)])
        .with_balance_change(10)
        .with_nonce_change(2)
        .with_changed_bytecode_hash(B256::repeat_byte(8))
        .with_account_status(AccountStatus::Changed);

    compare_results_for_state(&[account], provider_factory).unwrap();
}

#[test]
fn test_root_hash_destroyed_account() {
    let provider_factory = create_test_provider_factory();

    let account = AccountWithChange::new(address!("0000000000000000000000000000000000000001"))
        .with_initial_state(0, 0, None)
        .with_initial_storage(vec![(5, 7)])
        .with_account_status(AccountStatus::Destroyed);

    compare_results_for_state(&[account], provider_factory).unwrap();
}

#[test]
fn test_root_hash_changed_storage() {
    let provider_factory = create_test_provider_factory();

    let account = AccountWithChange::new(address!("0000000000000000000000000000000000000001"))
        .with_initial_state(0, 0, None)
        .with_initial_storage(vec![(5, 7)])
        .with_storage_change(vec![(5, 8)])
        .with_account_status(AccountStatus::Changed);

    compare_results_for_state(&[account], provider_factory).unwrap();
}

#[test]
fn test_root_hash_inserted_storage() {
    let provider_factory = create_test_provider_factory();

    let account = AccountWithChange::new(address!("0000000000000000000000000000000000000001"))
        .with_initial_state(0, 0, None)
        .with_storage_change(vec![(6, 8)])
        .with_account_status(AccountStatus::Changed);

    compare_results_for_state(&[account], provider_factory).unwrap();
}

#[test]
fn test_root_hash_inserted_storage_when_storage_exists_ok() {
    let provider_factory = create_test_provider_factory();

    let account = AccountWithChange::new(address!("0000000000000000000000000000000000000001"))
        .with_initial_state(0, 0, None)
        .with_initial_storage(vec![(5, 7)])
        .with_storage_change(vec![(6, 8)])
        .with_account_status(AccountStatus::Changed);

    compare_results_for_state(&[account], provider_factory).unwrap();
}

#[test]
fn test_root_hash_inserted_storage_when_storage_exists() {
    let provider_factory = create_test_provider_factory();

    let account = AccountWithChange::new(address!("0000000000000000000000000000000000000001"))
        .with_initial_state(0, 0, None)
        .with_initial_storage(vec![(5, 7)])
        .with_storage_change(vec![(5, 8), (6, 8)])
        .with_account_status(AccountStatus::Changed);

    compare_results_for_state(&[account], provider_factory).unwrap();
}

#[test]
fn test_root_hash_empty_trie_new_account() {
    let provider_factory = create_test_provider_factory();

    let account = AccountWithChange::new(address!("0000000000000000000000000000000000000001"))
        .with_balance_change(10)
        .with_storage_change(vec![(5, 7)])
        .with_account_status(AccountStatus::Changed);

    compare_results_for_state(&[account], provider_factory).unwrap();
}

#[test]
fn test_root_hash_empty_trie_new_empty_account() {
    let provider_factory = create_test_provider_factory();

    let account = AccountWithChange::new(address!("0000000000000000000000000000000000000001"))
        .with_balance_change(0)
        .with_account_status(AccountStatus::Changed);

    compare_results_for_state(&[account], provider_factory).unwrap();
}

#[test]
fn test_root_hash_changed_accounts() {
    let provider_factory = create_test_provider_factory();

    let mut accounts = Vec::new();
    accounts.push(
        AccountWithChange::new(address!("0000000000000000000000000000000000000001"))
            .with_initial_state(0, 0, None)
            .with_initial_storage(vec![(5, 7)])
            .with_balance_change(10)
            .with_nonce_change(2)
            .with_changed_bytecode_hash(B256::repeat_byte(8))
            .with_account_status(AccountStatus::Changed),
    );

    accounts.push(
        AccountWithChange::new(address!("0000000000000000000000000000000000000002"))
            .with_balance_change(10)
            .with_nonce_change(2)
            .with_changed_bytecode_hash(B256::repeat_byte(8))
            .with_account_status(AccountStatus::Changed),
    );

    compare_results_for_state(&accounts, provider_factory).unwrap();
}

#[test]
fn panicking_test_2() {
    let provider_factory = create_test_provider_factory();

    let account = AccountWithChange::new(address!("0000000000000000000000000000000000000001"))
        .with_initial_state(0, 0, None)
        .with_initial_storage(vec![(0, 1)])
        .with_storage_change(vec![(0, 2), (1, 3)])
        .with_account_status(AccountStatus::Changed);

    compare_results_for_state(&[account], provider_factory).unwrap();
}

#[test]
fn panicking_test_3() {
    let provider_factory = create_test_provider_factory();

    let account = AccountWithChange::new(address!("0000000000000000000000000000000000000001"))
        .with_initial_state(0, 0, None)
        .with_initial_storage(vec![(432261123656, 1)])
        .with_storage_change(vec![(13528446866928600, 2), (1176412350699727397, 3)])
        .with_account_status(AccountStatus::Changed);

    compare_results_for_state(&[account], provider_factory).unwrap();
}

fn random_account() -> BoxedStrategy<AccountWithChange> {
    let address = any::<Address>();
    let initial_balance = any::<Option<u64>>();
    let final_balance = any::<Option<u64>>();
    let initial_storage = any::<Vec<(u64, u64)>>();
    let new_storage = any::<Vec<(u64, u64)>>();

    (
        initial_balance,
        final_balance,
        address,
        initial_storage,
        new_storage,
    )
        .prop_map(
            |(initial_balance, final_balance, address, initial_storage, new_storage)| {
                let seed = AccountWithChangeSeed {
                    address,
                    initial_balance,
                    final_balance,
                    initial_storage,
                    new_storage,
                };
                AccountWithChange::from_seed(seed)
            },
        )
        .boxed()
}

proptest! {
    #[test]
    fn proptest_root_hash_changed_account(account in random_account()) {
        let provider_factory = create_test_provider_factory();
        compare_results_for_state(&[account], provider_factory).unwrap();
    }
}
