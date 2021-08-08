/*!
Fungible Token implementation with JSON serialization.
NOTES:
  - The maximum balance value is limited by U128 (2**128 - 1).
  - JSON calls should pass U128 as a base-10 string. E.g. "100".
  - The contract optimizes the inner trie structure by hashing account IDs. It will prevent some
    abuse of deep tries. Shouldn't be an issue, once NEAR clients implement full hashing of keys.
  - The contract tracks the change in storage before and after the call. If the storage increases,
    the contract requires the caller of the contract to attach enough deposit to the function call
    to cover the storage cost.
    This is done to prevent a denial of service attack on the contract by taking all available storage.
    If the storage decreases, the contract will issue a refund for the cost of the released storage.
    The unused tokens from the attached deposit are also refunded, so it's safe to
    attach more deposit than required.
  - To prevent the deployed contract from being modified or deleted, it should not have any access
    keys on its account.
*/
use near_contract_standards::fungible_token::metadata::{
    FungibleTokenMetadata, FungibleTokenMetadataProvider, FT_METADATA_SPEC,
};
use near_contract_standards::fungible_token::FungibleToken;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::LazyOption;
use near_sdk::json_types::{ValidAccountId, U128};
use near_sdk::{env, log, near_bindgen, AccountId, Balance, PanicOnDefault, PromiseOrValue};

near_sdk::setup_alloc!();

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct Contract {
    token: FungibleToken,
    metadata: LazyOption<FungibleTokenMetadata>,
}

const SVG_PARAS_ICON: &str = "data:image/png;base64,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";
const TOTAL_SUPPLY: Balance = 100_000_000_000_000_000_000_000_000;

#[near_bindgen]
impl Contract {
    #[init]
    pub fn new_paras_meta(owner_id: ValidAccountId) -> Self {
        Self::new(
            owner_id,
            U128(TOTAL_SUPPLY),
            FungibleTokenMetadata {
                spec: FT_METADATA_SPEC.to_string(),
                name: "PARAS".to_string(),
                symbol: "PARAS".to_string(),
                icon: Some(SVG_PARAS_ICON.to_string()),
                reference: None,
                reference_hash: None,
                decimals: 18
            },
        )
    }

    /// Initializes the contract with the given total supply owned by the given `owner_id` with
    /// the given fungible token metadata.
    #[init]
    pub fn new(
        owner_id: ValidAccountId,
        total_supply: U128,
        metadata: FungibleTokenMetadata,
    ) -> Self {
        assert!(!env::state_exists(), "Already initialized");
        metadata.assert_valid();
        let mut this = Self {
            token: FungibleToken::new(b"a".to_vec()),
            metadata: LazyOption::new(b"m".to_vec(), Some(&metadata)),
        };
        this.token.internal_register_account(owner_id.as_ref());
        this.token.internal_deposit(owner_id.as_ref(), total_supply.into());
        this
    }

    fn on_account_closed(&mut self, account_id: AccountId, balance: Balance) {
        log!("Closed @{} with {}", account_id, balance);
    }

    fn on_tokens_burned(&mut self, account_id: AccountId, amount: Balance) {
        log!("Account @{} burned {}", account_id, amount);
    }
}

near_contract_standards::impl_fungible_token_core!(Contract, token, on_tokens_burned);
near_contract_standards::impl_fungible_token_storage!(Contract, token, on_account_closed);

#[near_bindgen]
impl FungibleTokenMetadataProvider for Contract {
    fn ft_metadata(&self) -> FungibleTokenMetadata {
        self.metadata.get().unwrap()
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::MockedBlockchain;
    use near_sdk::{testing_env, Balance};

    use super::*;

    const TOTAL_SUPPLY: Balance = 1_000_000_000_000_000;

    fn get_context(predecessor_account_id: ValidAccountId) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        builder
            .current_account_id(accounts(0))
            .signer_account_id(predecessor_account_id.clone())
            .predecessor_account_id(predecessor_account_id);
        builder
    }

    #[test]
    fn test_new() {
        let mut context = get_context(accounts(1));
        testing_env!(context.build());
        let contract = Contract::new_default_meta(accounts(1).into(), TOTAL_SUPPLY.into());
        testing_env!(context.is_view(true).build());
        assert_eq!(contract.ft_total_supply().0, TOTAL_SUPPLY);
        assert_eq!(contract.ft_balance_of(accounts(1)).0, TOTAL_SUPPLY);
    }

    #[test]
    #[should_panic(expected = "The contract is not initialized")]
    fn test_default() {
        let context = get_context(accounts(1));
        testing_env!(context.build());
        let _contract = Contract::default();
    }

    #[test]
    fn test_transfer() {
        let mut context = get_context(accounts(2));
        testing_env!(context.build());
        let mut contract = Contract::new_default_meta(accounts(2).into(), TOTAL_SUPPLY.into());
        testing_env!(context
            .storage_usage(env::storage_usage())
            .attached_deposit(contract.storage_balance_bounds().min.into())
            .predecessor_account_id(accounts(1))
            .build());
        // Paying for account registration, aka storage deposit
        contract.storage_deposit(None, None);

        testing_env!(context
            .storage_usage(env::storage_usage())
            .attached_deposit(1)
            .predecessor_account_id(accounts(2))
            .build());
        let transfer_amount = TOTAL_SUPPLY / 3;
        contract.ft_transfer(accounts(1), transfer_amount.into(), None);

        testing_env!(context
            .storage_usage(env::storage_usage())
            .account_balance(env::account_balance())
            .is_view(true)
            .attached_deposit(0)
            .build());
        assert_eq!(contract.ft_balance_of(accounts(2)).0, (TOTAL_SUPPLY - transfer_amount));
        assert_eq!(contract.ft_balance_of(accounts(1)).0, transfer_amount);
    }
}
