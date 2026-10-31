use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::json_types::U128;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{env, near, require, AccountId, Gas, NearToken, PanicOnDefault, Promise, PromiseOrValue};

pub const GAS_FOR_EXECUTION: Gas = Gas::from_tgas(60);
pub const GAS_FOR_CALLBACK: Gas = Gas::from_tgas(10);

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(crate = "near_sdk::serde")]
pub enum ProposalStatus {
    Pending,
    Executed,
    Failed,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct Proposal {
    pub proposal_id: u64,
    pub proposer: AccountId,
    pub target: AccountId,
    pub method: String,
    pub args: String,
    pub deposit: U128,
    pub description: String,
    pub confirmations: Vec<AccountId>,
    pub status: ProposalStatus,
    pub created_at_ns: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct MultisigConfig {
    pub members: Vec<AccountId>,
    pub threshold: u32,
    pub total_proposals: u64,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct MultisigContract {
    pub members: Vec<AccountId>,
    pub threshold: u32,
    pub proposals: Vec<Proposal>,
    pub next_proposal_id: u64,
}

#[near]
impl MultisigContract {
    #[init]
    pub fn new(members: Vec<AccountId>, threshold: u32) -> Self {
        require!(!env::state_exists(), "Contract already initialized");
        require!(!members.is_empty(), "Multisig: at least one member required");
        require!(
            threshold >= 1 && (threshold as usize) <= members.len(),
            "Multisig: threshold must be between 1 and number of members"
        );
        let mut unique = members.clone();
        unique.sort();
        unique.dedup();
        require!(unique.len() == members.len(), "Multisig: duplicate members not allowed");
        Self {
            members,
            threshold,
            proposals: Vec::new(),
            next_proposal_id: 1,
        }
    }

    fn assert_member(&self) {
        let caller = env::predecessor_account_id();
        require!(
            self.members.contains(&caller),
            "Multisig: caller is not a member"
        );
    }

    /// Propose a contract call. The proposer automatically confirms.
    /// Executes immediately if the threshold is reached (e.g. threshold = 1).
    pub fn propose(
        &mut self,
        target: AccountId,
        method: String,
        args: String,
        deposit: Option<U128>,
        description: Option<String>,
    ) -> PromiseOrValue<u64> {
        self.assert_member();
        let proposer = env::predecessor_account_id();
        let id = self.next_proposal_id;
        self.next_proposal_id += 1;
        self.proposals.push(Proposal {
            proposal_id: id,
            proposer: proposer.clone(),
            target,
            method,
            args,
            deposit: deposit.unwrap_or(U128(0)),
            description: description.unwrap_or_default(),
            confirmations: vec![proposer],
            status: ProposalStatus::Pending,
            created_at_ns: env::block_timestamp(),
        });
        self.maybe_execute(id)
    }

    /// Confirm a pending proposal. Executes when confirmations reach threshold.
    pub fn confirm(&mut self, proposal_id: u64) -> PromiseOrValue<bool> {
        self.assert_member();
        let caller = env::predecessor_account_id();
        {
            let proposal = self
                .proposals
                .iter_mut()
                .find(|p| p.proposal_id == proposal_id)
                .expect("Multisig: proposal not found");
            require!(proposal.status == ProposalStatus::Pending, "Multisig: proposal is not pending");
            require!(
                !proposal.confirmations.contains(&caller),
                "Multisig: member has already confirmed"
            );
            proposal.confirmations.push(caller);
        }
        match self.maybe_execute(proposal_id) {
            PromiseOrValue::Promise(p) => PromiseOrValue::Promise(p),
            PromiseOrValue::Value(_) => PromiseOrValue::Value(true),
        }
    }

    /// Remove a member's confirmation from a pending proposal.
    pub fn revoke_confirmation(&mut self, proposal_id: u64) -> bool {
        self.assert_member();
        let caller = env::predecessor_account_id();
        let proposal = self
            .proposals
            .iter_mut()
            .find(|p| p.proposal_id == proposal_id)
            .expect("Multisig: proposal not found");
        require!(proposal.status == ProposalStatus::Pending, "Multisig: proposal is not pending");
        proposal.confirmations.retain(|m| m != &caller);
        true
    }

    fn maybe_execute(&mut self, proposal_id: u64) -> PromiseOrValue<u64> {
        let (ready, target, method, args, deposit) = {
            let proposal = self
                .proposals
                .iter()
                .find(|p| p.proposal_id == proposal_id)
                .expect("Multisig: proposal not found");
            (
                proposal.status == ProposalStatus::Pending
                    && (proposal.confirmations.len() as u32) >= self.threshold,
                proposal.target.clone(),
                proposal.method.clone(),
                proposal.args.clone(),
                proposal.deposit.0,
            )
        };
        if !ready {
            return PromiseOrValue::Value(proposal_id);
        }
        // Mark executed before dispatch to prevent replay / double execution.
        {
            let proposal = self
                .proposals
                .iter_mut()
                .find(|p| p.proposal_id == proposal_id)
                .unwrap();
            proposal.status = ProposalStatus::Executed;
        }
        let promise = Promise::new(target)
            .function_call(
                method,
                args.into_bytes(),
                NearToken::from_yoctonear(deposit),
                GAS_FOR_EXECUTION,
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_CALLBACK)
                    .on_executed(proposal_id),
            );
        PromiseOrValue::Promise(promise)
    }

    #[private]
    pub fn on_executed(&mut self, proposal_id: u64) -> bool {
        let success = env::promise_results_count() > 0
            && env::promise_result_checked(0, 1024 * 1024).is_ok();
        if !success {
            if let Some(proposal) = self
                .proposals
                .iter_mut()
                .find(|p| p.proposal_id == proposal_id)
            {
                proposal.status = ProposalStatus::Failed;
            }
        }
        success
    }

    pub fn get_config(&self) -> MultisigConfig {
        MultisigConfig {
            members: self.members.clone(),
            threshold: self.threshold,
            total_proposals: self.next_proposal_id - 1,
        }
    }

    pub fn get_proposal(&self, proposal_id: u64) -> Option<Proposal> {
        self.proposals.iter().find(|p| p.proposal_id == proposal_id).cloned()
    }

    pub fn list_proposals(&self, limit: Option<usize>) -> Vec<Proposal> {
        let max = limit.unwrap_or(50);
        let len = self.proposals.len();
        if len <= max {
            self.proposals.clone()
        } else {
            self.proposals[len - max..].to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn ctx(predecessor: &str) -> VMContextBuilder {
        let mut b = VMContextBuilder::new();
        b.current_account_id("guard.testnet".parse().unwrap())
            .signer_account_id(predecessor.parse().unwrap())
            .predecessor_account_id(predecessor.parse().unwrap())
            .block_timestamp(1_700_000_000_000_000_000);
        b
    }

    fn members() -> Vec<AccountId> {
        vec![
            "alice.testnet".parse().unwrap(),
            "bob.testnet".parse().unwrap(),
            "carol.testnet".parse().unwrap(),
        ]
    }

    fn setup() -> MultisigContract {
        testing_env!(ctx("alice.testnet").build());
        MultisigContract::new(members(), 2)
    }

    #[test]
    fn test_init_config() {
        let c = setup();
        let cfg = c.get_config();
        assert_eq!(cfg.threshold, 2);
        assert_eq!(cfg.members.len(), 3);
    }

    #[test]
    #[should_panic(expected = "Multisig: threshold must be between 1 and number of members")]
    fn test_init_rejects_bad_threshold() {
        testing_env!(ctx("alice.testnet").build());
        let _ = MultisigContract::new(members(), 4);
    }

    #[test]
    #[should_panic(expected = "Multisig: caller is not a member")]
    fn test_non_member_cannot_propose() {
        let mut c = setup();
        testing_env!(ctx("mallory.testnet").build());
        let _ = c.propose(
            "vault.testnet".parse().unwrap(),
            "emergency_freeze".to_string(),
            "{}".to_string(),
            None,
            None,
        );
    }

    #[test]
    fn test_proposal_waits_for_threshold() {
        let mut c = setup();
        let res = c.propose(
            "vault.testnet".parse().unwrap(),
            "emergency_freeze".to_string(),
            "{}".to_string(),
            None,
            Some("freeze vault".to_string()),
        );
        assert!(matches!(res, PromiseOrValue::Value(1)));
        let p = c.get_proposal(1).unwrap();
        assert_eq!(p.status, ProposalStatus::Pending);
        assert_eq!(p.confirmations.len(), 1);
    }

    #[test]
    fn test_second_confirmation_executes() {
        let mut c = setup();
        let _ = c.propose(
            "vault.testnet".parse().unwrap(),
            "emergency_freeze".to_string(),
            "{}".to_string(),
            None,
            None,
        );
        testing_env!(ctx("bob.testnet").build());
        let res = c.confirm(1);
        assert!(matches!(res, PromiseOrValue::Promise(_)));
        assert_eq!(c.get_proposal(1).unwrap().status, ProposalStatus::Executed);
    }

    #[test]
    #[should_panic(expected = "Multisig: member has already confirmed")]
    fn test_double_confirmation_rejected() {
        let mut c = setup();
        let _ = c.propose(
            "vault.testnet".parse().unwrap(),
            "emergency_freeze".to_string(),
            "{}".to_string(),
            None,
            None,
        );
        let _ = c.confirm(1);
    }

    #[test]
    fn test_revoke_confirmation() {
        let mut c = setup();
        let _ = c.propose(
            "vault.testnet".parse().unwrap(),
            "emergency_freeze".to_string(),
            "{}".to_string(),
            None,
            None,
        );
        assert!(c.revoke_confirmation(1));
        assert_eq!(c.get_proposal(1).unwrap().confirmations.len(), 0);
    }
}
