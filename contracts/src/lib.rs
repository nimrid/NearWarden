pub mod escalation;
pub mod policy;

use escalation::{ActionStatus, EscalationQueue, PendingAction};
use policy::{PolicyConfig, PolicyViolation, SpendingTracker};

use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::json_types::U128;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{env, near, require, AccountId, Gas, NearToken, PanicOnDefault, Promise, PromiseOrValue};

pub const GAS_FOR_INTENT: Gas = Gas::from_tgas(30);
pub const GAS_FOR_CALLBACK: Gas = Gas::from_tgas(10);

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct AuditEntry {
    pub timestamp_ns: u64,
    pub caller: AccountId,
    pub target: AccountId,
    pub method: String,
    pub amount: U128,
    pub status: String,
    pub threat_score: u8,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(crate = "near_sdk::serde")]
pub struct ExecutionResult {
    pub success: bool,
    pub status_code: u16,
    pub message: String,
    pub action_id: Option<u64>,
    pub threat_score: u8,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct VaultStatusView {
    pub owner_id: AccountId,
    pub is_frozen: bool,
    pub daily_spending_cap: U128,
    pub daily_spent: U128,
    pub remaining_daily_quota: U128,
    pub per_tx_cap: U128,
    pub total_pending_actions: usize,
    pub audit_log_count: usize,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct AgentGuardContract {
    pub owner_id: AccountId,
    pub policy: PolicyConfig,
    pub tracker: SpendingTracker,
    pub escalation: EscalationQueue,
    pub audit_log: Vec<AuditEntry>,
}

#[near]
impl AgentGuardContract {
    #[init]
    pub fn new(owner_id: AccountId, policy: Option<PolicyConfig>) -> Self {
        require!(!env::state_exists(), "Contract already initialized");
        let initial_policy = policy.unwrap_or_default();
        let current_time = env::block_timestamp();

        Self {
            owner_id,
            policy: initial_policy,
            tracker: SpendingTracker::new(current_time),
            escalation: EscalationQueue::new(),
            audit_log: Vec::new(),
        }
    }

    /// Primary execution gate for Autonomous AI Agents holding Function Call Keys.
    /// Evaluates requested action against on-chain policy constraints and spending rules.
    pub fn execute_intent(
        &mut self,
        target: AccountId,
        method: String,
        args: String,
        amount: Option<U128>,
    ) -> PromiseOrValue<ExecutionResult> {
        let caller = env::predecessor_account_id();
        let current_time = env::block_timestamp();
        let amount_raw: u128 = amount.map(|a| a.0).unwrap_or(0);

        // Pre-validate against policy
        match self.tracker.validate_and_record(
            &self.policy,
            &target,
            &method,
            amount_raw,
            current_time,
        ) {
            Ok(()) => {
                let entry = AuditEntry {
                    timestamp_ns: current_time,
                    caller: caller.clone(),
                    target: target.clone(),
                    method: method.clone(),
                    amount: U128(amount_raw),
                    status: "APPROVED_AND_EXECUTED".to_string(),
                    threat_score: 5,
                };
                self.audit_log.push(entry);

                // Dispatch on-chain cross-contract call with callback
                let promise = Promise::new(target.clone())
                    .function_call(
                        method.clone(),
                        args.into_bytes(),
                        NearToken::from_yoctonear(amount_raw),
                        GAS_FOR_INTENT,
                    )
                    .then(
                        Self::ext(env::current_account_id())
                            .with_static_gas(GAS_FOR_CALLBACK)
                            .on_intent_executed(caller, target, method, U128(amount_raw))
                    );

                PromiseOrValue::Promise(promise)
            }
            Err(PolicyViolation::ExceedsPerTxCap { amount, cap }) => {
                // If value exceeds single-tx limit but contract is not frozen, escalate to human approval
                let action_id = self.escalation.enqueue(
                    target.clone(),
                    method.clone(),
                    args,
                    amount_raw,
                    current_time,
                );

                let entry = AuditEntry {
                    timestamp_ns: current_time,
                    caller: caller.clone(),
                    target,
                    method,
                    amount: U128(amount_raw),
                    status: format!("ESCALATED_ACTION_{}", action_id),
                    threat_score: 65,
                };
                self.audit_log.push(entry);

                PromiseOrValue::Value(ExecutionResult {
                    success: false,
                    status_code: 202,
                    message: format!(
                        "Amount {} yoctoNEAR exceeds autonomous per-tx limit of {} yoctoNEAR. Escalated to pending action #{}",
                        amount, cap, action_id
                    ),
                    action_id: Some(action_id),
                    threat_score: 65,
                })
            }
            Err(err) => {
                let (error_msg, code, threat_score) = match err {
                    PolicyViolation::VaultFrozen => {
                        ("Vault is emergency frozen. All agent operations are halted.".to_string(), 503, 90)
                    }
                    PolicyViolation::TargetNotAllowed(t) => {
                        (format!("Contract target '{}' is not in authorized whitelist.", t), 403, 85)
                    }
                    PolicyViolation::MethodNotAllowed(m) => {
                        (format!("Method '{}' is not an authorized agent method.", m), 403, 80)
                    }
                    PolicyViolation::ExceedsDailyQuota { spent_today, attempted, cap } => {
                        (format!(
                            "Daily spending quota exhausted. Spent today: {}, Attempted: {}, Cap: {}",
                            spent_today, attempted, cap
                        ), 429, 75)
                    }
                    PolicyViolation::VelocityLimitExceeded { calls_in_window, max_allowed } => {
                        (format!(
                            "Velocity limit tripped: {} calls in past hour exceeds max of {}.",
                            calls_in_window, max_allowed
                        ), 429, 70)
                    }
                    PolicyViolation::ExceedsPerTxCap { .. } => unreachable!(),
                };

                let entry = AuditEntry {
                    timestamp_ns: current_time,
                    caller: caller.clone(),
                    target,
                    method,
                    amount: U128(amount_raw),
                    status: format!("BLOCKED: {}", error_msg),
                    threat_score,
                };
                self.audit_log.push(entry);

                PromiseOrValue::Value(ExecutionResult {
                    success: false,
                    status_code: code,
                    message: error_msg,
                    action_id: None,
                    threat_score,
                })
            }
        }
    }

    /// Callback for execute_intent: validates execution and refunds quota if the call failed
    #[private]
    pub fn on_intent_executed(
        &mut self,
        caller: AccountId,
        target: AccountId,
        method: String,
        amount: U128,
    ) -> ExecutionResult {
        let success = env::promise_results_count() > 0 && env::promise_result_checked(0, 1024 * 1024).is_ok();

        if !success {
            self.tracker.rollback_spend(amount.0);

            self.audit_log.push(AuditEntry {
                timestamp_ns: env::block_timestamp(),
                caller,
                target: target.clone(),
                method: method.clone(),
                amount,
                status: "CROSS_CONTRACT_FAILED_QUOTA_REVERTED".to_string(),
                threat_score: 30,
            });

            ExecutionResult {
                success: false,
                status_code: 500,
                message: format!("Execution of {} on {} failed; quota refunded", method, target),
                action_id: None,
                threat_score: 30,
            }
        } else {
            ExecutionResult {
                success: true,
                status_code: 200,
                message: format!("Intent executed successfully on {}", target),
                action_id: None,
                threat_score: 5,
            }
        }
    }

    /// Emergency Killswitch: instantly halts all autonomous agent actions
    pub fn emergency_freeze(&mut self) {
        self.assert_owner();
        self.policy.emergency_frozen = true;

        self.audit_log.push(AuditEntry {
            timestamp_ns: env::block_timestamp(),
            caller: env::predecessor_account_id(),
            target: env::current_account_id(),
            method: "emergency_freeze".to_string(),
            amount: U128(0),
            status: "EMERGENCY_FREEZE_ACTIVATED".to_string(),
            threat_score: 95,
        });
    }

    /// Unfreezes the vault after operator review
    pub fn emergency_unfreeze(&mut self) {
        self.assert_owner();
        self.policy.emergency_frozen = false;

        self.audit_log.push(AuditEntry {
            timestamp_ns: env::block_timestamp(),
            caller: env::predecessor_account_id(),
            target: env::current_account_id(),
            method: "emergency_unfreeze".to_string(),
            amount: U128(0),
            status: "EMERGENCY_FREEZE_LIFTED".to_string(),
            threat_score: 0,
        });
    }

    /// Approve an escalated transaction (Human-in-the-Loop) and execute its payload on-chain
    pub fn approve_escalated(&mut self, action_id: u64) -> PromiseOrValue<bool> {
        self.assert_owner();
        let action = self.escalation.get_action_mut(action_id).expect("Action not found");
        require!(action.status == ActionStatus::Pending, "Action is not pending");

        action.status = ActionStatus::Approved;

        let target = action.target.clone();
        let method = action.method.clone();
        let args = action.args.clone().into_bytes();
        let deposit = action.deposit;

        self.audit_log.push(AuditEntry {
            timestamp_ns: env::block_timestamp(),
            caller: env::predecessor_account_id(),
            target: target.clone(),
            method: method.clone(),
            amount: U128(deposit),
            status: format!("MANUALLY_APPROVED_AND_DISPATCHED_ACTION_{}", action_id),
            threat_score: 10,
        });

        let promise = Promise::new(target)
            .function_call(
                method,
                args,
                NearToken::from_yoctonear(deposit),
                GAS_FOR_INTENT,
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_CALLBACK)
                    .on_escalated_executed(action_id)
            );

        PromiseOrValue::Promise(promise)
    }

    /// Callback for approve_escalated: records on-chain outcome in escalation queue
    #[private]
    pub fn on_escalated_executed(&mut self, action_id: u64) -> bool {
        let success = env::promise_results_count() > 0 && env::promise_result_checked(0, 1024 * 1024).is_ok();

        if let Some(action) = self.escalation.get_action_mut(action_id) {
            action.status = if success {
                ActionStatus::Executed
            } else {
                ActionStatus::Rejected
            };
        }
        success
    }

    /// Reject an escalated transaction
    pub fn reject_escalated(&mut self, action_id: u64) -> bool {
        self.assert_owner();
        let action = self.escalation.get_action_mut(action_id).expect("Action not found");
        require!(action.status == ActionStatus::Pending, "Action is not pending");

        action.status = ActionStatus::Rejected;

        self.audit_log.push(AuditEntry {
            timestamp_ns: env::block_timestamp(),
            caller: env::predecessor_account_id(),
            target: action.target.clone(),
            method: action.method.clone(),
            amount: U128(action.deposit),
            status: format!("MANUALLY_REJECTED_ACTION_{}", action_id),
            threat_score: 30,
        });

        true
    }

    /// Update security policy parameters
    pub fn update_policy(&mut self, new_policy: PolicyConfig) {
        self.assert_owner();
        self.policy = new_policy;
    }

    // --- VIEW METHODS ---

    pub fn get_vault_status(&self) -> VaultStatusView {
        let current_time = env::block_timestamp();
        let remaining_quota = self.policy.daily_spending_cap.saturating_sub(self.tracker.current_day_spent);
        let pending = self.escalation.list_pending(current_time);

        VaultStatusView {
            owner_id: self.owner_id.clone(),
            is_frozen: self.policy.emergency_frozen,
            daily_spending_cap: U128(self.policy.daily_spending_cap),
            daily_spent: U128(self.tracker.current_day_spent),
            remaining_daily_quota: U128(remaining_quota),
            per_tx_cap: U128(self.policy.per_tx_cap),
            total_pending_actions: pending.iter().filter(|a| a.status == ActionStatus::Pending).count(),
            audit_log_count: self.audit_log.len(),
        }
    }

    pub fn get_policy(&self) -> PolicyConfig {
        self.policy.clone()
    }

    pub fn get_pending_actions(&self) -> Vec<PendingAction> {
        self.escalation.list_pending(env::block_timestamp())
    }

    pub fn get_audit_log(&self, limit: Option<usize>) -> Vec<AuditEntry> {
        let max = limit.unwrap_or(50);
        let len = self.audit_log.len();
        if len <= max {
            self.audit_log.clone()
        } else {
            self.audit_log[len - max..].to_vec()
        }
    }

    fn assert_owner(&self) {
        require!(
            env::predecessor_account_id() == self.owner_id,
            "Only contract owner can invoke this method"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn get_context(predecessor: AccountId, _is_init: bool) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        builder
            .current_account_id("vault.near".parse().unwrap())
            .signer_account_id(predecessor.clone())
            .predecessor_account_id(predecessor)
            .block_timestamp(1_700_000_000_000_000_000); // fixed epoch timestamp
        builder
    }

    #[test]
    fn test_initialization() {
        let context = get_context("alice.near".parse().unwrap(), true);
        testing_env!(context.build());

        let contract = AgentGuardContract::new("alice.near".parse().unwrap(), None);
        let status = contract.get_vault_status();

        assert_eq!(status.owner_id, "alice.near".parse::<AccountId>().unwrap());
        assert!(!status.is_frozen);
        assert_eq!(status.daily_spent.0, 0);
    }

    #[test]
    fn test_safe_intent_execution() {
        let context = get_context("agent.near".parse().unwrap(), false);
        testing_env!(context.build());

        let mut contract = AgentGuardContract::new("alice.near".parse().unwrap(), None);

        // Safe micro-swap on intents.near (0.5 NEAR)
        let res = contract.execute_intent(
            "intents.near".parse().unwrap(),
            "execute_intent".to_string(),
            r#"{"token_in":"wrap.near","amount":"500000000000000000000000"}"#.to_string(),
            Some(U128(500_000_000_000_000_000_000_000)), // 0.5 NEAR
        );

        match res {
            PromiseOrValue::Promise(_) => {
                // Verified: Promise dispatched on-chain for the target contract
            }
            PromiseOrValue::Value(v) => panic!("Expected Promise, got Value: {:?}", v),
        }

        let status = contract.get_vault_status();
        assert_eq!(status.daily_spent.0, 500_000_000_000_000_000_000_000);
    }

    #[test]
    fn test_unauthorized_target_rejection() {
        let context = get_context("agent.near".parse().unwrap(), false);
        testing_env!(context.build());

        let mut contract = AgentGuardContract::new("alice.near".parse().unwrap(), None);

        // Agent attempts calling an unwhitelisted suspicious contract
        let res = match contract.execute_intent(
            "malicious-drainer.near".parse().unwrap(),
            "drain_all".to_string(),
            "{}".to_string(),
            Some(U128(1_000_000_000_000_000_000_000_000)),
        ) {
            PromiseOrValue::Value(v) => v,
            PromiseOrValue::Promise(_) => panic!("Expected policy rejection"),
        };

        assert!(!res.success);
        assert_eq!(res.status_code, 403);
        assert!(res.message.contains("not in authorized whitelist"));
    }

    #[test]
    fn test_escalation_on_high_value_transaction() {
        let context = get_context("agent.near".parse().unwrap(), false);
        testing_env!(context.build());

        let mut contract = AgentGuardContract::new("alice.near".parse().unwrap(), None);

        // Attempt spending 5 NEAR (exceeds default 2 NEAR per-tx cap)
        let res = match contract.execute_intent(
            "wrap.near".parse().unwrap(),
            "ft_transfer".to_string(),
            r#"{"receiver_id":"bob.near","amount":"5000000000000000000000000"}"#.to_string(),
            Some(U128(5_000_000_000_000_000_000_000_000)),
        ) {
            PromiseOrValue::Value(v) => v,
            PromiseOrValue::Promise(_) => panic!("Expected escalation value"),
        };

        assert!(!res.success);
        assert_eq!(res.status_code, 202);
        assert!(res.action_id.is_some());

        let pending = contract.get_pending_actions();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].status, ActionStatus::Pending);

        // Now owner approves the action
        let owner_context = get_context("alice.near".parse().unwrap(), false);
        testing_env!(owner_context.build());

        let approved_res = contract.approve_escalated(res.action_id.unwrap());
        match approved_res {
            PromiseOrValue::Promise(_) => {}
            PromiseOrValue::Value(val) => assert!(val),
        }
        let updated_pending = contract.get_pending_actions();
        assert_eq!(updated_pending[0].status, ActionStatus::Approved);
    }

    #[test]
    fn test_daily_quota_exhaustion() {
        let context = get_context("agent.near".parse().unwrap(), false);
        testing_env!(context.build());

        let mut contract = AgentGuardContract::new("alice.near".parse().unwrap(), None);

        // Execute 5 txs of 2 NEAR each (total 10 NEAR = daily cap)
        for _ in 0..5 {
            let res = contract.execute_intent(
                "wrap.near".parse().unwrap(),
                "ft_transfer".to_string(),
                "{}".to_string(),
                Some(U128(2_000_000_000_000_000_000_000_000)),
            );
            assert!(matches!(res, PromiseOrValue::Promise(_)));
        }

        // 6th transaction must be blocked by daily spending quota
        let res = match contract.execute_intent(
            "wrap.near".parse().unwrap(),
            "ft_transfer".to_string(),
            "{}".to_string(),
            Some(U128(1_000_000_000_000_000_000_000_000)),
        ) {
            PromiseOrValue::Value(v) => v,
            PromiseOrValue::Promise(_) => panic!("Expected daily quota block"),
        };

        assert!(!res.success);
        assert_eq!(res.status_code, 429);
        assert!(res.message.contains("Daily spending quota exhausted"));
    }

    #[test]
    fn test_emergency_freeze() {
        let owner_context = get_context("alice.near".parse().unwrap(), false);
        testing_env!(owner_context.build());

        let mut contract = AgentGuardContract::new("alice.near".parse().unwrap(), None);

        // Trigger emergency freeze
        contract.emergency_freeze();
        assert!(contract.get_vault_status().is_frozen);

        // Now agent tries to execute an intent
        let agent_context = get_context("agent.near".parse().unwrap(), false);
        testing_env!(agent_context.build());

        let res = match contract.execute_intent(
            "intents.near".parse().unwrap(),
            "execute_intent".to_string(),
            "{}".to_string(),
            Some(U128(100_000_000_000_000_000_000)),
        ) {
            PromiseOrValue::Value(v) => v,
            PromiseOrValue::Promise(_) => panic!("Expected freeze rejection"),
        };

        assert!(!res.success);
        assert_eq!(res.status_code, 503);
        assert!(res.message.contains("Vault is emergency frozen"));
    }

    #[test]
    fn test_quota_rollback_on_callback_failure() {
        let context = get_context("agent.near".parse().unwrap(), false);
        testing_env!(context.build());

        let mut contract = AgentGuardContract::new("alice.near".parse().unwrap(), None);

        // Safe micro-swap on intents.near (0.5 NEAR)
        let _ = contract.execute_intent(
            "intents.near".parse().unwrap(),
            "execute_intent".to_string(),
            "{}".to_string(),
            Some(U128(500_000_000_000_000_000_000_000)),
        );

        assert_eq!(contract.get_vault_status().daily_spent.0, 500_000_000_000_000_000_000_000);

        // Simulate callback when external execution failed
        let self_context = get_context("vault.near".parse().unwrap(), false);
        testing_env!(self_context.build());

        let callback_res = contract.on_intent_executed(
            "agent.near".parse().unwrap(),
            "intents.near".parse().unwrap(),
            "execute_intent".to_string(),
            U128(500_000_000_000_000_000_000_000),
        );

        assert!(!callback_res.success);
        assert_eq!(callback_res.status_code, 500);

        // Quota has been refunded!
        assert_eq!(contract.get_vault_status().daily_spent.0, 0);
    }
}
