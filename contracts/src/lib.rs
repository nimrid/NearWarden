pub mod escalation;
pub mod policy;

use escalation::{ActionStatus, EscalationQueue, PendingAction, ACTION_EXPIRY_NS};
use policy::{FirewallAttestation, PolicyConfig, PolicyViolation, SpendingTracker};

use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::json_types::U128;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::store::LookupSet;
use near_sdk::{env, near, require, AccountId, Gas, NearToken, PanicOnDefault, Promise, PromiseOrValue, PublicKey};

pub const GAS_FOR_INTENT: Gas = Gas::from_tgas(30);
pub const GAS_FOR_CALLBACK: Gas = Gas::from_tgas(10);
pub const GAS_FOR_MPC_SIGN: Gas = Gas::from_tgas(250);
pub const GAS_FOR_MPC_CALLBACK: Gas = Gas::from_tgas(30);
pub const ATTACHED_DEPOSIT_FOR_MPC: NearToken = NearToken::from_yoctonear(50_000_000_000_000_000_000_000); // 0.05 NEAR
/// Maximum number of audit log entries retained on-chain.
/// When exceeded, the oldest entry is evicted (ring-buffer behaviour).
pub const MAX_AUDIT_ENTRIES: usize = 1_000;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct SignRequestArgs {
    pub request: SignRequestPayload,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct SignRequestPayload {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
}

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
    pub used_attestations: LookupSet<[u8; 32]>,
}

#[near]
impl AgentGuardContract {
    #[init]
    pub fn new(owner_id: AccountId, policy: Option<PolicyConfig>) -> Self {
        require!(!env::state_exists(), "Contract already initialized");
        let initial_policy = policy.unwrap_or_default();
        require!(
            initial_policy.firewall_public_key.is_some(),
            "AgentGuard: firewall_public_key required at initialization - AI Firewall attestation is mandatory"
        );
        let current_time = env::block_timestamp();

        Self {
            owner_id,
            policy: initial_policy,
            tracker: SpendingTracker::new(current_time),
            escalation: EscalationQueue::new(),
            audit_log: Vec::new(),
            used_attestations: LookupSet::new(b"u"),
        }
    }

    /// Verifies AI Firewall attestation with cryptographic Ed25519 signature & Replay-Protection Nullifiers
    fn verify_firewall_attestation(
        &mut self,
        target: &AccountId,
        method: &str,
        args: &str,
        amount_raw: u128,
        current_time_ns: u64,
        attestation: &Option<FirewallAttestation>,
    ) -> u8 {
        if let Some(ref firewall_pk) = self.policy.firewall_public_key {
            let att = attestation
                .as_ref()
                .expect("AgentGuard: Missing required AI Firewall attestation");

            // 1. Verify threat score threshold
            let max_score = self.policy.max_threat_score.unwrap_or(75);
            require!(
                att.threat_score <= max_score,
                format!("AgentGuard: Threat score {} exceeds maximum allowed {}", att.threat_score, max_score)
            );

            // 2. Verify timestamp freshness (prevent expired or future attestations)
            let max_age_ms = self.policy.max_attestation_age_ms.unwrap_or(300_000);
            let now_ms = current_time_ns / 1_000_000;
            require!(
                now_ms >= att.timestamp_ms && (now_ms - att.timestamp_ms) <= max_age_ms,
                "AgentGuard: Firewall attestation expired or timestamp in future"
            );

            // 3. Compute canonical message digest over intent parameters and unique nonce
            let digest_input = format!("{}:{}:{}:{}:{}:{}", target, method, args, amount_raw, att.timestamp_ms, att.nonce);
            let digest_vec = env::sha256(digest_input.as_bytes());
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&digest_vec);

            // 4. Replay Protection: Ensure this attestation nullifier has not already been consumed
            require!(
                !self.used_attestations.contains(&digest),
                "AgentGuard: Attestation replay detected - digest already consumed"
            );

            // 5. Verify Ed25519 signature
            let sig_bytes = hex::decode(&att.signature).expect("AgentGuard: Invalid hex in attestation signature");
            require!(sig_bytes.len() == 64, "AgentGuard: Signature must be 64 bytes");
            let mut sig_arr = [0u8; 64];
            sig_arr.copy_from_slice(&sig_bytes);

            let pk_bytes = firewall_pk.as_bytes();
            require!(pk_bytes[0] == 0 && pk_bytes.len() == 33, "AgentGuard: Firewall key must be Ed25519");
            let mut pk_arr = [0u8; 32];
            pk_arr.copy_from_slice(&pk_bytes[1..33]);

            require!(
                env::ed25519_verify(&sig_arr, &digest_vec, &pk_arr),
                "AgentGuard: Invalid firewall attestation signature"
            );

            // 6. Consume attestation nullifier
            self.used_attestations.insert(digest);

            att.threat_score
        } else {
            env::panic_str(
                "AgentGuard: Firewall attestation enforcement not configured - firewall_public_key must be anchored",
            )
        }
    }

    fn assert_authorized_caller(&self) {
        let caller = env::predecessor_account_id();
        require!(
            caller == self.owner_id || self.policy.authorized_callers.contains(&caller),
            "AgentGuard: Caller is not an authorized caller"
        );
    }

    fn verify_supervisor_passkey(
        &self,
        action_id: u64,
        target: &AccountId,
        method: &str,
        args: &str,
        deposit: u128,
        passkey_signature: &Option<String>,
    ) -> bool {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        use p256::ecdsa::{Signature, VerifyingKey};

        if let Some(ref pk_hex) = self.policy.supervisor_passkey_public_key {
            let sig_hex = passkey_signature
                .as_ref()
                .expect("AgentGuard: Passkey biometric approval required by vault security policy");
            require!(!sig_hex.is_empty(), "AgentGuard: Empty passkey signature");

            let pk_bytes = hex::decode(pk_hex).expect("AgentGuard: Invalid supervisor passkey public key hex");
            let verifying_key = VerifyingKey::from_sec1_bytes(&pk_bytes)
                .expect("AgentGuard: Invalid supervisor passkey public key");

            let canonical = format!(
                "AgentGuard:ApproveAction:{}:{}:{}:{}:{}",
                action_id, target, method, args, deposit
            );
            let digest = env::sha256(canonical.as_bytes());
            let digest2 = env::sha256(&digest);

            let sig_bytes = hex::decode(sig_hex).expect("AgentGuard: Invalid hex in passkey signature");
            let signature = Signature::from_der(&sig_bytes)
                .expect("AgentGuard: Invalid supervisor passkey signature encoding");

            require!(
                verifying_key.verify_prehash(&digest2, &signature).is_ok(),
                "AgentGuard: Invalid supervisor passkey signature"
            );
            true
        } else if self.policy.supervisor_passkey_hash.is_some() {
            env::panic_str(
                "AgentGuard: Supervisor passkey public key not anchored - call set_supervisor_passkey_public_key before approving",
            )
        } else {
            passkey_signature.is_some()
        }
    }

    /// Checks if an attestation digest has already been consumed (view method)
    pub fn is_attestation_consumed(&self, digest_hex: String) -> bool {
        if let Ok(bytes) = hex::decode(&digest_hex) {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                return self.used_attestations.contains(&arr);
            }
        }
        false
    }

    /// Primary execution gate for Autonomous AI Agents holding Function Call Keys.
    /// Evaluates requested action against on-chain policy constraints and spending rules.
    pub fn execute_intent(
        &mut self,
        target: AccountId,
        method: String,
        args: String,
        amount: Option<U128>,
        attestation: Option<FirewallAttestation>,
    ) -> PromiseOrValue<ExecutionResult> {
        self.assert_authorized_caller();
        let caller = env::predecessor_account_id();
        let current_time = env::block_timestamp();
        let amount_raw: u128 = amount.map(|a| a.0).unwrap_or(0);

        // 1. Cryptographic AI Firewall Verification with Replay Nullifiers
        let verified_threat_score = self.verify_firewall_attestation(
            &target,
            &method,
            &args,
            amount_raw,
            current_time,
            &attestation,
        );

        // 2. Pre-validate against spending policy and limits
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
                    threat_score: verified_threat_score,
                };
                self.push_audit(entry);

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
                self.push_audit(entry);

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
                self.push_audit(entry);

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

            self.push_audit(AuditEntry {
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

    /// Requests a multi-chain signature from the NEAR MPC network (v1.signer)
    /// under AgentGuard policy engine and AI Firewall attestation constraints.
    #[payable]
    pub fn request_chain_signature(
        &mut self,
        payload: [u8; 32],
        path: String,
        key_version: Option<u32>,
        foreign_chain: Option<String>,
        estimated_amount: Option<U128>,
        attestation: Option<FirewallAttestation>,
    ) -> PromiseOrValue<ExecutionResult> {
        self.assert_authorized_caller();
        let caller = env::predecessor_account_id();
        let current_time = env::block_timestamp();
        let amount_raw: u128 = estimated_amount.map(|a| a.0).unwrap_or(0);
        let chain = foreign_chain.unwrap_or_else(|| "base".to_string());
        let version = key_version.unwrap_or(0);
        let payload_hex = hex::encode(payload);

        let mpc_contract: AccountId = self.policy.mpc_contract_id.clone().unwrap_or_else(|| {
            "v1.signer-prod.testnet".parse().unwrap()
        });

        // 1. Verify Firewall Attestation
        let verified_threat_score = self.verify_firewall_attestation(
            &mpc_contract,
            &format!("sign_multichain:{}", chain),
            &format!("{}:{}", path, payload_hex),
            amount_raw,
            current_time,
            &attestation,
        );

        // 2. Validate against spending tracker & policies
        match self.tracker.validate_and_record(
            &self.policy,
            &mpc_contract,
            &"sign".to_string(),
            amount_raw,
            current_time,
        ) {
            Ok(()) => {
                let entry = AuditEntry {
                    timestamp_ns: current_time,
                    caller: caller.clone(),
                    target: mpc_contract.clone(),
                    method: format!("sign_multichain:{}", chain),
                    amount: U128(amount_raw),
                    status: "CHAIN_SIGNATURE_REQUESTED".to_string(),
                    threat_score: verified_threat_score,
                };
                self.push_audit(entry);

                let sign_args = SignRequestArgs {
                    request: SignRequestPayload {
                        payload,
                        path: path.clone(),
                        key_version: version,
                    },
                };
                let sign_args_json = near_sdk::serde_json::to_vec(&sign_args).expect("Failed to serialize sign args");

                let promise = Promise::new(mpc_contract.clone())
                    .function_call(
                        "sign".to_string(),
                        sign_args_json,
                        ATTACHED_DEPOSIT_FOR_MPC,
                        GAS_FOR_MPC_SIGN,
                    )
                    .then(
                        Self::ext(env::current_account_id())
                            .with_static_gas(GAS_FOR_MPC_CALLBACK)
                            .on_chain_signature_completed(caller, mpc_contract, chain, path, U128(amount_raw))
                    );

                PromiseOrValue::Promise(promise)
            }
            Err(PolicyViolation::ExceedsPerTxCap { amount, cap }) => {
                let action_id = self.escalation.enqueue(
                    mpc_contract.clone(),
                    format!("sign_multichain:{}", chain),
                    format!("path:{},payload:{}", path, payload_hex),
                    amount_raw,
                    current_time,
                );

                let entry = AuditEntry {
                    timestamp_ns: current_time,
                    caller: caller.clone(),
                    target: mpc_contract,
                    method: format!("sign_multichain:{}", chain),
                    amount: U128(amount_raw),
                    status: format!("ESCALATED_ACTION_{}", action_id),
                    threat_score: 65,
                };
                self.push_audit(entry);

                PromiseOrValue::Value(ExecutionResult {
                    success: false,
                    status_code: 202,
                    message: format!(
                        "Estimated amount {} exceeds autonomous per-tx limit of {}. Escalated to pending action #{}",
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
                        (format!("Target '{}' is not in authorized whitelist for chain signature.", t), 403, 85)
                    }
                    PolicyViolation::MethodNotAllowed(m) => {
                        (format!("Method '{}' is not an authorized agent method.", m), 403, 80)
                    }
                    PolicyViolation::ExceedsDailyQuota { spent_today, attempted, cap } => {
                        (format!("Daily quota exhausted: spent {} + attempted {} exceeds cap {}.", spent_today, attempted, cap), 429, 70)
                    }
                    PolicyViolation::VelocityLimitExceeded { calls_in_window, max_allowed } => {
                        (format!("Velocity throttle: {} calls in window exceeds limit of {}.", calls_in_window, max_allowed), 429, 75)
                    }
                    PolicyViolation::ExceedsPerTxCap { .. } => unreachable!(),
                };

                let entry = AuditEntry {
                    timestamp_ns: current_time,
                    caller,
                    target: mpc_contract,
                    method: format!("sign_multichain:{}", chain),
                    amount: U128(amount_raw),
                    status: format!("BLOCKED: {}", error_msg),
                    threat_score,
                };
                self.push_audit(entry);

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

    /// Callback for request_chain_signature: validates completion and refunds quota if MPC failed
    #[private]
    pub fn on_chain_signature_completed(
        &mut self,
        caller: AccountId,
        mpc_contract: AccountId,
        chain: String,
        path: String,
        amount: U128,
    ) -> ExecutionResult {
        let success = env::promise_results_count() > 0 && env::promise_result_checked(0, 1024 * 1024).is_ok();

        if !success {
            self.tracker.rollback_spend(amount.0);

            self.push_audit(AuditEntry {
                timestamp_ns: env::block_timestamp(),
                caller,
                target: mpc_contract,
                method: format!("sign_multichain:{}", chain),
                amount,
                status: "CHAIN_SIGNATURE_FAILED_QUOTA_REVERTED".to_string(),
                threat_score: 30,
            });

            ExecutionResult {
                success: false,
                status_code: 502,
                message: format!("NEAR MPC threshold signing failed for chain {} (path: {}); quota refunded", chain, path),
                action_id: None,
                threat_score: 30,
            }
        } else {
            self.push_audit(AuditEntry {
                timestamp_ns: env::block_timestamp(),
                caller,
                target: mpc_contract,
                method: format!("sign_multichain:{}", chain),
                amount,
                status: "CHAIN_SIGNATURE_COMPLETED".to_string(),
                threat_score: 0,
            });

            ExecutionResult {
                success: true,
                status_code: 200,
                message: format!("Chain signature successfully generated by NEAR MPC for chain {} (path: {})", chain, path),
                action_id: None,
                threat_score: 0,
            }
        }
    }

    pub fn emergency_freeze(&mut self) {
        self.assert_owner();
        self.policy.emergency_frozen = true;

        self.push_audit(AuditEntry {
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

        self.push_audit(AuditEntry {
            timestamp_ns: env::block_timestamp(),
            caller: env::predecessor_account_id(),
            target: env::current_account_id(),
            method: "emergency_unfreeze".to_string(),
            amount: U128(0),
            status: "EMERGENCY_FREEZE_LIFTED".to_string(),
            threat_score: 0,
        });
    }

    /// Approve an escalated transaction (Human-in-the-Loop) and execute its payload on-chain.
    /// Supports optional Biometric WebAuthn Passkey signature for hardware-level supervisor verification.
    pub fn approve_escalated(&mut self, action_id: u64, passkey_signature: Option<String>) -> PromiseOrValue<bool> {
        self.assert_owner();
        let current_time = env::block_timestamp();

        // Persist expiry before reading action status so expired actions
        // fail the Pending check below rather than slipping through.
        self.escalation.prune_expired(current_time);

        let (target0, method0, args0, deposit0, created_at_ns) = {
            let action = self.escalation.get_action(action_id).expect("Action not found");
            require!(action.status == ActionStatus::Pending, "Action is not pending");
            (
                action.target.clone(),
                action.method.clone(),
                action.args.clone(),
                action.deposit,
                action.created_at_ns,
            )
        };

        require!(
            current_time <= created_at_ns.saturating_add(ACTION_EXPIRY_NS),
            "AgentGuard: Escalated action expired"
        );

        let has_passkey = self.verify_supervisor_passkey(
            action_id,
            &target0,
            &method0,
            &args0,
            deposit0,
            &passkey_signature,
        );

        if let Err(err) = self.tracker.validate_escalated_and_record(
            &self.policy,
            &target0,
            &method0,
            deposit0,
            current_time,
        ) {
            match err {
                PolicyViolation::VaultFrozen => {
                    env::panic_str("Vault is emergency frozen. All agent operations are halted.")
                }
                PolicyViolation::TargetNotAllowed(t) => env::panic_str(&format!(
                    "AgentGuard: Escalated target '{}' is not in authorized whitelist.",
                    t
                )),
                PolicyViolation::MethodNotAllowed(m) => env::panic_str(&format!(
                    "AgentGuard: Escalated method '{}' is not an authorized agent method.",
                    m
                )),
                PolicyViolation::ExceedsDailyQuota { spent_today, attempted, cap } => {
                    env::panic_str(&format!(
                        "Daily spending quota exhausted. Spent today: {}, Attempted: {}, Cap: {}",
                        spent_today, attempted, cap
                    ))
                }
                PolicyViolation::VelocityLimitExceeded { calls_in_window, max_allowed } => {
                    env::panic_str(&format!(
                        "Velocity limit tripped: {} calls in past hour exceeds max of {}.",
                        calls_in_window, max_allowed
                    ))
                }
                PolicyViolation::ExceedsPerTxCap { .. } => unreachable!(),
            }
        }

        let action = self.escalation.get_action_mut(action_id).expect("Action not found");
        action.status = ActionStatus::Approved;

        let target = action.target.clone();
        let method = action.method.clone();
        let args = action.args.clone().into_bytes();
        let deposit = action.deposit;

        let status = if has_passkey {
            format!("MANUALLY_APPROVED_VIA_PASSKEY_AND_DISPATCHED_ACTION_{}", action_id)
        } else {
            format!("MANUALLY_APPROVED_AND_DISPATCHED_ACTION_{}", action_id)
        };

        self.push_audit(AuditEntry {
            timestamp_ns: env::block_timestamp(),
            caller: env::predecessor_account_id(),
            target: target.clone(),
            method: method.clone(),
            amount: U128(deposit),
            status,
            threat_score: 5,
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

        let deposit = self.escalation.get_action(action_id).map(|a| a.deposit);
        if !success {
            if let Some(amount) = deposit {
                self.tracker.rollback_spend(amount);
            }
        }
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
        // Extract fields before mutating status to avoid double-borrow
        let (target, method, deposit) = {
            let action = self.escalation.get_action(action_id).expect("Action not found");
            require!(action.status == ActionStatus::Pending, "Action is not pending");
            (action.target.clone(), action.method.clone(), action.deposit)
        };
        // Now it's safe to mutate
        self.escalation.get_action_mut(action_id).unwrap().status = ActionStatus::Rejected;

        self.push_audit(AuditEntry {
            timestamp_ns: env::block_timestamp(),
            caller: env::predecessor_account_id(),
            target,
            method,
            amount: U128(deposit),
            status: format!("MANUALLY_REJECTED_ACTION_{}", action_id),
            threat_score: 30,
        });

        true
    }

    /// Update security policy parameters
    pub fn update_policy(&mut self, new_policy: PolicyConfig) {
        self.assert_owner();
        require!(
            new_policy.firewall_public_key.is_some(),
            "AgentGuard: firewall_public_key required - policy update cannot disable AI Firewall attestation"
        );
        self.policy = new_policy;
    }

    /// Replaces the allowlist of accounts authorized to execute intents.
    pub fn set_authorized_callers(&mut self, callers: Vec<AccountId>) {
        self.assert_owner();
        self.policy.authorized_callers = callers;
    }

    /// Anchors or rotates the AI Firewall Public Key (derived from OutLayer Intel TDX TEE enclave)
    pub fn set_firewall_public_key(&mut self, public_key: Option<PublicKey>) {
        self.assert_owner();
        require!(
            public_key.is_some(),
            "AgentGuard: firewall_public_key cannot be cleared - attestation is mandatory"
        );
        self.policy.firewall_public_key = public_key;

        self.push_audit(AuditEntry {
            timestamp_ns: env::block_timestamp(),
            caller: env::predecessor_account_id(),
            target: env::current_account_id(),
            method: "set_firewall_public_key".to_string(),
            amount: U128(0),
            status: "FIREWALL_PUBLIC_KEY_ANCHORED_IN_TEE".to_string(),
            threat_score: 0,
        });
    }

    /// Anchors the supervisor P-256 public key used to verify escalation approvals.
    /// `public_key_hex` is the hex-encoded uncompressed SEC1 point (65 bytes).
    pub fn set_supervisor_passkey_public_key(&mut self, public_key_hex: Option<String>) {
        self.assert_owner();
        if let Some(ref pk_hex) = public_key_hex {
            let pk_bytes =
                hex::decode(pk_hex).expect("AgentGuard: Invalid supervisor passkey public key hex");
            let _ = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pk_bytes)
                .expect("AgentGuard: Invalid supervisor passkey public key");
            self.policy.supervisor_passkey_hash = Some(hex::encode(env::sha256(&pk_bytes)));
        }
        self.policy.supervisor_passkey_public_key = public_key_hex;

        self.push_audit(AuditEntry {
            timestamp_ns: env::block_timestamp(),
            caller: env::predecessor_account_id(),
            target: env::current_account_id(),
            method: "set_supervisor_passkey_public_key".to_string(),
            amount: U128(0),
            status: "SUPERVISOR_PASSKEY_PUBLIC_KEY_ANCHORED".to_string(),
            threat_score: 0,
        });
    }

    /// Anchors or rotates the Supervisor Biometric WebAuthn Passkey credential hash (Touch ID / Face ID / YubiKey)
    pub fn set_supervisor_passkey(&mut self, passkey_hash: Option<String>) {
        self.assert_owner();
        let hash_display = passkey_hash.clone().unwrap_or_else(|| "NONE".to_string());
        self.policy.supervisor_passkey_hash = passkey_hash;

        self.push_audit(AuditEntry {
            timestamp_ns: env::block_timestamp(),
            caller: env::predecessor_account_id(),
            target: env::current_account_id(),
            method: "set_supervisor_passkey".to_string(),
            amount: U128(0),
            status: format!("SUPERVISOR_PASSKEY_BIOMETRIC_ANCHORED: {}", hash_display),
            threat_score: 0,
        });
    }

    // --- VIEW METHODS ---

    pub fn get_vault_status(&mut self) -> VaultStatusView {
        let current_time = env::block_timestamp();
        let remaining_quota = self.policy.daily_spending_cap.saturating_sub(self.tracker.current_day_spent);
        // list_pending persists Expired status in-place for accurate counts
        let all_actions = self.escalation.list_pending(current_time);

        VaultStatusView {
            owner_id: self.owner_id.clone(),
            is_frozen: self.policy.emergency_frozen,
            daily_spending_cap: U128(self.policy.daily_spending_cap),
            daily_spent: U128(self.tracker.current_day_spent),
            remaining_daily_quota: U128(remaining_quota),
            per_tx_cap: U128(self.policy.per_tx_cap),
            total_pending_actions: all_actions.iter().filter(|a| a.status == ActionStatus::Pending).count(),
            audit_log_count: self.audit_log.len(),
        }
    }

    pub fn get_policy(&self) -> PolicyConfig {
        self.policy.clone()
    }

    pub fn get_pending_actions(&mut self) -> Vec<PendingAction> {
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

    /// Appends an audit entry, evicting the oldest when the log reaches MAX_AUDIT_ENTRIES.
    fn push_audit(&mut self, entry: AuditEntry) {
        if self.audit_log.len() >= MAX_AUDIT_ENTRIES {
            self.audit_log.remove(0);
        }
        self.audit_log.push(entry);
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

    fn test_policy() -> PolicyConfig {
        let mut policy = PolicyConfig::default();
        policy.firewall_public_key =
            Some("ed25519:GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB".parse().unwrap());
        policy.authorized_callers = vec!["agent.near".parse().unwrap()];
        policy
    }

    fn att(target: &str, method: &str, args: &str, amount: u128) -> FirewallAttestation {
        use ed25519_dalek::{Signer, SigningKey};
        use std::sync::atomic::{AtomicU64, Ordering};
        static NONCE: AtomicU64 = AtomicU64::new(1_000);
        let nonce = NONCE.fetch_add(1, Ordering::SeqCst);
        let timestamp_ms = env::block_timestamp() / 1_000_000;
        let digest_input = format!("{}:{}:{}:{}:{}:{}", target, method, args, amount, timestamp_ms, nonce);
        let digest = env::sha256(digest_input.as_bytes());
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let signature = signing_key.sign(&digest);
        FirewallAttestation {
            threat_score: 10,
            timestamp_ms,
            nonce,
            signature: hex::encode(signature.to_bytes()),
        }
    }

    fn test_contract() -> AgentGuardContract {
        AgentGuardContract::new("alice.near".parse().unwrap(), Some(test_policy()))
    }

    fn passkey_keypair() -> (p256::ecdsa::SigningKey, String) {
        use p256::ecdsa::SigningKey;
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let sec1 = sk.verifying_key().to_encoded_point(false);
        (sk, hex::encode(sec1.as_bytes()))
    }

    fn sign_passkey(
        sk: &p256::ecdsa::SigningKey,
        action_id: u64,
        target: &str,
        method: &str,
        args: &str,
        deposit: u128,
    ) -> String {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use sha2::{Digest, Sha256};
        let canonical = format!(
            "AgentGuard:ApproveAction:{}:{}:{}:{}:{}",
            action_id, target, method, args, deposit
        );
        let digest = Sha256::digest(canonical.as_bytes());
        let digest2 = Sha256::digest(digest);
        let sig: p256::ecdsa::Signature = sk.sign_prehash(&digest2).unwrap();
        hex::encode(sig.to_der().as_bytes())
    }

    fn escalate_five_near(contract: &mut AgentGuardContract) -> u64 {
        let args = r#"{"receiver_id":"bob.near","amount":"5000000000000000000000000"}"#;
        let res = match contract.execute_intent(
            "wrap.near".parse().unwrap(),
            "ft_transfer".to_string(),
            args.to_string(),
            Some(U128(5_000_000_000_000_000_000_000_000)),
            Some(att("wrap.near", "ft_transfer", args, 5_000_000_000_000_000_000_000_000)),
        ) {
            PromiseOrValue::Value(v) => v,
            PromiseOrValue::Promise(_) => panic!("Expected escalation value"),
        };
        res.action_id.unwrap()
    }

    #[test]
    fn test_initialization() {
        let context = get_context("alice.near".parse().unwrap(), true);
        testing_env!(context.build());

        let mut contract = test_contract();
        let status = contract.get_vault_status();

        assert_eq!(status.owner_id, "alice.near".parse::<AccountId>().unwrap());
        assert!(!status.is_frozen);
        assert_eq!(status.daily_spent.0, 0);
    }

    #[test]
    fn test_serde_policy() {
        #[allow(dead_code)]
        #[derive(near_sdk::serde::Deserialize, Debug)]
        #[serde(crate = "near_sdk::serde")]
        struct NewArgs {
            owner_id: AccountId,
            policy: Option<PolicyConfig>,
        }
        let json_num = r#"{"owner_id":"guard.longdata4360.testnet","policy":{"daily_spending_cap":10000000000000000000000000,"per_tx_cap":2000000000000000000000000,"allowed_targets":["wrap.testnet","intents.testnet","v1.signer-prod.testnet"],"allowed_methods":["ft_transfer","ft_transfer_call","execute_intent","storage_deposit","near_deposit","sign"],"max_velocity_per_hour":20,"emergency_frozen":false,"firewall_public_key":"ed25519:TYyTf51QAY7P6p35vRTEU3GungTDsHeKdKM2R2DrbF9","max_attestation_age_ms":300000,"max_threat_score":75,"supervisor_passkey_hash":null,"mpc_contract_id":"v1.signer-prod.testnet","authorized_callers":["agent.longdata4360.testnet"],"supervisor_passkey_public_key":null}}"#;
        let res_num: Result<NewArgs, _> = near_sdk::serde_json::from_str(json_num);
        assert!(res_num.is_ok(), "NewArgs failed: {:?}", res_num.err());
    }

    #[test]
    fn test_safe_intent_execution() {
        let context = get_context("agent.near".parse().unwrap(), false);
        testing_env!(context.build());

        let mut contract = test_contract();

        // Safe micro-swap on intents.near (0.5 NEAR)
        let args = r#"{"token_in":"wrap.near","amount":"500000000000000000000000"}"#;
        let res = contract.execute_intent(
            "intents.near".parse().unwrap(),
            "execute_intent".to_string(),
            args.to_string(),
            Some(U128(500_000_000_000_000_000_000_000)), // 0.5 NEAR
            Some(att("intents.near", "execute_intent", args, 500_000_000_000_000_000_000_000)),
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

        let mut contract = test_contract();

        // Agent attempts calling an unwhitelisted suspicious contract
        let res = match contract.execute_intent(
            "malicious-drainer.near".parse().unwrap(),
            "drain_all".to_string(),
            "{}".to_string(),
            Some(U128(1_000_000_000_000_000_000_000_000)),
            Some(att("malicious-drainer.near", "drain_all", "{}", 1_000_000_000_000_000_000_000_000)),
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

        let mut contract = test_contract();

        // Attempt spending 5 NEAR (exceeds default 2 NEAR per-tx cap)
        let args = r#"{"receiver_id":"bob.near","amount":"5000000000000000000000000"}"#;
        let res = match contract.execute_intent(
            "wrap.near".parse().unwrap(),
            "ft_transfer".to_string(),
            args.to_string(),
            Some(U128(5_000_000_000_000_000_000_000_000)),
            Some(att("wrap.near", "ft_transfer", args, 5_000_000_000_000_000_000_000_000)),
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

        let approved_res = contract.approve_escalated(res.action_id.unwrap(), None);
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

        let mut contract = test_contract();

        // Execute 5 txs of 2 NEAR each (total 10 NEAR = daily cap)
        for _ in 0..5 {
            let res = contract.execute_intent(
                "wrap.near".parse().unwrap(),
                "ft_transfer".to_string(),
                "{}".to_string(),
                Some(U128(2_000_000_000_000_000_000_000_000)),
                Some(att("wrap.near", "ft_transfer", "{}", 2_000_000_000_000_000_000_000_000)),
            );
            assert!(matches!(res, PromiseOrValue::Promise(_)));
        }

        // 6th transaction must be blocked by daily spending quota
        let res = match contract.execute_intent(
            "wrap.near".parse().unwrap(),
            "ft_transfer".to_string(),
            "{}".to_string(),
            Some(U128(1_000_000_000_000_000_000_000_000)),
            Some(att("wrap.near", "ft_transfer", "{}", 1_000_000_000_000_000_000_000_000)),
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

        let mut contract = test_contract();

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
            Some(att("intents.near", "execute_intent", "{}", 100_000_000_000_000_000_000)),
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

        let mut contract = test_contract();

        // Safe micro-swap on intents.near (0.5 NEAR)
        let _ = contract.execute_intent(
            "intents.near".parse().unwrap(),
            "execute_intent".to_string(),
            "{}".to_string(),
            Some(U128(500_000_000_000_000_000_000_000)),
            Some(att("intents.near", "execute_intent", "{}", 500_000_000_000_000_000_000_000)),
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

    #[test]
    #[should_panic(expected = "AgentGuard: Missing required AI Firewall attestation")]
    fn test_firewall_bypass_rejected_when_attestation_missing() {
        let context = get_context("agent.near".parse().unwrap(), false);
        testing_env!(context.build());

        // Configure policy requiring an AI Firewall public key
        let mut policy = PolicyConfig::default();
        policy.firewall_public_key = Some("ed25519:6E8sCci9badyRkXb3JoRpAxTMkx2qkAZCSnVq6Qup2x5".parse().unwrap());
        policy.authorized_callers = vec!["agent.near".parse().unwrap()];

        let mut contract = AgentGuardContract::new("alice.near".parse().unwrap(), Some(policy));

        // Attacker attempts calling execute_intent directly without AI firewall attestation
        let _ = contract.execute_intent(
            "wrap.near".parse().unwrap(),
            "ft_transfer".to_string(),
            "{}".to_string(),
            Some(U128(500_000_000_000_000_000_000_000)),
            None, // <--- Missing attestation triggers on-chain rejection!
        );
    }

    #[test]
    #[should_panic(expected = "AgentGuard: Invalid firewall attestation signature")]
    fn test_firewall_attestation_tampered_signature_rejected() {
        let context = get_context("agent.near".parse().unwrap(), false);
        testing_env!(context.build());

        let mut policy = PolicyConfig::default();
        policy.firewall_public_key = Some("ed25519:6E8sCci9badyRkXb3JoRpAxTMkx2qkAZCSnVq6Qup2x5".parse().unwrap());
        policy.authorized_callers = vec!["agent.near".parse().unwrap()];

        let mut contract = AgentGuardContract::new("alice.near".parse().unwrap(), Some(policy));

        // Attacker supplies a fresh timestamp but forged 64-byte signature
        let forged_sig = hex::encode([1u8; 64]);
        let forged_attestation = FirewallAttestation {
            threat_score: 10,
            timestamp_ms: env::block_timestamp() / 1_000_000,
            nonce: 0,
            signature: forged_sig,
        };

        let _ = contract.execute_intent(
            "wrap.near".parse().unwrap(),
            "ft_transfer".to_string(),
            "{}".to_string(),
            Some(U128(500_000_000_000_000_000_000_000)),
            Some(forged_attestation),
        );
    }

    #[test]
    #[should_panic(expected = "AgentGuard: Attestation replay detected - digest already consumed")]
    fn test_firewall_attestation_replay_rejected() {
        let mut context = get_context("agent.near".parse().unwrap(), false);
        // Set block timestamp to exactly 1000 ms (1_000_000_000 ns) to match signed vector
        context.block_timestamp(1_000_000_000);
        testing_env!(context.build());

        let mut policy = PolicyConfig::default();
        policy.firewall_public_key = Some("ed25519:GEfAEhGDvjJaiGAHQxRbtc5VDdPLccxivpdeWbL7NE39".parse().unwrap());
        policy.authorized_callers = vec!["agent.near".parse().unwrap()];

        let mut contract = AgentGuardContract::new("alice.near".parse().unwrap(), Some(policy));

        let valid_attestation = FirewallAttestation {
            threat_score: 15,
            timestamp_ms: 1000,
            nonce: 42,
            signature: "def0ac1f21ce5971445b2b7f9bc855bd44cbc68ea9cfd8aff7b7520e1f87a3aab2741d0c045f5789a91199873b7a95661a2435611ea27b2b6411d8f5b5aa290e".to_string(),
        };

        // First execution succeeds (or creates transfer promise)
        let first_res = contract.execute_intent(
            "wrap.near".parse().unwrap(),
            "ft_transfer".to_string(),
            "{}".to_string(),
            Some(U128(500_000_000_000_000_000_000_000)),
            Some(valid_attestation.clone()),
        );
        assert!(matches!(first_res, PromiseOrValue::Promise(_)));

        // Verify digest is marked consumed via view method
        let digest_input = "wrap.near:ft_transfer:{}:500000000000000000000000:1000:42";
        let digest_hex = hex::encode(env::sha256(digest_input.as_bytes()));
        assert!(contract.is_attestation_consumed(digest_hex));

        // Replay attack: Attacker submits the exact same attestation again -> MUST PANIC with replay detected
        let _ = contract.execute_intent(
            "wrap.near".parse().unwrap(),
            "ft_transfer".to_string(),
            "{}".to_string(),
            Some(U128(500_000_000_000_000_000_000_000)),
            Some(valid_attestation),
        );
    }

    #[test]
    fn test_anchor_firewall_public_key_via_tee() {
        let owner_context = get_context("alice.near".parse().unwrap(), false);
        testing_env!(owner_context.build());

        let mut contract = test_contract();
        assert!(contract.get_policy().firewall_public_key.is_some());

        // Rotate to OutLayer Intel TDX TEE public key
        let tee_pk: PublicKey = "ed25519:GEfAEhGDvjJaiGAHQxRbtc5VDdPLccxivpdeWbL7NE39".parse().unwrap();
        contract.set_firewall_public_key(Some(tee_pk.clone()));

        assert_eq!(contract.get_policy().firewall_public_key, Some(tee_pk));
        assert_eq!(contract.audit_log.last().unwrap().status, "FIREWALL_PUBLIC_KEY_ANCHORED_IN_TEE");
    }

    #[test]
    fn test_anchor_supervisor_passkey() {
        let owner_context = get_context("alice.near".parse().unwrap(), false);
        testing_env!(owner_context.build());

        let mut contract = test_contract();
        assert!(contract.get_policy().supervisor_passkey_hash.is_none());

        let passkey_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string();
        contract.set_supervisor_passkey(Some(passkey_hash.clone()));

        assert_eq!(contract.get_policy().supervisor_passkey_hash, Some(passkey_hash.clone()));
        assert!(contract.audit_log.last().unwrap().status.contains("SUPERVISOR_PASSKEY_BIOMETRIC_ANCHORED"));
    }

    #[test]
    #[should_panic(expected = "AgentGuard: Passkey biometric approval required by vault security policy")]
    fn test_passkey_enforcement_blocks_unsigned_approval() {
        let context = get_context("agent.near".parse().unwrap(), false);
        testing_env!(context.build());

        let mut contract = test_contract();
        
        // Anchor supervisor passkey requirement
        let owner_context = get_context("alice.near".parse().unwrap(), false);
        testing_env!(owner_context.build());
        let (_sk, pub_hex) = passkey_keypair();
        contract.set_supervisor_passkey_public_key(Some(pub_hex));

        // Trigger escalation
        let agent_context = get_context("agent.near".parse().unwrap(), false);
        testing_env!(agent_context.build());
        let action_id = escalate_five_near(&mut contract);

        // Attempt approval without passkey signature -> MUST PANIC
        testing_env!(owner_context.build());
        let _ = contract.approve_escalated(action_id, None);
    }

    #[test]
    fn test_passkey_approval_succeeds_with_biometric_signature() {
        let context = get_context("agent.near".parse().unwrap(), false);
        testing_env!(context.build());

        let mut contract = test_contract();
        
        // Anchor supervisor passkey requirement
        let owner_context = get_context("alice.near".parse().unwrap(), false);
        testing_env!(owner_context.build());
        let (sk, pub_hex) = passkey_keypair();
        contract.set_supervisor_passkey_public_key(Some(pub_hex));

        // Trigger escalation
        let agent_context = get_context("agent.near".parse().unwrap(), false);
        testing_env!(agent_context.build());
        let action_id = escalate_five_near(&mut contract);

        // Approve with valid biometric passkey signature
        testing_env!(owner_context.build());
        let args = r#"{"receiver_id":"bob.near","amount":"5000000000000000000000000"}"#;
        let sig = sign_passkey(&sk, action_id, "wrap.near", "ft_transfer", args, 5_000_000_000_000_000_000_000_000);
        let approved_res = contract.approve_escalated(action_id, Some(sig));
        match approved_res {
            PromiseOrValue::Promise(_) => {}
            PromiseOrValue::Value(val) => assert!(val),
        }

        let pending = contract.get_pending_actions();
        assert_eq!(pending[0].status, ActionStatus::Approved);
        assert!(contract.audit_log.last().unwrap().status.contains("MANUALLY_APPROVED_VIA_PASSKEY"));
    }

    #[test]
    fn test_chain_signature_request_dispatches_mpc_promise() {
        let context = get_context("agent.near".parse().unwrap(), false);
        testing_env!(context.build());

        let mut contract = test_contract();

        let payload = [7u8; 32];
        let res = contract.request_chain_signature(
            payload,
            "ethereum,1".to_string(),
            Some(0),
            Some("base".to_string()),
            Some(U128(500_000_000_000_000_000_000_000)), // 0.5 NEAR (within 2 NEAR cap)
            Some(att("v1.signer-prod.testnet", "sign_multichain:base", &format!("ethereum,1:{}", hex::encode(payload)), 500_000_000_000_000_000_000_000)),
        );

        match res {
            PromiseOrValue::Promise(_) => {
                // Expected cross-contract promise to v1.signer
            }
            PromiseOrValue::Value(_) => panic!("Expected cross-contract promise to MPC contract"),
        }

        assert_eq!(contract.audit_log.len(), 1);
        assert_eq!(contract.audit_log[0].status, "CHAIN_SIGNATURE_REQUESTED");
        assert_eq!(contract.audit_log[0].method, "sign_multichain:base");
    }

    #[test]
    fn test_chain_signature_escalates_on_high_value_foreign_transaction() {
        let context = get_context("agent.near".parse().unwrap(), false);
        testing_env!(context.build());

        let mut contract = test_contract();

        let payload = [9u8; 32];
        let res = match contract.request_chain_signature(
            payload,
            "base,1".to_string(),
            Some(0),
            Some("base".to_string()),
            Some(U128(5_000_000_000_000_000_000_000_000)), // 5 NEAR (exceeds 2 NEAR cap)
            Some(att("v1.signer-prod.testnet", "sign_multichain:base", &format!("base,1:{}", hex::encode(payload)), 5_000_000_000_000_000_000_000_000)),
        ) {
            PromiseOrValue::Value(v) => v,
            PromiseOrValue::Promise(_) => panic!("Expected escalation value, got promise"),
        };

        assert_eq!(res.status_code, 202);
        assert!(res.action_id.is_some());
        assert!(res.message.contains("Escalated to pending action"));

        let pending = contract.get_pending_actions();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].method, "sign_multichain:base");
    }

    #[test]
    fn test_chain_signature_blocked_when_vault_frozen() {
        let owner_context = get_context("alice.near".parse().unwrap(), false);
        testing_env!(owner_context.build());

        let mut contract = test_contract();
        contract.emergency_freeze();

        let agent_context = get_context("agent.near".parse().unwrap(), false);
        testing_env!(agent_context.build());

        let payload = [1u8; 32];
        let res = match contract.request_chain_signature(
            payload,
            "ethereum,1".to_string(),
            None,
            Some("ethereum".to_string()),
            Some(U128(100)),
            Some(att("v1.signer-prod.testnet", "sign_multichain:ethereum", &format!("ethereum,1:{}", hex::encode(payload)), 100)),
        ) {
            PromiseOrValue::Value(v) => v,
            PromiseOrValue::Promise(_) => panic!("Expected value, got promise"),
        };

        assert_eq!(res.status_code, 503);
        assert!(res.message.contains("frozen"));
    }

    #[test]
    #[should_panic(expected = "AgentGuard: firewall_public_key required")]
    fn test_init_rejects_missing_firewall_key() {
        let context = get_context("alice.near".parse().unwrap(), true);
        testing_env!(context.build());
        let _ = AgentGuardContract::new("alice.near".parse().unwrap(), None);
    }

    #[test]
    #[should_panic(expected = "AgentGuard: Caller is not an authorized caller")]
    fn test_unauthorized_caller_rejected() {
        let context = get_context("mallory.near".parse().unwrap(), false);
        testing_env!(context.build());
        let mut contract = test_contract();
        let _ = contract.execute_intent(
            "wrap.near".parse().unwrap(),
            "ft_transfer".to_string(),
            "{}".to_string(),
            Some(U128(1_000_000_000_000_000_000_000_000)),
            Some(att("wrap.near", "ft_transfer", "{}", 1_000_000_000_000_000_000_000_000)),
        );
    }

    #[test]
    fn test_passkey_valid_signature_approves_and_records_spend() {
        let context = get_context("agent.near".parse().unwrap(), false);
        testing_env!(context.build());
        let mut contract = test_contract();
        let (sk, pub_hex) = passkey_keypair();
        let owner_context = get_context("alice.near".parse().unwrap(), false);
        testing_env!(owner_context.build());
        contract.set_supervisor_passkey_public_key(Some(pub_hex));
        let agent_context = get_context("agent.near".parse().unwrap(), false);
        testing_env!(agent_context.build());
        let action_id = escalate_five_near(&mut contract);
        testing_env!(owner_context.build());
        let args = r#"{"receiver_id":"bob.near","amount":"5000000000000000000000000"}"#;
        let sig = sign_passkey(&sk, action_id, "wrap.near", "ft_transfer", args, 5_000_000_000_000_000_000_000_000);
        let res = contract.approve_escalated(action_id, Some(sig));
        assert!(matches!(res, PromiseOrValue::Promise(_)));
        assert_eq!(contract.get_vault_status().daily_spent.0, 5_000_000_000_000_000_000_000_000);
    }

    #[test]
    #[should_panic(expected = "AgentGuard: Invalid supervisor passkey signature")]
    fn test_passkey_tampered_signature_rejected() {
        let context = get_context("agent.near".parse().unwrap(), false);
        testing_env!(context.build());
        let mut contract = test_contract();
        let (sk, pub_hex) = passkey_keypair();
        let owner_context = get_context("alice.near".parse().unwrap(), false);
        testing_env!(owner_context.build());
        contract.set_supervisor_passkey_public_key(Some(pub_hex));
        let agent_context = get_context("agent.near".parse().unwrap(), false);
        testing_env!(agent_context.build());
        let action_id = escalate_five_near(&mut contract);
        testing_env!(owner_context.build());
        let args = r#"{"receiver_id":"bob.near","amount":"5000000000000000000000000"}"#;
        // Sign for a different action id than the one being approved.
        let sig = sign_passkey(&sk, action_id + 99, "wrap.near", "ft_transfer", args, 5_000_000_000_000_000_000_000_000);
        let _ = contract.approve_escalated(action_id, Some(sig));
    }

    #[test]
    #[should_panic(expected = "emergency frozen")]
    fn test_escalated_approval_rejected_when_frozen() {
        let context = get_context("agent.near".parse().unwrap(), false);
        testing_env!(context.build());
        let mut contract = test_contract();
        let action_id = escalate_five_near(&mut contract);
        let owner_context = get_context("alice.near".parse().unwrap(), false);
        testing_env!(owner_context.build());
        contract.emergency_freeze();
        let _ = contract.approve_escalated(action_id, None);
    }

    #[test]
    #[should_panic(expected = "Action is not pending")]
    fn test_escalated_approval_rejected_after_expiry() {
        let context = get_context("agent.near".parse().unwrap(), false);
        testing_env!(context.build());
        let mut contract = test_contract();
        let action_id = escalate_five_near(&mut contract);
        let mut owner_context = get_context("alice.near".parse().unwrap(), false);
        // Advance time by 25 hours (> ACTION_EXPIRY_NS = 24 hours)
        owner_context.block_timestamp(1_700_000_000_000_000_000 + 90_000_000_000_000);
        testing_env!(owner_context.build());
        let _ = contract.approve_escalated(action_id, None);
    }

    #[test]
    #[should_panic(expected = "Daily spending quota exhausted")]
    fn test_escalated_approval_enforces_daily_quota() {
        let context = get_context("agent.near".parse().unwrap(), false);
        testing_env!(context.build());
        let mut policy = test_policy();
        policy.daily_spending_cap = 6_000_000_000_000_000_000_000_000;
        let mut contract = AgentGuardContract::new("alice.near".parse().unwrap(), Some(policy));
        let first = escalate_five_near(&mut contract);
        let owner_context = get_context("alice.near".parse().unwrap(), false);
        testing_env!(owner_context.build());
        let _ = contract.approve_escalated(first, None);
        let agent_context = get_context("agent.near".parse().unwrap(), false);
        testing_env!(agent_context.build());
        let second = escalate_five_near(&mut contract);
        testing_env!(owner_context.build());
        let _ = contract.approve_escalated(second, None);
    }
}

