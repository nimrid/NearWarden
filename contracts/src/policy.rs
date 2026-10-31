use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{AccountId, PublicKey};

pub const ONE_DAY_NS: u64 = 86_400_000_000_000; // 24 hours in nanoseconds
pub const ONE_HOUR_NS: u64 = 3_600_000_000_000; // 1 hour in nanoseconds

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(crate = "near_sdk::serde")]
pub struct FirewallAttestation {
    pub threat_score: u8,
    pub timestamp_ms: u64,
    #[serde(default)]
    pub nonce: u64,
    pub signature: String, // hex-encoded 64-byte Ed25519 signature
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(crate = "near_sdk::serde")]
pub struct PolicyConfig {
    /// Maximum total spend allowed in rolling 24-hour window (in yoctoNEAR)
    pub daily_spending_cap: u128,
    /// Maximum spend for a single automated transaction (in yoctoNEAR)
    pub per_tx_cap: u128,
    /// Whitelist of contracts the agent is authorized to interact with
    pub allowed_targets: Vec<AccountId>,
    /// Whitelist of method names the agent can invoke
    pub allowed_methods: Vec<String>,
    /// Velocity throttle: Maximum allowed transactions per rolling hour
    pub max_velocity_per_hour: u32,
    /// Emergency kill-switch: if true, all agent interactions are blocked
    pub emergency_frozen: bool,
    /// Optional Ed25519 public key of the AI Firewall signer (enforces cryptographic attestation)
    #[serde(default)]
    pub firewall_public_key: Option<PublicKey>,
    /// Maximum allowed age of firewall attestation in milliseconds (default: 300,000 = 5 mins)
    #[serde(default)]
    pub max_attestation_age_ms: Option<u64>,
    /// Maximum threat score accepted by the contract (default: 75)
    #[serde(default)]
    pub max_threat_score: Option<u8>,
    /// Optional biometric supervisor WebAuthn Passkey credential hash
    #[serde(default)]
    pub supervisor_passkey_hash: Option<String>,
    /// Optional NEAR MPC Signer Contract ID (default: "v1.signer-prod.testnet")
    #[serde(default)]
    pub mpc_contract_id: Option<AccountId>,
    /// Accounts authorized to call execute_intent / request_chain_signature.
    /// The owner is always authorized. Empty means no agent is authorized.
    #[serde(default)]
    pub authorized_callers: Vec<AccountId>,
    /// Hex-encoded uncompressed SEC1 P-256 public key (65 bytes) of the
    /// supervisor passkey. Required for cryptographic approval verification.
    #[serde(default)]
    pub supervisor_passkey_public_key: Option<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            daily_spending_cap: 10_000_000_000_000_000_000_000_000, // 10 NEAR
            per_tx_cap: 2_000_000_000_000_000_000_000_000,          // 2 NEAR
            allowed_targets: vec![
                "wrap.near".parse().unwrap(),
                "intents.near".parse().unwrap(),
                "v2.ref-finance.near".parse().unwrap(),
                "v1.signer-prod.testnet".parse().unwrap(),
                "v1.signer".parse().unwrap(),
            ],
            allowed_methods: vec![
                "ft_transfer".to_string(),
                "ft_transfer_call".to_string(),
                "execute_intent".to_string(),
                "storage_deposit".to_string(),
                "near_deposit".to_string(),
                "sign".to_string(),
                "request_chain_signature".to_string(),
            ],
            max_velocity_per_hour: 20,
            emergency_frozen: false,
            firewall_public_key: None,
            max_attestation_age_ms: Some(300_000),
            max_threat_score: Some(75),
            supervisor_passkey_hash: None,
            mpc_contract_id: Some("v1.signer-prod.testnet".parse().unwrap()),
            authorized_callers: Vec::new(),
            supervisor_passkey_public_key: None,
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug, Default)]
#[serde(crate = "near_sdk::serde")]
pub struct SpendingTracker {
    pub current_day_spent: u128,
    pub last_reset_timestamp_ns: u64,
    pub call_timestamps_ns: Vec<u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(crate = "near_sdk::serde")]
pub enum PolicyViolation {
    VaultFrozen,
    TargetNotAllowed(String),
    MethodNotAllowed(String),
    ExceedsPerTxCap { amount: u128, cap: u128 },
    ExceedsDailyQuota { spent_today: u128, attempted: u128, cap: u128 },
    VelocityLimitExceeded { calls_in_window: u32, max_allowed: u32 },
}

impl SpendingTracker {
    pub fn new(current_time_ns: u64) -> Self {
        Self {
            current_day_spent: 0,
            last_reset_timestamp_ns: current_time_ns,
            call_timestamps_ns: Vec::new(),
        }
    }

    /// Verifies policy constraints against an attempted action and updates state if approved
    pub fn validate_and_record(
        &mut self,
        policy: &PolicyConfig,
        target: &AccountId,
        method: &str,
        amount: u128,
        current_time_ns: u64,
    ) -> Result<(), PolicyViolation> {
        // 1. Emergency Freeze check
        if policy.emergency_frozen {
            return Err(PolicyViolation::VaultFrozen);
        }

        // 2. Target Contract Whitelist check
        if !policy.allowed_targets.is_empty() && !policy.allowed_targets.contains(target) {
            return Err(PolicyViolation::TargetNotAllowed(target.to_string()));
        }

        // 3. Method Whitelist check
        if !policy.allowed_methods.is_empty() && !policy.allowed_methods.iter().any(|m| m == method) {
            return Err(PolicyViolation::MethodNotAllowed(method.to_string()));
        }

        // 4. Per-Transaction Limit check
        if amount > policy.per_tx_cap {
            return Err(PolicyViolation::ExceedsPerTxCap {
                amount,
                cap: policy.per_tx_cap,
            });
        }

        // 5. Rolling 24h Daily Reset check
        if current_time_ns >= self.last_reset_timestamp_ns.saturating_add(ONE_DAY_NS) {
            self.current_day_spent = 0;
            self.last_reset_timestamp_ns = current_time_ns;
        }

        // 6. Daily Quota Check
        let projected_daily_spend = self.current_day_spent.saturating_add(amount);
        if projected_daily_spend > policy.daily_spending_cap {
            return Err(PolicyViolation::ExceedsDailyQuota {
                spent_today: self.current_day_spent,
                attempted: amount,
                cap: policy.daily_spending_cap,
            });
        }

        // 7. Velocity Throttle (prune calls older than 1 hour)
        let cutoff_time = current_time_ns.saturating_sub(ONE_HOUR_NS);
        self.call_timestamps_ns.retain(|&ts| ts >= cutoff_time);

        if self.call_timestamps_ns.len() as u32 >= policy.max_velocity_per_hour {
            return Err(PolicyViolation::VelocityLimitExceeded {
                calls_in_window: self.call_timestamps_ns.len() as u32,
                max_allowed: policy.max_velocity_per_hour,
            });
        }

        // Commit spending & record call timestamp
        self.current_day_spent = projected_daily_spend;
        self.call_timestamps_ns.push(current_time_ns);

        Ok(())
    }

    /// Re-validates an escalated action at approval time and records its spend.
    /// Per-tx cap is intentionally skipped: exceeding it is why the action was
    /// escalated. Freeze, whitelists, daily quota, and velocity still apply.
    pub fn validate_escalated_and_record(
        &mut self,
        policy: &PolicyConfig,
        target: &AccountId,
        method: &str,
        amount: u128,
        current_time_ns: u64,
    ) -> Result<(), PolicyViolation> {
        if policy.emergency_frozen {
            return Err(PolicyViolation::VaultFrozen);
        }
        if !policy.allowed_targets.is_empty() && !policy.allowed_targets.contains(target) {
            return Err(PolicyViolation::TargetNotAllowed(target.to_string()));
        }
        let is_chain_signature = method.starts_with("sign_multichain:");
        if !is_chain_signature
            && !policy.allowed_methods.is_empty()
            && !policy.allowed_methods.iter().any(|m| m == method)
        {
            return Err(PolicyViolation::MethodNotAllowed(method.to_string()));
        }
        if current_time_ns >= self.last_reset_timestamp_ns.saturating_add(ONE_DAY_NS) {
            self.current_day_spent = 0;
            self.last_reset_timestamp_ns = current_time_ns;
        }
        let projected_daily_spend = self.current_day_spent.saturating_add(amount);
        if projected_daily_spend > policy.daily_spending_cap {
            return Err(PolicyViolation::ExceedsDailyQuota {
                spent_today: self.current_day_spent,
                attempted: amount,
                cap: policy.daily_spending_cap,
            });
        }
        let cutoff_time = current_time_ns.saturating_sub(ONE_HOUR_NS);
        self.call_timestamps_ns.retain(|&ts| ts >= cutoff_time);
        if self.call_timestamps_ns.len() as u32 >= policy.max_velocity_per_hour {
            return Err(PolicyViolation::VelocityLimitExceeded {
                calls_in_window: self.call_timestamps_ns.len() as u32,
                max_allowed: policy.max_velocity_per_hour,
            });
        }
        self.current_day_spent = projected_daily_spend;
        self.call_timestamps_ns.push(current_time_ns);
        Ok(())
    }

    /// Reverts a recorded spend if the cross-contract execution fails
    pub fn rollback_spend(&mut self, amount: u128) {
        self.current_day_spent = self.current_day_spent.saturating_sub(amount);
        if !self.call_timestamps_ns.is_empty() {
            self.call_timestamps_ns.pop();
        }
    }
}
