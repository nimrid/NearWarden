use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::AccountId;

pub const ONE_DAY_NS: u64 = 86_400_000_000_000; // 24 hours in nanoseconds
pub const ONE_HOUR_NS: u64 = 3_600_000_000_000; // 1 hour in nanoseconds

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
            ],
            allowed_methods: vec![
                "ft_transfer".to_string(),
                "ft_transfer_call".to_string(),
                "execute_intent".to_string(),
                "storage_deposit".to_string(),
                "near_deposit".to_string(),
            ],
            max_velocity_per_hour: 20,
            emergency_frozen: false,
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
}
