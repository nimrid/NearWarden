use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::AccountId;

pub const ACTION_EXPIRY_NS: u64 = 86_400_000_000_000; // 24 hours expiry for escalation requests

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(crate = "near_sdk::serde")]
pub enum ActionStatus {
    Pending,
    Approved,
    Rejected,
    Executed,
    Expired,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct PendingAction {
    pub action_id: u64,
    pub target: AccountId,
    pub method: String,
    pub args: String, // JSON payload string
    pub deposit: u128,
    pub created_at_ns: u64,
    pub status: ActionStatus,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug, Default)]
#[serde(crate = "near_sdk::serde")]
pub struct EscalationQueue {
    pub actions: Vec<PendingAction>,
    pub next_action_id: u64,
}

impl EscalationQueue {
    pub fn new() -> Self {
        Self {
            actions: Vec::new(),
            next_action_id: 1,
        }
    }

    pub fn enqueue(
        &mut self,
        target: AccountId,
        method: String,
        args: String,
        deposit: u128,
        created_at_ns: u64,
    ) -> u64 {
        let id = self.next_action_id;
        self.next_action_id += 1;

        self.actions.push(PendingAction {
            action_id: id,
            target,
            method,
            args,
            deposit,
            created_at_ns,
            status: ActionStatus::Pending,
        });

        id
    }

    pub fn get_action_mut(&mut self, action_id: u64) -> Option<&mut PendingAction> {
        self.actions.iter_mut().find(|a| a.action_id == action_id)
    }

    pub fn get_action(&self, action_id: u64) -> Option<&PendingAction> {
        self.actions.iter().find(|a| a.action_id == action_id)
    }

    pub fn list_pending(&self, current_time_ns: u64) -> Vec<PendingAction> {
        self.actions
            .iter()
            .map(|a| {
                let mut action = a.clone();
                if action.status == ActionStatus::Pending
                    && current_time_ns > action.created_at_ns.saturating_add(ACTION_EXPIRY_NS)
                {
                    action.status = ActionStatus::Expired;
                }
                action
            })
            .collect()
    }
}
