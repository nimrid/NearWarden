/**
 * AgentGuard Policy Engine (Client-side mirror and simulator)
 * Evaluates spending velocity, quotas, and whitelist constraints.
 */

export class PolicyEngine {
  constructor(config = {}) {
    this.dailySpendingCap = BigInt(config.dailySpendingCap || '10000000000000000000000000'); // 10 NEAR
    this.perTxCap = BigInt(config.perTxCap || '2000000000000000000000000'); // 2 NEAR
    this.allowedTargets = new Set(config.allowedTargets || [
      'wrap.near',
      'intents.near',
      'v2.ref-finance.near',
      'usdt.tether-token.near',
    ]);
    this.allowedMethods = new Set(config.allowedMethods || [
      'ft_transfer',
      'ft_transfer_call',
      'execute_intent',
      'storage_deposit',
      'near_deposit',
      'swap',
    ]);
    this.maxVelocityPerHour = config.maxVelocityPerHour || 20;
    this.emergencyFrozen = !!config.emergencyFrozen;

    // Runtime state
    this.dailySpent = 0n;
    this.lastResetTime = Date.now();
    this.callHistory = [];
  }

  /**
   * Pre-evaluates an action against policy rules.
   * @param {Object} action
   * @param {string} action.target
   * @param {string} action.method
   * @param {string|bigint|number} action.amount - in yoctoNEAR
   * @param {number} [action.timestamp]
   * @returns {Object} { allowed: boolean, statusCode: number, reason: string, requiresEscalation: boolean }
   */
  evaluate({ target, method, amount = '0', timestamp = Date.now() }) {
    const amountBn = BigInt(amount ?? 0);

    // 1. Emergency Freeze check
    if (this.emergencyFrozen) {
      return {
        allowed: false,
        statusCode: 503,
        reason: 'Vault is emergency frozen. All autonomous actions suspended.',
        requiresEscalation: false,
      };
    }

    // 2. Target Contract Whitelist check
    if (this.allowedTargets.size > 0 && !this.allowedTargets.has(target)) {
      return {
        allowed: false,
        statusCode: 403,
        reason: `Target contract '${target}' is not in authorized whitelist.`,
        requiresEscalation: false,
      };
    }

    // 3. Method Whitelist check
    if (this.allowedMethods.size > 0 && !this.allowedMethods.has(method)) {
      return {
        allowed: false,
        statusCode: 403,
        reason: `Method '${method}' is not an authorized agent method.`,
        requiresEscalation: false,
      };
    }

    // 4. Per-Transaction Limit check
    if (amountBn > this.perTxCap) {
      return {
        allowed: false,
        statusCode: 202,
        reason: `Amount ${amountBn} yoctoNEAR exceeds per-transaction limit of ${this.perTxCap}. Requires human approval.`,
        requiresEscalation: true,
      };
    }

    // 5. Rolling 24-hour Quota reset check
    const ONE_DAY_MS = 86_400_000;
    if (timestamp - this.lastResetTime >= ONE_DAY_MS) {
      this.dailySpent = 0n;
      this.lastResetTime = timestamp;
    }

    // 6. Daily Quota Check
    const projectedDailySpend = this.dailySpent + amountBn;
    if (projectedDailySpend > this.dailySpendingCap) {
      return {
        allowed: false,
        statusCode: 429,
        reason: `Daily quota exceeded. Spent: ${this.dailySpent}, Attempted: ${amountBn}, Cap: ${this.dailySpendingCap}.`,
        requiresEscalation: false,
      };
    }

    // 7. Velocity Limit check (rolling 60 minutes)
    const ONE_HOUR_MS = 3_600_000;
    this.callHistory = this.callHistory.filter((ts) => ts >= timestamp - ONE_HOUR_MS);

    if (this.callHistory.length >= this.maxVelocityPerHour) {
      return {
        allowed: false,
        statusCode: 429,
        reason: `Velocity limit exceeded: ${this.callHistory.length} calls in past hour (max: ${this.maxVelocityPerHour}).`,
        requiresEscalation: false,
      };
    }

    // Passed validation -> Record call and spend
    this.dailySpent = projectedDailySpend;
    this.callHistory.push(timestamp);

    return {
      allowed: true,
      statusCode: 200,
      reason: 'Compliant with on-chain spending policy.',
      requiresEscalation: false,
    };
  }

  freeze() {
    this.emergencyFrozen = true;
  }

  unfreeze() {
    this.emergencyFrozen = false;
  }

  getStatus() {
    const remaining = this.dailySpendingCap > this.dailySpent ? this.dailySpendingCap - this.dailySpent : 0n;
    return {
      isFrozen: this.emergencyFrozen,
      dailySpendingCap: this.dailySpendingCap.toString(),
      dailySpent: this.dailySpent.toString(),
      remainingQuota: remaining.toString(),
      perTxCap: this.perTxCap.toString(),
      recentCallCount: this.callHistory.length,
      maxVelocityPerHour: this.maxVelocityPerHour,
    };
  }
}
