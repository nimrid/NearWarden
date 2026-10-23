/**
 * AgentGuard AI Firewall Engine
 * Pre-flight Prompt-Injection, Jailbreak, and Anomaly Analyzer
 */

export const ThreatLevel = {
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL',
};

const INJECTION_PATTERNS = [
  { pattern: /system\s+override/i, weight: 85, flag: 'SYSTEM_OVERRIDE_DIRECTIVE' },
  { pattern: /ignore\s+(all\s+|any\s+)?(previous|prior|above)\s+(instructions|directives|rules|constraints)/i, weight: 90, flag: 'PROMPT_HIJACK_INSTRUCTION' },
  { pattern: /developer\s+mode\s+(enabled|activated|on)/i, weight: 80, flag: 'DEVELOPER_MODE_JAILBREAK' },
  { pattern: /jailbreak|unrestricted\s+mode|dan\s+mode/i, weight: 85, flag: 'JAILBREAK_TOKEN' },
  { pattern: /you\s+are\s+no\s+longer\s+(bound|restricted|limited)/i, weight: 75, flag: 'ROLEPLAY_ESCAPE_ATTEMPT' },
  { pattern: /bypass\s+(firewall|policy|guardrail|security|limits)/i, weight: 80, flag: 'GUARDRAIL_BYPASS_ATTEMPT' },
  { pattern: /base64\s*:\s*[A-Za-z0-9+/=]{20,}/i, weight: 65, flag: 'OBFUSCATED_PAYLOAD_DETECTED' },
  { pattern: /<\s*script\b|javascript\s*:\s*/i, weight: 70, flag: 'INLINE_SCRIPT_INJECTION' },
];

const DRAINAGE_PATTERNS = [
  { pattern: /drain\s+(all|entire|total|wallet|treasury|funds|balance)/i, weight: 95, flag: 'DRAIN_TREASURY_COMMAND' },
  { pattern: /transfer\s+(all|everything|max|entire|total)\s+(near|usdc|usdt|tokens|balance)/i, weight: 90, flag: 'MAX_TRANSFER_COMMAND' },
  { pattern: /empty\s+(the\s+)?(wallet|vault|account)/i, weight: 85, flag: 'EMPTY_VAULT_COMMAND' },
  { pattern: /liquidate\s+(all|everything|entire)/i, weight: 75, flag: 'LIQUIDATION_ANOMALY' },
];

export class AgentFirewall {
  constructor(options = {}) {
    this.strictMode = options.strictMode ?? true;
    this.customRules = options.customRules || [];
    this.blockedDestinations = new Set(options.blockedDestinations || [
      'attacker.near',
      'drainer.near',
      'exploit.near',
      'phishing.near',
    ]);
  }

  /**
   * Evaluates an agent's intended prompt, tool-call, and parameters before on-chain dispatch.
   * @param {Object} input
   * @param {string} input.prompt - The natural language intent or tool invocation prompt
   * @param {string} input.targetContract - The target smart contract on NEAR
   * @param {string} input.methodName - Contract method to invoke
   * @param {Object|string} input.args - Parameters passed to the method
   * @param {string|number} [input.amount] - Token amount in yoctoNEAR or lowest denomination
   * @returns {Object} AnalysisReport
   */
  inspect({ prompt = '', targetContract = '', methodName = '', args = {}, amount = 0 }) {
    let score = 0;
    const detectedFlags = [];
    const promptStr = String(prompt);
    const argsStr = typeof args === 'string' ? args : JSON.stringify(args);
    const combinedText = `${promptStr} ${argsStr}`;

    // 1. Check prompt injection markers
    for (const rule of INJECTION_PATTERNS) {
      if (rule.pattern.test(combinedText)) {
        score = Math.max(score, rule.weight);
        detectedFlags.push(rule.flag);
      }
    }

    // 2. Check treasury drainage markers
    for (const rule of DRAINAGE_PATTERNS) {
      if (rule.pattern.test(combinedText)) {
        score = Math.max(score, rule.weight);
        detectedFlags.push(rule.flag);
      }
    }

    // 3. Check blocked destination blacklist
    if (this.blockedDestinations.has(targetContract)) {
      score = Math.max(score, 99);
      detectedFlags.push(`BLOCKED_DESTINATION_${targetContract.toUpperCase()}`);
    }

    // Also inspect recipient inside args if specified
    const recipientMatch = argsStr.match(/(?:receiver_id|recipient|to)\s*["':]\s*["']?([a-zA-Z0-9._-]+)["']?/i);
    if (recipientMatch && recipientMatch[1]) {
      const recipient = recipientMatch[1];
      if (this.blockedDestinations.has(recipient)) {
        score = Math.max(score, 99);
        detectedFlags.push(`BLOCKED_RECIPIENT_${recipient.toUpperCase()}`);
      }
    }

    // 4. Determine Threat Level & Action
    let threatLevel = ThreatLevel.LOW;
    let action = 'APPROVE';

    if (score >= 80) {
      threatLevel = ThreatLevel.CRITICAL;
      action = 'BLOCK';
    } else if (score >= 60) {
      threatLevel = ThreatLevel.HIGH;
      action = 'ESCALATE';
    } else if (score >= 30) {
      threatLevel = ThreatLevel.MEDIUM;
      action = 'CONFIRM';
    }

    const isAllowed = action === 'APPROVE';

    return {
      isAllowed,
      threatScore: score,
      threatLevel,
      action,
      detectedFlags,
      targetContract,
      methodName,
      timestamp: Date.now(),
      summary: isAllowed
        ? `Clean intent: Threat score ${score}/100.`
        : `Intervention triggered: Threat score ${score}/100. Flags: ${detectedFlags.join(', ')}`,
    };
  }

  addBlockedDestination(destination) {
    this.blockedDestinations.add(destination);
  }

  removeBlockedDestination(destination) {
    this.blockedDestinations.delete(destination);
  }
}
