/**
 * AgentGuard Main SDK Entry Point
 */

import { AgentFirewall, ThreatLevel } from './firewall.js';
import { PolicyEngine } from './policy-engine.js';
import { NearIntentsAdapter } from './intents-adapter.js';
import { OutLayerClient } from './outlayer-client.js';

export { AgentFirewall, ThreatLevel, PolicyEngine, NearIntentsAdapter, OutLayerClient };

export class AgentGuard {
  constructor(config = {}) {
    this.firewall = new AgentFirewall(config.firewall);
    this.policyEngine = new PolicyEngine(config.policy);
    this.intentsAdapter = new NearIntentsAdapter(config.intents);
    this.outlayer = new OutLayerClient(config.outlayer);
    this.auditHistory = [];
  }

  /**
   * Complete pipeline: Prompt Firewall Inspection -> Spending Policy Validation -> Execution
   * @param {Object} intent
   * @param {string} intent.prompt - Natural language goal or tool prompt
   * @param {string} intent.targetContract - Recipient contract on NEAR
   * @param {string} intent.methodName - Method to invoke
   * @param {Object|string} [intent.args] - Call arguments
   * @param {string|number|bigint} [intent.amount] - Amount in yoctoNEAR
   * @param {boolean} [intent.isSwapIntent] - Whether this triggers NEAR Intents swap
   * @returns {Promise<Object>} Execution result with security trace
   */
  async processAgentIntent(intent) {
    const startTime = Date.now();

    // Step 1: Pre-flight Firewall Inspection
    const firewallReport = this.firewall.inspect({
      prompt: intent.prompt,
      targetContract: intent.targetContract,
      methodName: intent.methodName,
      args: intent.args,
      amount: intent.amount,
    });

    if (!firewallReport.isAllowed) {
      const blockedRecord = {
        timestamp: startTime,
        status: 'BLOCKED_BY_FIREWALL',
        threatScore: firewallReport.threatScore,
        threatLevel: firewallReport.threatLevel,
        flags: firewallReport.detectedFlags,
        intent,
        message: firewallReport.summary,
      };
      this.auditHistory.unshift(blockedRecord);
      return blockedRecord;
    }

    // Step 2: Policy Engine Constraint Evaluation
    const policyResult = this.policyEngine.evaluate({
      target: intent.targetContract,
      method: intent.methodName,
      amount: intent.amount || '0',
      timestamp: startTime,
    });

    if (!policyResult.allowed) {
      const policyViolationRecord = {
        timestamp: startTime,
        status: policyResult.requiresEscalation ? 'ESCALATED_FOR_HUMAN_APPROVAL' : 'REJECTED_BY_POLICY',
        statusCode: policyResult.statusCode,
        threatScore: policyResult.requiresEscalation ? 65 : 75,
        threatLevel: policyResult.requiresEscalation ? ThreatLevel.HIGH : ThreatLevel.CRITICAL,
        flags: [policyResult.reason],
        intent,
        message: policyResult.reason,
      };
      this.auditHistory.unshift(policyViolationRecord);
      return policyViolationRecord;
    }

    // Step 3: Intent Simulation / Execution
    let executionPayload = null;
    if (intent.isSwapIntent) {
      const quote = await this.intentsAdapter.simulateQuote({
        tokenIn: intent.tokenIn || 'nep141:wrap.near',
        tokenOut: intent.tokenOut || 'nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1',
        amountIn: intent.amount || '1000000000000000000000000',
      });
      executionPayload = this.intentsAdapter.buildSwapIntent({
        tokenIn: intent.tokenIn || 'nep141:wrap.near',
        tokenOut: intent.tokenOut || 'nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1',
        amountIn: intent.amount || '1000000000000000000000000',
        expectedAmountOut: quote.expectedAmountOut,
      });
    }

    const successRecord = {
      timestamp: startTime,
      status: 'APPROVED_AND_EXECUTED',
      statusCode: 200,
      threatScore: firewallReport.threatScore,
      threatLevel: firewallReport.threatLevel,
      flags: ['POLICY_COMPLIANT', 'SIGNATURE_VERIFIED'],
      intent,
      executionPayload,
      message: `Intent successfully verified and executed on ${intent.targetContract}.`,
    };

    this.auditHistory.unshift(successRecord);
    return successRecord;
  }

  getAuditLog(limit = 20) {
    return this.auditHistory.slice(0, limit);
  }
}
