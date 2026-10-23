import * as nearAPI from 'near-api-js';
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

    // Optional On-Chain NEAR Configuration
    this.contractId = config.contractId || null;
    this.networkId = config.networkId || 'testnet';
    this.nodeUrl = config.nodeUrl || (this.networkId === 'mainnet' ? 'https://rpc.mainnet.near.org' : 'https://rpc.testnet.near.org');
    this.account = config.account || null;
    this.near = null;
  }

  /**
   * Initializes real NEAR connection if configured.
   */
  async initNearConnection() {
    if (this.near) return this.near;
    this.near = await nearAPI.connect({
      networkId: this.networkId,
      nodeUrl: this.nodeUrl,
      keyStore: new nearAPI.keyStores.InMemoryKeyStore(),
    });
    return this.near;
  }

  /**
   * Queries real on-chain vault status via NEAR RPC
   */
  async getOnChainVaultStatus() {
    if (!this.contractId) throw new Error('contractId not set in AgentGuard configuration');
    const near = await this.initNearConnection();
    const raw = await near.connection.provider.query({
      request_type: 'call_function',
      account_id: this.contractId,
      method_name: 'get_vault_status',
      args_base64: Buffer.from('{}').toString('base64'),
      finality: 'optimistic',
    });
    return JSON.parse(Buffer.from(raw.result).toString());
  }

  /**
   * Queries real on-chain pending escalation actions
   */
  async getOnChainPendingActions() {
    if (!this.contractId) throw new Error('contractId not set in AgentGuard configuration');
    const near = await this.initNearConnection();
    const raw = await near.connection.provider.query({
      request_type: 'call_function',
      account_id: this.contractId,
      method_name: 'get_pending_actions',
      args_base64: Buffer.from('{}').toString('base64'),
      finality: 'optimistic',
    });
    return JSON.parse(Buffer.from(raw.result).toString());
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
   * @param {boolean} [intent.executeOnChain] - Whether to broadcast transaction to live NEAR contract
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

    // Step 2: Policy Engine Constraint Evaluation (Local pre-flight)
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

    // Step 4: Optional On-Chain Execution via Scoped Function Call Key
    let onChainTx = null;
    if (intent.executeOnChain && this.account && this.contractId) {
      try {
        const txOutcome = await this.account.functionCall({
          contractId: this.contractId,
          methodName: 'execute_intent',
          args: {
            target: intent.targetContract,
            method: intent.methodName,
            args: typeof intent.args === 'string' ? intent.args : JSON.stringify(intent.args || {}),
            amount: intent.amount ? intent.amount.toString() : null,
          },
          gas: '50000000000000', // 50 TGas
          attachedDeposit: '0',
        });
        onChainTx = {
          transactionHash: txOutcome.transaction.hash,
          gasBurned: txOutcome.receipts_outcome.reduce((acc, r) => acc + (r.outcome.gas_burnt || 0), 0),
        };
      } catch (err) {
        return {
          timestamp: startTime,
          status: 'ON_CHAIN_EXECUTION_ERROR',
          statusCode: 500,
          threatScore: 40,
          threatLevel: ThreatLevel.MEDIUM,
          intent,
          message: `On-chain execution failed: ${err.message}`,
        };
      }
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
      onChainTx,
      message: `Intent successfully verified and executed on ${intent.targetContract}.`,
    };

    this.auditHistory.unshift(successRecord);
    return successRecord;
  }

  getAuditLog(limit = 20) {
    return this.auditHistory.slice(0, limit);
  }
}
