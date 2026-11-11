/**
 * AgentGuard Framework Middleware
 * Drop-in security adapters for ElizaOS, LangChain, and autonomous agent runtimes.
 */

import { ThreatLevel } from './firewall.js';

/**
 * Creates an ElizaOS-compatible security plugin that intercepts agent actions
 * and validates them against the AgentGuard Firewall and On-Chain Spending Policy.
 *
 * @param {import('./index.js').AgentGuard} agentGuard - Initialized AgentGuard instance
 * @returns {Object} ElizaOS Plugin definition
 */
export function createElizaPlugin(agentGuard) {
  return {
    name: 'near-warden',
    description: 'Autonomous security firewall and on-chain spending guardrails for Web3 agents',
    
    // Pre-action security inspector
    async validateAction({ runtime, message, state, actionName, params }) {
      const prompt = message?.content?.text || '';
      const targetContract = params?.targetContract || params?.contractId || 'intents.near';
      const methodName = params?.methodName || actionName || 'execute_intent';
      const amount = params?.amount || params?.value || '0';

      const report = await agentGuard.processAgentIntent({
        prompt,
        targetContract,
        methodName,
        args: params,
        amount,
        executeOnChain: false,
      });

      if (report.status === 'BLOCKED_BY_FIREWALL') {
        return {
          allowed: false,
          reason: `Action blocked by AI Firewall: ${report.message}`,
          threatScore: report.threatScore,
          threatLevel: report.threatLevel,
        };
      }

      if (report.status === 'REJECTED_BY_POLICY') {
        return {
          allowed: false,
          reason: `Action rejected by Spending Policy: ${report.message}`,
          statusCode: report.statusCode,
        };
      }

      if (report.status === 'ESCALATED_FOR_HUMAN_APPROVAL') {
        return {
          allowed: false,
          requiresEscalation: true,
          reason: `High-value action requires human approval: ${report.message}`,
          actionId: report.intent?.actionId,
        };
      }

      return {
        allowed: true,
        threatScore: report.threatScore,
        summary: report.message,
      };
    },

    // Evaluators to assess safety after turns
    evaluators: [
      {
        name: 'AGENT_GUARD_SECURITY_EVALUATOR',
        description: 'Continuously monitors conversation context for jailbreaks or prompt injections',
        handler: async (runtime, message) => {
          const text = message?.content?.text || '';
          return agentGuard.firewall.inspect({ prompt: text });
        },
      },
    ],

    // Actions the agent can invoke to introspect its own limits
    actions: [
      {
        name: 'CHECK_VAULT_LIMITS',
        description: 'Checks remaining daily spending quota and per-transaction limits on NEAR',
        handler: async (runtime, message) => {
          const status = agentGuard.policyEngine.getStatus();
          return {
            isFrozen: status.isFrozen,
            remainingDailyQuota: status.remainingQuota,
            dailySpent: status.dailySpent,
            dailySpendingCap: status.dailySpendingCap,
            perTransactionCap: status.perTxCap,
            recentCallCount: status.recentCallCount,
            maxVelocityPerHour: status.maxVelocityPerHour,
          };
        },
      },
    ],
  };
}

/**
 * Wraps any LangChain DynamicStructuredTool or Custom Tool with AgentGuard pre-flight inspection.
 *
 * @param {Object} tool - LangChain tool instance with .name and .invoke / .call
 * @param {import('./index.js').AgentGuard} agentGuard - Initialized AgentGuard instance
 * @returns {Object} Wrapped LangChain tool
 */
export function wrapLangChainTool(tool, agentGuard) {
  const originalCall = tool.invoke ? tool.invoke.bind(tool) : tool.call.bind(tool);

  const guardedInvoke = async (input, config) => {
    const prompt = typeof input === 'string' ? input : (input.prompt || input.instruction || JSON.stringify(input));
    const targetContract = input.targetContract || input.contract || input.to || 'intents.near';
    const methodName = input.methodName || input.method || tool.name;
    const amount = input.amount || input.value || '0';

    // Run full security pipeline
    const auditResult = await agentGuard.processAgentIntent({
      prompt,
      targetContract,
      methodName,
      args: input,
      amount,
      executeOnChain: false,
    });

    if (auditResult.status !== 'APPROVED_AND_EXECUTED') {
      return {
        success: false,
        interrupted: true,
        securityReport: {
          status: auditResult.status,
          threatScore: auditResult.threatScore,
          threatLevel: auditResult.threatLevel,
          flags: auditResult.flags,
          reason: auditResult.message,
        },
        error: `AgentGuard Intercept: ${auditResult.status} - ${auditResult.message}`,
      };
    }

    // Call underlying tool with verified input
    const toolResult = await originalCall(input, config);

    return {
      success: true,
      result: toolResult,
      agentGuardTrace: {
        threatScore: auditResult.threatScore,
        evaluator: auditResult.evaluator || 'HEURISTIC_GUARD',
        policyCompliant: true,
      },
    };
  };

  // Preserve tool properties
  const guardedTool = Object.create(tool);
  guardedTool.invoke = guardedInvoke;
  guardedTool.call = guardedInvoke;
  guardedTool.isGuardedByAgentGuard = true;

  return guardedTool;
}

/**
 * Generic functional middleware for any arbitrary agent loop or OpenAI function-call runner.
 *
 * @param {import('./index.js').AgentGuard} agentGuard
 * @returns {Function} (toolCall, next) => Promise<any>
 */
export function createAgentGuardMiddleware(agentGuard) {
  return async function guardMiddleware(context, next) {
    const { prompt, targetContract, methodName, args, amount } = context;

    const report = await agentGuard.processAgentIntent({
      prompt,
      targetContract,
      methodName,
      args,
      amount,
    });

    if (report.status !== 'APPROVED_AND_EXECUTED') {
      const err = new Error(`AgentGuard Intercept [${report.status}]: ${report.message}`);
      err.code = report.status;
      err.report = report;
      throw err;
    }

    context.securityReport = report;
    return await next();
  };
}
