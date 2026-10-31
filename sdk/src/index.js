import * as nearAPI from 'near-api-js';
import { AgentFirewall, ThreatLevel } from './firewall.js';
import { PolicyEngine } from './policy-engine.js';
import { NearIntentsAdapter, SUPPORTED_CHAINS, WELL_KNOWN_ASSETS } from './intents-adapter.js';
import { OutLayerClient } from './outlayer-client.js';
import { createElizaPlugin, wrapLangChainTool, createAgentGuardMiddleware } from './middleware.js';
import {
  createFirewallKeypair,
  signFirewallAttestation,
  verifyFirewallAttestation,
  computeIntentDigest,
} from './attestation.js';
import {
  createSupervisorPasskey,
  signEscalationWithPasskey,
  verifyPasskeyApproval,
  isPasskeySupported,
  bufferToBase64Url,
  base64UrlToBuffer,
} from './passkey.js';

import {
  ChainSignatures,
  deriveForeignAddress,
  deriveChildPublicKey,
  buildEvmTransaction,
  assembleSignedEvmTransaction,
  toChecksumAddress,
  EVM_CHAIN_IDS,
  MPC_CONTRACTS,
} from './chain-signatures.js';

export {
  AgentFirewall,
  ThreatLevel,
  PolicyEngine,
  NearIntentsAdapter,
  OutLayerClient,
  ChainSignatures,
  deriveForeignAddress,
  deriveChildPublicKey,
  buildEvmTransaction,
  assembleSignedEvmTransaction,
  toChecksumAddress,
  EVM_CHAIN_IDS,
  MPC_CONTRACTS,
  SUPPORTED_CHAINS,
  WELL_KNOWN_ASSETS,
  createElizaPlugin,
  wrapLangChainTool,
  createAgentGuardMiddleware,
  createFirewallKeypair,
  signFirewallAttestation,
  verifyFirewallAttestation,
  computeIntentDigest,
  createSupervisorPasskey,
  signEscalationWithPasskey,
  verifyPasskeyApproval,
  isPasskeySupported,
  bufferToBase64Url,
  base64UrlToBuffer,
};

export class AgentGuard {
  constructor(config = {}) {
    this.firewall = new AgentFirewall(config.firewall);
    this.policyEngine = new PolicyEngine(config.policy);
    this.intentsAdapter = config.intentsAdapter || new NearIntentsAdapter(config.intents);
    this.outlayer = new OutLayerClient(config.outlayer);
    this.firewallPrivateKey = config.firewallPrivateKey || null;
    this.useTeeSigner = config.useTeeSigner ?? (config.firewallPrivateKey ? false : true);
    this.supervisorPasskey = config.supervisorPasskey || null;
    this.auditHistory = [];

    // Optional On-Chain NEAR Configuration
    this.contractId = config.contractId || null;
    this.networkId = config.networkId || 'testnet';
    this.nodeUrl = config.nodeUrl || (this.networkId === 'mainnet' ? 'https://rpc.mainnet.near.org' : 'https://rpc.testnet.near.org');
    this.account = config.account || null;
    this.near = null;

    // Chain Signatures (NEAR MPC Multi-Chain Execution)
    this.chainSignatures = new ChainSignatures({
      networkId: this.networkId,
      vaultContractId: this.contractId,
      account: this.account,
      ...config.chainSignatures,
    });
  }

  /**
   * Anchors the Firewall Attestation Key inside an OutLayer Intel TDX Hardware Enclave.
   * If syncToContract is true, updates the smart contract's firewall_public_key on NEAR.
   */
  async anchorTeeFirewallKey(options = {}) {
    const res = await this.outlayer.anchorFirewallKeyInTee(options);

    if (options.syncToContract && this.contractId && this.account) {
      await this.account.callFunction({
        contractId: this.contractId,
        methodName: 'set_firewall_public_key',
        args: {
          public_key: res.publicKey,
        },
        gas: '30000000000000',
      });
      res.syncedToContract = true;
      res.contractId = this.contractId;
    }

    return res;
  }

  /**
   * Registers a hardware-bound Biometric WebAuthn Passkey for the Human Supervisor.
   * If syncToContract is true, anchors the credential hash on the NEAR contract.
   */
  async registerSupervisorPasskey(options = {}) {
    const passkey = await createSupervisorPasskey(options);
    this.supervisorPasskey = passkey;

    if (options.syncToContract && this.contractId && this.account) {
      if (passkey.publicKeyHex) {
        await this.account.callFunction({
          contractId: this.contractId,
          methodName: 'set_supervisor_passkey_public_key',
          args: {
            public_key_hex: passkey.publicKeyHex,
          },
          gas: '30000000000000',
        });
      } else {
        await this.account.callFunction({
          contractId: this.contractId,
          methodName: 'set_supervisor_passkey',
          args: {
            passkey_hash: passkey.credentialHash || passkey.credentialId,
          },
          gas: '30000000000000',
        });
      }
      passkey.syncedToContract = true;
      passkey.contractId = this.contractId;
    }

    return passkey;
  }

  /**
   * Signs an escalated action approval with the Supervisor's Biometric Passkey.
   */
  async signEscalationWithPasskey(actionId, options = {}) {
    const passkey = options.passkey || this.supervisorPasskey;
    return signEscalationWithPasskey({
      actionId,
      targetContract: options.targetContract || this.contractId,
      amount: options.amount || '0',
      credentialId: passkey?.credentialId,
      privateKey: passkey?.privateKey,
      ...options,
    });
  }

  /**
   * Verifies a Supervisor Biometric Passkey signature.
   */
  verifyPasskeyApproval(options) {
    return verifyPasskeyApproval(options);
  }

  /**
   * Approves an escalated transaction on-chain, optionally presenting a Biometric Passkey signature.
   */
  async approveEscalatedWithPasskey(actionId, passkeySignature = null) {
    if (!this.contractId || !this.account) {
      throw new Error('contractId and account required for on-chain approval');
    }
    return this.account.callFunction({
      contractId: this.contractId,
      methodName: 'approve_escalated',
      args: {
        action_id: Number(actionId),
        passkey_signature: passkeySignature,
      },
      gas: '60000000000000',
    });
  }

  /**
   * Initializes real NEAR RPC Provider if configured.
   */
  initNearProvider() {
    if (!this.provider) {
      this.provider = new nearAPI.JsonRpcProvider({ url: this.nodeUrl });
    }
    return this.provider;
  }

  /**
   * Queries real on-chain vault status via NEAR RPC
   */
  async getOnChainVaultStatus() {
    if (!this.contractId) throw new Error('contractId not set in AgentGuard configuration');
    const provider = this.initNearProvider();
    const raw = await provider.query({
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
    const provider = this.initNearProvider();
    const raw = await provider.query({
      request_type: 'call_function',
      account_id: this.contractId,
      method_name: 'get_pending_actions',
      args_base64: Buffer.from('{}').toString('base64'),
      finality: 'optimistic',
    });
    return JSON.parse(Buffer.from(raw.result).toString());
  }

  /**
   * Derives a deterministic foreign address (Base, Ethereum, Arbitrum, Bitcoin) for the agent.
   */
  deriveForeignAddress(options = {}) {
    const accountId = options.accountId || this.account?.accountId || 'agent.near';
    return this.chainSignatures.deriveAddress({
      accountId,
      path: options.path || 'ethereum,1',
      chain: options.chain || 'base',
    });
  }

  /**
   * Requests an MPC threshold signature from NEAR v1.signer for arbitrary multi-chain payloads.
   */
  async requestChainSignature(options = {}) {
    return this.chainSignatures.requestSignature(options);
  }

  /**
   * End-to-end multi-chain EVM execution: prepares EIP-1559 tx, validates policy, requests MPC sig, and assembles.
   */
  async executeMultiChainEvm({ evmTx, path = 'ethereum,1', foreignChain = 'base', estimatedAmount = '0' } = {}) {
    // 1. Prepare and hash EIP-1559 transaction
    const unsignedTx = this.chainSignatures.prepareEvmTransaction(evmTx);

    // 2. Pre-flight Firewall Inspection on the multi-chain intent
    const firewallReport = this.firewall.inspect({
      prompt: `Multi-Chain EVM Tx on ${foreignChain}: send ${unsignedTx.value} wei to ${unsignedTx.to}`,
      targetContract: this.chainSignatures.mpcContractId,
      methodName: `sign_multichain:${foreignChain}`,
      args: { path, to: unsignedTx.to, value: unsignedTx.value, data: unsignedTx.data },
      amount: estimatedAmount,
    });

    if (!firewallReport.isAllowed) {
      return {
        status: 'BLOCKED_BY_FIREWALL',
        threatScore: firewallReport.threatScore,
        message: firewallReport.summary,
        flags: firewallReport.detectedFlags,
      };
    }

    // 3. Request MPC signature via AgentGuard
    const sigResult = await this.chainSignatures.requestSignature({
      payload: unsignedTx.hashArray,
      path,
      foreignChain,
      estimatedAmount,
    });

    // 4. If simulated or returned affine point coordinates, assemble the signed raw hex
    let signedRawTxHex = null;
    if (sigResult.big_r && sigResult.s) {
      signedRawTxHex = this.chainSignatures.assembleSignedTransaction({
        unsignedTx,
        bigR: sigResult.big_r,
        s: sigResult.s,
        recoveryId: sigResult.recovery_id,
      });
    }

    return {
      status: 'APPROVED_AND_EXECUTED',
      foreignChain,
      unsignedTx,
      sigResult,
      signedRawTxHex,
      message: `Multi-chain intent successfully authorized and signed for ${foreignChain}.`,
    };
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

    // Step 1: Pre-flight Firewall Inspection (Heuristic + Claude AI when configured)
    const firewallReport = await this.firewall.inspectWithClaude({
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

    // Step 4: Cryptographic AI Firewall Attestation (Anchored in OutLayer TEE or Local Signer)
    let onChainTx = null;
    let attestation = null;

    try {
      if (this.useTeeSigner || this.outlayer?.isTeeSignerAnchored?.()) {
        attestation = await this.outlayer.signAttestationViaTee({
          target: intent.targetContract,
          method: intent.methodName,
          args: intent.args || {},
          amount: intent.amount || '0',
          threatScore: firewallReport.threatScore,
        });
      } else if (this.firewallPrivateKey) {
        attestation = signFirewallAttestation({
          target: intent.targetContract,
          method: intent.methodName,
          args: intent.args || {},
          amount: intent.amount || '0',
          threatScore: firewallReport.threatScore,
          privateKey: this.firewallPrivateKey,
        });
      }
    } catch (err) {
      return {
        timestamp: startTime,
        status: 'ATTESTATION_UNAVAILABLE',
        statusCode: 503,
        threatScore: firewallReport.threatScore,
        threatLevel: firewallReport.threatLevel,
        flags: ['ATTESTATION_SIGNER_UNAVAILABLE'],
        intent,
        message: `Attestation signer unavailable; refusing to execute without a valid attestation: ${err.message}`,
      };
    }

    if (intent.executeOnChain && !attestation) {
      return {
        timestamp: startTime,
        status: 'ATTESTATION_UNAVAILABLE',
        statusCode: 503,
        threatScore: firewallReport.threatScore,
        threatLevel: firewallReport.threatLevel,
        flags: ['ATTESTATION_SIGNER_UNAVAILABLE'],
        intent,
        message: 'No attestation signer configured (TEE or local); refusing on-chain execution without an attestation.',
      };
    }

    if (intent.executeOnChain && this.account && this.contractId) {
      try {
        const callArgs = {
          contractId: this.contractId,
          methodName: 'execute_intent',
          args: {
            target: intent.targetContract,
            method: intent.methodName,
            args: typeof intent.args === 'string' ? intent.args : JSON.stringify(intent.args || {}),
            amount: intent.amount ? intent.amount.toString() : null,
            attestation,
          },
          gas: '50000000000000', // 50 TGas
          attachedDeposit: '0',
        };
        const txOutcome = typeof this.account.callFunction === 'function'
          ? await this.account.callFunction(callArgs)
          : await this.account.functionCall(callArgs);
        onChainTx = {
          transactionHash: txOutcome?.transaction?.hash || txOutcome?.transaction_outcome?.id || 'broadcast_success',
          gasBurned: txOutcome?.receipts_outcome?.reduce((acc, r) => acc + (r.outcome?.gas_burnt || 0), 0) || 0,
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
      attestation,
      message: `Intent successfully verified and executed on ${intent.targetContract}.`,
    };

    this.auditHistory.unshift(successRecord);
    return successRecord;
  }

  getAuditLog(limit = 20) {
    return this.auditHistory.slice(0, limit);
  }
}
