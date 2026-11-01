/**
 * AgentGuard NEAR Intents (Defuse Protocol) Adapter
 * Formats, validates, and bounds cross-chain swaps and transfers with strict slippage protection.
 * Supports 30+ chains via NEAR Chain Abstraction and the 1Click Defuse solver network.
 */

export const SUPPORTED_CHAINS = [
  'near',
  'solana',
  'base',
  'ethereum',
  'bitcoin',
  'arbitrum',
  'dogecoin',
  'sui',
  'polygon',
  'avalanche',
  'optimism',
];

export const WELL_KNOWN_ASSETS = {
  'near:wNEAR': 'nep141:wrap.near',
  'near:USDC': 'nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1',
  'solana:SOL': 'nep141:sol.omft.near',
  'base:USDC': 'nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near',
  'base:ETH': 'nep141:base.omft.near',
  'ethereum:USDC': 'nep141:eth-0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48.omft.near',
  'ethereum:ETH': 'nep141:eth.omft.near',
  'ethereum:USDT': 'nep141:eth-0xdac17f958d2ee523a2206206994597c13d831ec7.omft.near',
  'bitcoin:BTC': 'nep141:btc.omft.near',
  'arbitrum:ARB': 'nep141:arb-0x912ce59144191c1204e64559fe8253a0e49e6548.omft.near',
  'dogecoin:DOGE': 'nep141:doge.omft.near',
};

export class NearIntentsAdapter {
  constructor(options = {}) {
    this.verifierContract = options.verifierContract || 'intents.near';
    this.defaultMaxSlippagePercent = options.maxSlippagePercent || 1.5;
    this.solverRelayWsUrl = options.solverRelayWsUrl || 'wss://solver-relay-v2.chaindefuser.com/ws';
    this.oneClickApiUrl = options.oneClickApiUrl || 'https://1click.chaindefuser.com/v0';
    // The NEAR account ID that will sign/send intent transactions.
    // Override per-call or set once at construction.
    this.signerAccountId = options.signerAccountId || options.accountId || 'agent.near';
  }

  /**
   * Validates recipient address format for supported blockchains.
   */
  validateRecipientAddress(chain, address) {
    if (!address || typeof address !== 'string') {
      return { valid: false, reason: 'Recipient address must be a non-empty string' };
    }

    const normalizedChain = chain.toLowerCase();

    if (normalizedChain === 'near') {
      const isNamed = /^[a-z0-9_-]+\.(near|testnet)$/.test(address);
      const isImplicit = /^[0-9a-fA-F]{64}$/.test(address);
      if (!isNamed && !isImplicit) {
        return { valid: false, reason: 'Invalid NEAR account ID (must end in .near/.testnet or be 64-char hex)' };
      }
    } else if (normalizedChain === 'ethereum' || normalizedChain === 'base' || normalizedChain === 'arbitrum' || normalizedChain === 'polygon' || normalizedChain === 'optimism') {
      const isEvm = /^0x[0-9a-fA-F]{40}$/.test(address);
      if (!isEvm) {
        return { valid: false, reason: `Invalid ${chain} address (must be 0x-prefixed 40-character hex)` };
      }
    } else if (normalizedChain === 'solana') {
      const isSolana = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(address);
      if (!isSolana) {
        return { valid: false, reason: 'Invalid Solana address (must be Base58 string between 32 and 44 characters)' };
      }
    } else if (normalizedChain === 'bitcoin') {
      const isBtc = /^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$/.test(address);
      if (!isBtc) {
        return { valid: false, reason: 'Invalid Bitcoin address format' };
      }
    }

    return { valid: true };
  }

  /**
   * Prepares and validates a swap intent payload under security guardrails.
   */
  buildSwapIntent({
    tokenIn,
    tokenOut,
    amountIn,
    expectedAmountOut,
    maxSlippagePercent,
    deadlineMinutes = 5,
    signerId,
  }) {
    const slippage = maxSlippagePercent ?? this.defaultMaxSlippagePercent;
    if (slippage > 5.0) {
      throw new Error(`Slippage tolerance of ${slippage}% exceeds maximum security bound of 5.0%`);
    }

    const expectedOutBn = BigInt(expectedAmountOut);
    const slippageBps = BigInt(Math.floor(slippage * 100));
    const minAmountOut = (expectedOutBn * (10000n - slippageBps)) / 10000n;
    const deadlineTimestamp = Date.now() + deadlineMinutes * 60 * 1000;
    const resolvedSignerId = signerId || this.signerAccountId;

    const intentPayload = {
      standard: 'nep413',
      message: {
        signer_id: resolvedSignerId,
        verifying_contract: this.verifierContract,
        deadline: new Date(deadlineTimestamp).toISOString(),
        intents: [
          {
            intent: 'token_diff',
            diff: {
              [tokenIn]: `-${amountIn.toString()}`,
              [tokenOut]: minAmountOut.toString(),
            },
          },
        ],
      },
    };

    return {
      verifierContract: this.verifierContract,
      tokenIn,
      tokenOut,
      amountIn: amountIn.toString(),
      minAmountOut: minAmountOut.toString(),
      expectedAmountOut: expectedAmountOut.toString(),
      slippagePercent: slippage,
      deadlineTimestamp,
      intentPayload,
      summary: `Intent: Swap ${amountIn} of ${tokenIn} for minimum ${minAmountOut} of ${tokenOut} (max ${slippage}% slippage).`,
    };
  }

  /**
   * Builds and validates a cross-chain swap intent across NEAR, Solana, Base, Ethereum, or Bitcoin.
   */
  buildCrossChainSwapIntent({
    originAsset,
    destinationAsset,
    destinationChain,
    recipientAddress,
    amountIn,
    expectedAmountOut,
    maxSlippagePercent,
    refundAddress = 'agent.near',
    deadlineMinutes = 10,
  }) {
    const slippage = maxSlippagePercent ?? this.defaultMaxSlippagePercent;
    if (slippage > 5.0) {
      throw new Error(`Cross-chain slippage tolerance of ${slippage}% exceeds maximum security bound of 5.0%`);
    }

    // Resolve well-known shorthand aliases
    const resolvedOrigin = WELL_KNOWN_ASSETS[originAsset] || originAsset;
    const resolvedDest = WELL_KNOWN_ASSETS[destinationAsset] || destinationAsset;

    // Validate recipient address on destination chain
    const addrCheck = this.validateRecipientAddress(destinationChain, recipientAddress);
    if (!addrCheck.valid) {
      throw new Error(`Destination address validation failed: ${addrCheck.reason}`);
    }

    const expectedOutBn = BigInt(expectedAmountOut);
    const slippageBps = BigInt(Math.floor(slippage * 100));
    const minAmountOut = (expectedOutBn * (10000n - slippageBps)) / 10000n;
    const deadline = new Date(Date.now() + deadlineMinutes * 60 * 1000).toISOString();

    const crossChainPayload = {
      dry: false,
      swapType: 'EXACT_INPUT',
      originAsset: resolvedOrigin,
      destinationAsset: resolvedDest,
      amount: amountIn.toString(),
      slippageTolerance: Math.round(slippage * 100),
      depositType: 'INTENTS',
      refundTo: refundAddress,
      refundType: 'INTENTS',
      recipient: recipientAddress,
      recipientType: destinationChain.toLowerCase() === 'near' ? 'INTENTS' : 'DESTINATION_CHAIN',
      deadline,
    };

    return {
      isCrossChain: true,
      destinationChain,
      recipientAddress,
      originAsset: resolvedOrigin,
      destinationAsset: resolvedDest,
      amountIn: amountIn.toString(),
      expectedAmountOut: expectedAmountOut.toString(),
      minAmountOut: minAmountOut.toString(),
      slippagePercent: slippage,
      deadline,
      payload: crossChainPayload,
      summary: `Cross-Chain Intent: Swap ${amountIn} (${resolvedOrigin}) to ${destinationChain.toUpperCase()} address ${recipientAddress} for min ${minAmountOut} (${resolvedDest}).`,
    };
  }

  /**
   * Fetches real quote from NEAR Intents 1Click API or calculates deterministic fallback.
   */
  async simulateQuote({ tokenIn, tokenOut, amountIn, accountId = 'user.near' }) {
    try {
      const deadline = new Date(Date.now() + 5 * 60 * 1000).toISOString();
      const res = await fetch(`${this.oneClickApiUrl}/quote`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          dry: true,
          swapType: 'EXACT_INPUT',
          originAsset: tokenIn,
          destinationAsset: tokenOut,
          amount: amountIn.toString(),
          slippageTolerance: Math.round((this.defaultMaxSlippagePercent || 1.5) * 100),
          depositType: 'INTENTS',
          refundTo: accountId,
          refundType: 'INTENTS',
          recipient: accountId,
          recipientType: 'INTENTS',
          deadline,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        if (data && data.quote) {
          return {
            solver: '1click.chaindefuser.com',
            quoteId: data.correlationId || `quote_${Date.now()}`,
            amountIn: data.quote.amountIn,
            amountInUsd: data.quote.amountInUsd,
            expectedAmountOut: data.quote.amountOut,
            minAmountOut: data.quote.minAmountOut,
            amountOutUsd: data.quote.amountOutUsd,
            timeEstimate: data.quote.timeEstimate,
            signature: data.signature,
            executionChain: 'near',
            gasless: true,
            isLiveQuote: true,
          };
        }
      }
    } catch (err) {
      throw new Error(`1Click quote unavailable (${err.message}); refusing to fabricate a quote`);
    }
    throw new Error('1Click quote unavailable: empty or invalid response; refusing to fabricate a quote');
  }

  /**
   * Fetches real live quote for a cross-chain swap to external chains (Solana, Base, Ethereum, BTC).
   */
  async simulateCrossChainQuote({
    originAsset,
    destinationAsset,
    destinationChain,
    recipientAddress,
    amountIn,
    refundAddress = 'agent.near',
  }) {
    const resolvedOrigin = WELL_KNOWN_ASSETS[originAsset] || originAsset;
    const resolvedDest = WELL_KNOWN_ASSETS[destinationAsset] || destinationAsset;
    const deadline = new Date(Date.now() + 5 * 60 * 1000).toISOString();
    const isDirectChainDelivery = destinationChain && destinationChain.toLowerCase() !== 'near';

    try {
      const res = await fetch(`${this.oneClickApiUrl}/quote`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          dry: true,
          swapType: 'EXACT_INPUT',
          originAsset: resolvedOrigin,
          destinationAsset: resolvedDest,
          amount: amountIn.toString(),
          slippageTolerance: Math.round((this.defaultMaxSlippagePercent || 1.5) * 100),
          depositType: 'INTENTS',
          refundTo: refundAddress,
          refundType: 'INTENTS',
          recipient: recipientAddress,
          recipientType: isDirectChainDelivery ? 'DESTINATION_CHAIN' : 'INTENTS',
          deadline,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        if (data && data.quote) {
          return {
            isCrossChain: true,
            destinationChain,
            originAsset: resolvedOrigin,
            destinationAsset: resolvedDest,
            amountIn: data.quote.amountIn,
            amountInUsd: data.quote.amountInUsd,
            expectedAmountOut: data.quote.amountOut,
            minAmountOut: data.quote.minAmountOut,
            amountOutUsd: data.quote.amountOutUsd,
            timeEstimate: data.quote.timeEstimate,
            withdrawFee: data.quote.withdrawFee || '0',
            recipientAddress,
            signature: data.signature,
            isLiveQuote: true,
          };
        }
      }
    } catch (err) {
      throw new Error(`1Click cross-chain quote unavailable (${err.message}); refusing to fabricate a quote`);
    }
    throw new Error('1Click cross-chain quote unavailable: empty or invalid response; refusing to fabricate a quote');
  }

  /**
   * Retrieves full catalog of tokens available across 37 blockchains.
   */
  async fetchCatalog() {
    try {
      const res = await fetch(`${this.oneClickApiUrl}/tokens`);
      if (res.ok) {
        return await res.json();
      }
    } catch (_) {}
    return [];
  }
}
