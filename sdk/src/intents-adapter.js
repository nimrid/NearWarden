/**
 * AgentGuard NEAR Intents (Defuse Protocol) Adapter
 * Formats, validates, and bounds cross-chain swaps and transfers with strict slippage protection.
 */

export class NearIntentsAdapter {
  constructor(options = {}) {
    this.verifierContract = options.verifierContract || 'intents.near';
    this.defaultMaxSlippagePercent = options.maxSlippagePercent || 1.5;
    this.solverRelayWsUrl = options.solverRelayWsUrl || 'wss://solver-relay-v2.chaindefuser.com/ws';
  }

  /**
   * Prepares and validates a swap intent payload under security guardrails.
   * @param {Object} params
   * @param {string} params.tokenIn - NEP-141 or NEP-245 token ID (e.g. "nep141:wrap.near")
   * @param {string} params.tokenOut - Target token ID (e.g. "nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1" for USDC)
   * @param {string|bigint} params.amountIn - Raw token input amount
   * @param {string|bigint} params.expectedAmountOut - Expected fill without slippage
   * @param {number} [params.maxSlippagePercent] - Slippage tolerance (default: 1.5%)
   * @param {number} [params.deadlineMinutes] - Expiry in minutes (default: 5)
   * @returns {Object} Signed intent payload and validation metadata
   */
  buildSwapIntent({
    tokenIn,
    tokenOut,
    amountIn,
    expectedAmountOut,
    maxSlippagePercent,
    deadlineMinutes = 5,
  }) {
    const slippage = maxSlippagePercent ?? this.defaultMaxSlippagePercent;
    if (slippage > 5.0) {
      throw new Error(`Slippage tolerance of ${slippage}% exceeds maximum security bound of 5.0%`);
    }

    const expectedOutBn = BigInt(expectedAmountOut);
    // minAmountOut = expectedOut * (1000 - slippage * 10) / 1000
    const slippageBps = BigInt(Math.floor(slippage * 100));
    const minAmountOut = (expectedOutBn * (10000n - slippageBps)) / 10000n;

    const deadlineTimestamp = Date.now() + deadlineMinutes * 60 * 1000;

    const intentPayload = {
      standard: 'nep413',
      message: {
        signer_id: 'agent.near',
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
   * Simulates quotes from competitive solvers.
   */
  async simulateQuote({ tokenIn, tokenOut, amountIn }) {
    // Deterministic simulation based on mock pools
    const amountBn = BigInt(amountIn);
    // Example: 1 NEAR (~5 USDC)
    const simulatedRate = tokenIn.includes('wrap.near') && tokenOut.includes('17208628') ? 5_000_000n : 1_000_000n;
    const expectedOut = (amountBn * simulatedRate) / 1_000_000_000_000_000_000_000_000n;

    return {
      solver: 'solver-relay-top-bid.near',
      quoteId: `quote_${Date.now()}`,
      amountIn: amountIn.toString(),
      expectedAmountOut: expectedOut > 0n ? expectedOut.toString() : '5000000',
      executionChain: 'near',
      gasless: true,
    };
  }
}
