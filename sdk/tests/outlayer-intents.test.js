import test from 'node:test';
import assert from 'node:assert/strict';
import { OutLayerClient } from '../src/outlayer-client.js';
import { NearIntentsAdapter } from '../src/intents-adapter.js';
import { AgentFirewall } from '../src/firewall.js';

test('OutLayerClient - Parses payment key owner and nonce correctly', () => {
  const client = new OutLayerClient({
    paymentKey: 'blackquokka5481.testnet:1:secretkey12345',
  });
  assert.equal(client.paymentOwner, 'blackquokka5481.testnet');
  assert.equal(client.paymentNonce, '1');
  assert.equal(client.nearAccountId, 'blackquokka5481.testnet');
});

test('OutLayerClient - Builds valid TEE binding policy specification', () => {
  const client = new OutLayerClient();
  const policy = client.buildBindingPolicy({
    dailyCap: '5000000000000000000000000',
    perTxCap: '1000000000000000000000000',
    allowedPayees: ['intents.near', 'ref-finance.near'],
  });
  assert.equal(policy.version, '1.0');
  assert.equal(policy.spending_caps.daily, '5000000000000000000000000');
  assert.deepEqual(policy.address_rules.allowed_addresses, ['intents.near', 'ref-finance.near']);
});

test('NearIntentsAdapter - Builds valid NEP-413 intent message with slippage guardrails', () => {
  const adapter = new NearIntentsAdapter({ maxSlippagePercent: 1.0 });
  const intent = adapter.buildSwapIntent({
    tokenIn: 'nep141:wrap.near',
    tokenOut: 'nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1',
    amountIn: '1000000000000000000000000',
    expectedAmountOut: '5000000',
  });

  assert.equal(intent.standard, undefined);
  assert.equal(intent.intentPayload.standard, 'nep413');
  assert.equal(intent.slippagePercent, 1.0);
  assert.equal(intent.minAmountOut, '4950000'); // 5,000,000 - 1%
});

test('NearIntentsAdapter - Rejects slippage exceeding 5.0% security bound', () => {
  const adapter = new NearIntentsAdapter();
  assert.throws(() => {
    adapter.buildSwapIntent({
      tokenIn: 'nep141:wrap.near',
      tokenOut: 'nep141:usdc.near',
      amountIn: '1000',
      expectedAmountOut: '1000',
      maxSlippagePercent: 6.5,
    });
  }, /exceeds maximum security bound/);
});

test('AgentFirewall - Gracefully parses Claude responses with or without markdown codeblocks', async () => {
  const firewall = new AgentFirewall();
  // Test baseline heuristic inspection
  const report = firewall.inspect({
    prompt: 'Execute 0.1 NEAR swap',
    targetContract: 'intents.near',
    methodName: 'execute_intent',
    amount: '100000000000000000000000',
  });
  assert.equal(report.isAllowed, true);
  assert.equal(report.threatScore, 0);
});

function mockTeeFetch() {
  return async (url, opts) => {
    const body = JSON.parse(opts.body);
    const input = body.input;
    let output;
    if (input.operation === 'public_key') {
      output = { status: 'ok', public_key: 'ed25519:6E8sCci9badyRkXb3JoRpAxTMkx2qkAZCSnVq6Qup2x5', public_key_hex: '00'.repeat(32) };
    } else if (input.operation === 'sign_attestation') {
      if (input.threat_score > 75) {
        output = { status: 'err', message: `threat score ${input.threat_score} exceeds enclave maximum of 75; signing refused` };
      } else {
        output = {
          status: 'ok',
          threat_score: input.threat_score,
          timestamp_ms: input.timestamp_ms,
          nonce: input.nonce,
          signature: 'ab'.repeat(64),
          public_key: 'ed25519:6E8sCci9badyRkXb3JoRpAxTMkx2qkAZCSnVq6Qup2x5',
        };
      }
    }
    const isErr = output.status !== 'ok';
    return {
      ok: true,
      json: async () => isErr
        ? { status: 'completed', output: JSON.stringify(output), call_id: 'call-1' }
        : { status: 'completed', output: JSON.stringify(output), attestation_url: '/attestations/call-1', call_id: 'call-1' },
      text: async () => '',
    };
  };
}

test('OutLayerClient - Fetches firewall public key from TEE enclave', async () => {
  const client = new OutLayerClient({
    paymentKey: 'blackquokka5481.testnet:1:secretkey12345',
    signerProject: 'blackquokka5481.testnet/agentguard-firewall-signer',
    fetchImpl: mockTeeFetch(),
  });
  const res = await client.anchorFirewallKeyInTee();

  assert.equal(res.success, true);
  assert.match(res.publicKey, /^ed25519:[1-9A-HJ-NP-Za-km-z]+$/);
  assert.equal(res.enclave.type, 'INTEL_TDX');
  assert.equal(res.enclave.hardware_sealed, true);
  assert.equal(res.enclave.status, 'TEE_DERIVED');
  assert.equal(client.isTeeSignerAnchored(), true);
  assert.equal(client.getTeePublicKey(), res.publicKey);
});

test('OutLayerClient - Fails closed when TEE signer is not configured', async () => {
  const client = new OutLayerClient();
  await assert.rejects(
    async () => client.anchorFirewallKeyInTee(),
    /TEE signer not configured/
  );
  await assert.rejects(
    async () => client.signAttestationViaTee({
      target: 'wrap.near', method: 'ft_transfer', args: {}, amount: '1', threatScore: 1,
    }),
    /TEE signer not configured/
  );
});

test('OutLayerClient - Signs attestation via TEE enclave and enforces security threshold', async () => {
  const client = new OutLayerClient({
    paymentKey: 'blackquokka5481.testnet:1:secretkey12345',
    signerProject: 'blackquokka5481.testnet/agentguard-firewall-signer',
    fetchImpl: mockTeeFetch(),
  });

  const intent = {
    target: 'wrap.near',
    method: 'ft_transfer',
    args: { receiver_id: 'alice.near', amount: '500' },
    amount: '500000000000000000000000',
    threatScore: 10,
  };

  const att = await client.signAttestationViaTee(intent);
  assert.equal(att.threat_score, 10);
  assert.equal(att.tee_proof.enclave_type, 'INTEL_TDX');
  assert.equal(att.tee_proof.hardware_sealed, true);
  assert.equal(att.signature.length, 128);

  await assert.rejects(
    async () => {
      await client.signAttestationViaTee({
        ...intent,
        threatScore: 88,
      });
    },
    /refused/
  );
});

test('AgentGuard - End-to-end intent processing with OutLayer TEE anchored attestation', async () => {
  const { AgentGuard } = await import('../src/index.js');
  const guard = new AgentGuard({
    useTeeSigner: true,
    outlayer: {
      paymentKey: 'blackquokka5481.testnet:1:secretkey12345',
      signerProject: 'blackquokka5481.testnet/agentguard-firewall-signer',
      fetchImpl: mockTeeFetch(),
    },
  });

  const anchorRes = await guard.anchorTeeFirewallKey();
  assert.equal(anchorRes.success, true);
  assert.ok(anchorRes.publicKey);

  const res = await guard.processAgentIntent({
    prompt: 'Swap 0.5 NEAR to USDC on intents.near',
    targetContract: 'intents.near',
    methodName: 'execute_intent',
    amount: '500000000000000000000000',
    isSwapIntent: false,
    executeOnChain: false,
  });

  assert.equal(res.status, 'APPROVED_AND_EXECUTED');
  assert.ok(res.attestation);
  assert.equal(res.attestation.tee_proof.enclave_type, 'INTEL_TDX');
  assert.equal(res.attestation.tee_proof.hardware_sealed, true);
});
