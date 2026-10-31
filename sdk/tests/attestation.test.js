import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createFirewallKeypair,
  signFirewallAttestation,
  verifyFirewallAttestation,
  computeIntentDigest,
} from '../src/attestation.js';
import { AgentGuard } from '../src/index.js';

test('Attestation - Generates valid Ed25519 keypair', () => {
  const keys = createFirewallKeypair();
  assert.ok(keys.publicKey);
  assert.ok(keys.privateKey);
  assert.equal(keys.rawPublicKeyBytes.length, 32);
});

test('Attestation - Signs intent and verifies against public key', () => {
  const { publicKey, privateKey } = createFirewallKeypair();

  const intent = {
    target: 'wrap.near',
    method: 'ft_transfer',
    args: { receiver_id: 'bob.near', amount: '1000' },
    amount: '1000000000000000000000000',
    threatScore: 12,
  };

  const attestation = signFirewallAttestation({
    ...intent,
    privateKey,
  });

  assert.equal(attestation.threat_score, 12);
  assert.equal(typeof attestation.timestamp_ms, 'number');
  assert.equal(attestation.signature.length, 128); // 64 bytes in hex = 128 chars

  const check = verifyFirewallAttestation({
    ...intent,
    attestation,
    publicKey,
  });

  assert.equal(check.valid, true);
  assert.equal(check.reason, 'Signature valid');
});

test('Attestation - Rejects tampered target or amount', () => {
  const { publicKey, privateKey } = createFirewallKeypair();

  const intent = {
    target: 'wrap.near',
    method: 'ft_transfer',
    args: { receiver_id: 'bob.near', amount: '1000' },
    amount: '1000000000000000000000000',
    threatScore: 10,
  };

  const attestation = signFirewallAttestation({
    ...intent,
    privateKey,
  });

  // Tamper: Attacker modifies target to attacker.near
  const tamperedTarget = verifyFirewallAttestation({
    ...intent,
    target: 'attacker.near',
    attestation,
    publicKey,
  });
  assert.equal(tamperedTarget.valid, false);

  // Tamper: Attacker modifies amount
  const tamperedAmount = verifyFirewallAttestation({
    ...intent,
    amount: '9999999999999999999999999',
    attestation,
    publicKey,
  });
  assert.equal(tamperedAmount.valid, false);
});

test('Attestation - Rejects expired attestation', () => {
  const { publicKey, privateKey } = createFirewallKeypair();

  const intent = {
    target: 'intents.near',
    method: 'execute_intent',
    args: {},
    amount: '0',
    threatScore: 5,
  };

  const expiredAttestation = signFirewallAttestation({
    ...intent,
    privateKey,
    timestampMs: Date.now() - 400_000, // 400 seconds ago (maxAge is 300s)
  });

  const check = verifyFirewallAttestation({
    ...intent,
    attestation: expiredAttestation,
    publicKey,
    maxAgeMs: 300_000,
  });

  assert.equal(check.valid, false);
  assert.match(check.reason, /expired/);
});

test('AgentGuard - Integrates firewall private key and attaches attestation to executed intent', async () => {
  const { privateKey } = createFirewallKeypair();
  const guard = new AgentGuard({
    firewallPrivateKey: privateKey,
  });

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
  assert.equal(res.attestation.signature.length, 128);
  assert.equal(typeof res.attestation.threat_score, 'number');
  assert.equal(typeof res.attestation.nonce, 'number');
});

test('Attestation - Generates unique nonces to prevent replay attacks and rejects tampered nonces', () => {
  const { publicKey, privateKey } = createFirewallKeypair();

  const intent = {
    target: 'wrap.near',
    method: 'ft_transfer',
    args: { receiver_id: 'bob.near', amount: '1000' },
    amount: '1000000000000000000000000',
    threatScore: 8,
  };

  const att1 = signFirewallAttestation({ ...intent, privateKey });
  const att2 = signFirewallAttestation({ ...intent, privateKey });

  // Each signed attestation has unique entropy (nonce) to prevent replay
  assert.notEqual(att1.nonce, att2.nonce);
  assert.notEqual(att1.signature, att2.signature);

  // Both are independently valid with their respective nonces
  assert.equal(verifyFirewallAttestation({ ...intent, attestation: att1, publicKey }).valid, true);
  assert.equal(verifyFirewallAttestation({ ...intent, attestation: att2, publicKey }).valid, true);

  // Tampering with nonce invalidates signature
  const tamperedNonce = { ...att1, nonce: att1.nonce + 1 };
  const tamperedCheck = verifyFirewallAttestation({ ...intent, attestation: tamperedNonce, publicKey });
  assert.equal(tamperedCheck.valid, false);
  assert.equal(tamperedCheck.reason, 'Cryptographic signature mismatch');
});
