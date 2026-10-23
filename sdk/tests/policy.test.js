import test from 'node:test';
import assert from 'node:assert/strict';
import { PolicyEngine } from '../src/policy-engine.js';

test('PolicyEngine - Allows spending within per-tx and daily limits', () => {
  const engine = new PolicyEngine({
    dailySpendingCap: '10000000000000000000000000', // 10 NEAR
    perTxCap: '2000000000000000000000000', // 2 NEAR
  });

  const res = engine.evaluate({
    target: 'wrap.near',
    method: 'ft_transfer',
    amount: '1000000000000000000000000', // 1 NEAR
  });

  assert.equal(res.allowed, true);
  assert.equal(res.statusCode, 200);
});

test('PolicyEngine - Rejects target contract not in whitelist', () => {
  const engine = new PolicyEngine({
    allowedTargets: ['wrap.near', 'intents.near'],
  });

  const res = engine.evaluate({
    target: 'untrusted-gambling.near',
    method: 'bet',
    amount: '100000000000000000000000',
  });

  assert.equal(res.allowed, false);
  assert.equal(res.statusCode, 403);
  assert.ok(res.reason.includes('not in authorized whitelist'));
});

test('PolicyEngine - Flags transactions exceeding per-tx cap for escalation', () => {
  const engine = new PolicyEngine({
    perTxCap: '2000000000000000000000000', // 2 NEAR
  });

  const res = engine.evaluate({
    target: 'wrap.near',
    method: 'ft_transfer',
    amount: '5000000000000000000000000', // 5 NEAR
  });

  assert.equal(res.allowed, false);
  assert.equal(res.statusCode, 202);
  assert.equal(res.requiresEscalation, true);
});

test('PolicyEngine - Blocks execution when daily quota is exhausted', () => {
  const engine = new PolicyEngine({
    dailySpendingCap: '4000000000000000000000000', // 4 NEAR
    perTxCap: '2000000000000000000000000',
  });

  // Spend 2 NEAR
  assert.equal(engine.evaluate({ target: 'wrap.near', method: 'ft_transfer', amount: '2000000000000000000000000' }).allowed, true);
  // Spend 2 NEAR
  assert.equal(engine.evaluate({ target: 'wrap.near', method: 'ft_transfer', amount: '2000000000000000000000000' }).allowed, true);

  // Attempting 1 more NEAR exceeds 4 NEAR cap
  const res = engine.evaluate({ target: 'wrap.near', method: 'ft_transfer', amount: '1000000000000000000000000' });
  assert.equal(res.allowed, false);
  assert.equal(res.statusCode, 429);
  assert.ok(res.reason.includes('Daily quota exceeded'));
});

test('PolicyEngine - Emergency freeze halts all operations', () => {
  const engine = new PolicyEngine();
  engine.freeze();

  const res = engine.evaluate({
    target: 'wrap.near',
    method: 'ft_transfer',
    amount: '100000000000000000000000',
  });

  assert.equal(res.allowed, false);
  assert.equal(res.statusCode, 503);
  assert.ok(res.reason.includes('emergency frozen'));
});
