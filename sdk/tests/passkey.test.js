import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isPasskeySupported,
  bufferToBase64Url,
  base64UrlToBuffer,
  createSupervisorPasskey,
  signEscalationWithPasskey,
  verifyPasskeyApproval,
} from '../src/passkey.js';
import { AgentGuard } from '../src/index.js';

test('Passkey - Checks environment passkey support', () => {
  // In Node.js environment, window is undefined, so isPasskeySupported returns false
  const supported = isPasskeySupported();
  assert.equal(supported, false);
});

test('Passkey - Base64URL encoding and decoding roundtrip', () => {
  const original = Buffer.from('AgentGuard:WebAuthn:TouchID:EscalationChallenge');
  const encoded = bufferToBase64Url(original);
  assert.ok(!encoded.includes('+'));
  assert.ok(!encoded.includes('/'));
  assert.ok(!encoded.includes('='));

  const decoded = base64UrlToBuffer(encoded);
  assert.equal(decoded.toString('utf8'), original.toString('utf8'));
});

test('Passkey - Generates NIST P-256 (ES256) supervisor passkey credentials', async () => {
  const passkey = await createSupervisorPasskey({
    username: 'supervisor.near',
    displayName: 'Chief Risk Officer',
  });

  assert.ok(passkey.credentialId);
  assert.ok(passkey.publicKeyPem);
  assert.ok(passkey.publicKeyDer);
  assert.ok(passkey.credentialHash);
  assert.equal(passkey.credentialHash.length, 64); // SHA-256 hex string
  assert.equal(passkey.authenticator, 'SIMULATED_SECURE_ENCLAVE');
  assert.equal(passkey.algorithm, 'ES256 (NIST P-256)');
  assert.equal(passkey.status, 'REGISTERED');
});

test('Passkey - Biometric signing produces valid cryptographic signature over escalation challenge', async () => {
  const passkey = await createSupervisorPasskey();

  const approval = await signEscalationWithPasskey({
    actionId: 42,
    targetContract: 'wrap.near',
    amount: '5000000000000000000000000', // 5 NEAR
    credentialId: passkey.credentialId,
    privateKey: passkey.privateKey,
  });

  assert.equal(approval.actionId, 42);
  assert.equal(approval.credentialId, passkey.credentialId);
  assert.ok(approval.signature);
  assert.ok(approval.challengeText.includes('AgentGuard:ApproveAction:42:wrap.near:5000000000000000000000000:'));
  assert.equal(approval.biometricVerified, true);
  assert.equal(approval.authMethod, 'SECURE_ENCLAVE_P256');

  const check = verifyPasskeyApproval({
    publicKeyPem: passkey.publicKeyPem,
    signature: approval.signature,
    challengeText: approval.challengeText,
  });

  assert.equal(check.valid, true);
  assert.equal(check.reason, 'Biometric passkey signature valid');
});

test('Passkey - Rejects tampered actionId, targetContract, or amount', async () => {
  const passkey = await createSupervisorPasskey();

  const approval = await signEscalationWithPasskey({
    actionId: 10,
    targetContract: 'wrap.near',
    amount: '3000000000000000000000000',
    credentialId: passkey.credentialId,
    privateKey: passkey.privateKey,
  });

  // Tampered challenge text with different action ID
  const tamperedActionCheck = verifyPasskeyApproval({
    publicKeyPem: passkey.publicKeyPem,
    signature: approval.signature,
    challengeText: approval.challengeText.replace(':10:', ':99:'),
  });
  assert.equal(tamperedActionCheck.valid, false);

  // Tampered challenge text with different amount
  const tamperedAmountCheck = verifyPasskeyApproval({
    publicKeyPem: passkey.publicKeyPem,
    signature: approval.signature,
    challengeText: approval.challengeText.replace('3000000000000000000000000', '9000000000000000000000000'),
  });
  assert.equal(tamperedAmountCheck.valid, false);
});

test('Passkey - Rejects corrupted signature', async () => {
  const passkey = await createSupervisorPasskey();

  const approval = await signEscalationWithPasskey({
    actionId: 1,
    targetContract: 'wrap.near',
    amount: '1000',
    credentialId: passkey.credentialId,
    privateKey: passkey.privateKey,
  });

  const corruptedSignature = approval.signature.slice(0, -4) + 'abcd';
  const check = verifyPasskeyApproval({
    publicKeyPem: passkey.publicKeyPem,
    signature: corruptedSignature,
    challengeText: approval.challengeText,
  });

  assert.equal(check.valid, false);
});

test('Passkey - AgentGuard registers supervisor passkey and signs escalation approval', async () => {
  const guard = new AgentGuard();

  const passkey = await guard.registerSupervisorPasskey({
    username: 'alice.near',
    displayName: 'Alice Supervisor',
  });

  assert.ok(passkey.credentialId);
  assert.equal(guard.supervisorPasskey, passkey);

  const approval = await guard.signEscalationWithPasskey(7, {
    targetContract: 'v2.ref-finance.near',
    amount: '4000000000000000000000000',
  });

  assert.equal(approval.actionId, 7);
  assert.ok(approval.signature);

  const verification = guard.verifyPasskeyApproval({
    publicKeyPem: passkey.publicKeyPem,
    signature: approval.signature,
    challengeText: approval.challengeText,
  });

  assert.equal(verification.valid, true);
});

test('Passkey - AgentGuard syncs supervisor passkey hash to NEAR smart contract', async () => {
  let calledContractMethod = null;
  let calledArgs = null;

  const mockAccount = {
    callFunction: async ({ contractId, methodName, args }) => {
      calledContractMethod = methodName;
      calledArgs = args;
      return { transaction: { hash: 'mock_tx_passkey_anchor' } };
    },
  };

  const guard = new AgentGuard({
    contractId: 'vault.alice.near',
    account: mockAccount,
  });

  const passkey = await guard.registerSupervisorPasskey({
    syncToContract: true,
  });

  assert.equal(passkey.syncedToContract, true);
  assert.equal(calledContractMethod, 'set_supervisor_passkey_public_key');
  assert.equal(calledArgs.public_key_hex, passkey.publicKeyHex);
  assert.equal(passkey.publicKeyHex.length, 130);
});

test('Passkey - Contract-canonical signing verifies and rejects tampered amount', async () => {
  const passkey = await createSupervisorPasskey();
  assert.equal(passkey.publicKeyHex.length, 130);

  const approval = await signEscalationWithPasskey({
    actionId: 3,
    targetContract: 'wrap.near',
    method: 'ft_transfer',
    args: '{"receiver_id":"bob.near","amount":"5000000000000000000000000"}',
    amount: '5000000000000000000000000',
    credentialId: passkey.credentialId,
    privateKey: passkey.privateKey,
  });

  assert.equal(
    approval.challengeText,
    'AgentGuard:ApproveAction:3:wrap.near:ft_transfer:{"receiver_id":"bob.near","amount":"5000000000000000000000000"}:5000000000000000000000000',
  );
  const ok = verifyPasskeyApproval({
    publicKeyPem: passkey.publicKeyPem,
    signature: approval.signature,
    challengeText: approval.challengeText,
  });
  assert.equal(ok.valid, true);

  const tampered = verifyPasskeyApproval({
    publicKeyPem: passkey.publicKeyPem,
    signature: approval.signature,
    challengeText: approval.challengeText.replace('5000000000000000000000000', '9000000000000000000000000'),
  });
  assert.equal(tampered.valid, false);
});

test('Passkey - AgentGuard approveEscalatedWithPasskey dispatches on-chain call with passkey signature', async () => {
  let dispatchedMethod = null;
  let dispatchedArgs = null;

  const mockAccount = {
    callFunction: async ({ contractId, methodName, args }) => {
      dispatchedMethod = methodName;
      dispatchedArgs = args;
      return { transaction: { hash: 'mock_tx_escalation_approved' } };
    },
  };

  const guard = new AgentGuard({
    contractId: 'vault.alice.near',
    account: mockAccount,
  });

  const passkeySig = '3045022100abc123...mock_p256_signature';
  await guard.approveEscalatedWithPasskey(12, passkeySig);

  assert.equal(dispatchedMethod, 'approve_escalated');
  assert.equal(dispatchedArgs.action_id, 12);
  assert.equal(dispatchedArgs.passkey_signature, passkeySig);
});
