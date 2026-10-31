/**
 * AgentGuard Cryptographic AI Firewall Attestation
 * Binds off-chain Claude AI Firewall approvals directly to on-chain smart contract execution,
 * eliminating the "Firewall Bypass" vulnerability via Ed25519 digital signatures.
 */

import crypto from 'node:crypto';

/**
 * Generates an Ed25519 keypair for the AI Firewall signer.
 */
export function createFirewallKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  
  // Export raw public key in NEAR format (ed25519:<base58>)
  const rawPub = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  
  return {
    publicKey,
    privateKey,
    rawPublicKeyBytes: rawPub,
  };
}

/**
 * Computes the canonical message digest for an intent.
 */
export function computeIntentDigest({ target, method, args, amount, timestampMs, nonce = 0 }) {
  const argsStr = typeof args === 'string' ? args : JSON.stringify(args || {});
  const amountStr = (amount || '0').toString();
  const rawString = `${target}:${method}:${argsStr}:${amountStr}:${timestampMs}:${nonce}`;
  return crypto.createHash('sha256').update(rawString).digest();
}

/**
 * Signs an AI firewall attestation over an approved intent.
 */
export function signFirewallAttestation({
  target,
  method,
  args,
  amount,
  threatScore,
  privateKey,
  timestampMs = Date.now(),
  nonce = Math.floor(Math.random() * 1_000_000_000_000),
}) {
  const digest = computeIntentDigest({ target, method, args, amount, timestampMs, nonce });
  const signatureBuffer = crypto.sign(null, digest, privateKey);

  return {
    threat_score: threatScore,
    timestamp_ms: timestampMs,
    nonce,
    signature: signatureBuffer.toString('hex'),
  };
}

/**
 * Verifies a firewall attestation off-chain against a public key.
 */
export function verifyFirewallAttestation({
  target,
  method,
  args,
  amount,
  attestation,
  publicKey,
  maxAgeMs = 300_000,
}) {
  if (!attestation || !attestation.signature || typeof attestation.timestamp_ms !== 'number') {
    return { valid: false, reason: 'Malformed attestation object' };
  }

  // Freshness check
  const now = Date.now();
  if (now < attestation.timestamp_ms || (now - attestation.timestamp_ms) > maxAgeMs) {
    return { valid: false, reason: 'Attestation timestamp expired or in future' };
  }

  const digest = computeIntentDigest({
    target,
    method,
    args,
    amount,
    timestampMs: attestation.timestamp_ms,
    nonce: attestation.nonce || 0,
  });

  const sigBuffer = Buffer.from(attestation.signature, 'hex');
  const isValid = crypto.verify(null, digest, publicKey, sigBuffer);

  return {
    valid: isValid,
    reason: isValid ? 'Signature valid' : 'Cryptographic signature mismatch',
  };
}
