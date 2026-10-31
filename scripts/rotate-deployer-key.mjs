/**
 * Rotate the deployer account's FullAccess key.
 * The old key was previously stored in a plaintext .env (now migrated to
 * Keychain). This script:
 *   1. Generates a fresh keypair in memory.
 *   2. Adds it as FullAccess, signed by the old key.
 *   3. Stores the new private key in macOS Keychain.
 *   4. Deletes the old key on-chain, signed by the new key.
 *   5. Verifies the old key no longer exists.
 * Abort-safe: the old key is only deleted after the new key is stored.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getSecret, setSecret, requireSecret } from './lib/keychain.mjs';
import { rpc } from './lib/near-rpc.mjs';
import { sendTx, act, generateKeyPair } from './lib/near-tx.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const config = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, '../config/testnet.json'), 'utf8')
);
const RPC = config.rpcUrl;
const ACCOUNT = config.deployerAccount;

async function listKeys() {
  const res = await rpc(RPC, 'query', {
    request_type: 'view_access_key_list',
    account_id: ACCOUNT,
    finality: 'final',
  });
  return res.keys.map((k) => k.public_key);
}

async function main() {
  const oldPrivate = requireSecret(
    config.keychainSecrets.deployer,
    'Run scripts/migrate-secrets.sh first.'
  );
  const { KeyPair } = await import('near-api-js');
  const oldPublic = KeyPair.fromString(oldPrivate).getPublicKey().toString();

  const before = await listKeys();
  console.log(`Account ${ACCOUNT} keys before: ${before.join(', ')}`);
  if (!before.includes(oldPublic)) {
    throw new Error('Keychain deployer key does not match any on-chain access key. Aborting.');
  }

  const fresh = generateKeyPair();
  console.log(`Generated replacement key: ${fresh.publicKey}`);

  console.log('[1/3] Adding new FullAccess key (signed by old key)...');
  await sendTx({
    rpcUrl: RPC,
    signerId: ACCOUNT,
    privateKey: oldPrivate,
    receiverId: ACCOUNT,
    actions: [act.addFullAccessKey(fresh.publicKey)],
  });

  setSecret(config.keychainSecrets.deployer, fresh.privateKey);
  console.log('      New private key stored in Keychain.');

  console.log('[2/3] Deleting old key (signed by new key)...');
  await sendTx({
    rpcUrl: RPC,
    signerId: ACCOUNT,
    privateKey: fresh.privateKey,
    receiverId: ACCOUNT,
    actions: [act.deleteKey(oldPublic)],
  });

  console.log('[3/3] Verifying rotation...');
  const after = await listKeys();
  console.log(`Keys after: ${after.join(', ')}`);
  if (after.includes(oldPublic)) throw new Error('Old key still present on-chain!');
  if (!after.includes(fresh.publicKey)) throw new Error('New key missing on-chain!');
  console.log('Rotation complete. The previously exposed key is revoked.');
}

main().catch((e) => {
  console.error('Rotation failed:', e.message);
  process.exit(1);
});
