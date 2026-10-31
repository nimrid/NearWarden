/**
 * Offline NEAR transaction signing + broadcast (near-api-js v7 API).
 * Signs locally with a KeyPair (key material supplied by the caller from
 * the Keychain, never from disk) and broadcasts via near-rpc.mjs.
 */
import * as nearAPI from 'near-api-js';
import { createHash } from 'node:crypto';
import { rpc } from './near-rpc.mjs';

const { actions, createTransaction, encodeTransaction, KeyPair, PublicKey, Signature, SignedTransaction, baseDecode } = nearAPI;

export async function sendTx({ rpcUrl, signerId, privateKey, receiverId, actions: txActions }) {
  const keyPair = KeyPair.fromString(privateKey);
  const publicKey = keyPair.getPublicKey();

  const accessKey = await rpc(rpcUrl, 'query', {
    request_type: 'view_access_key',
    account_id: signerId,
    public_key: publicKey.toString(),
    finality: 'final',
  });
  const block = await rpc(rpcUrl, 'block', { finality: 'final' });
  const nonce = BigInt(accessKey.nonce) + 1n;
  const blockHash = baseDecode(block.header.hash);

  const tx = createTransaction(signerId, publicKey, receiverId, nonce, txActions, blockHash);
  const txHash = createHash('sha256').update(encodeTransaction(tx)).digest();
  const { signature: signatureBytes } = keyPair.sign(txHash);
  const signedTx = new SignedTransaction({
    transaction: tx,
    signature: new Signature({ keyType: publicKey.keyType, data: signatureBytes }),
  });

  const outcome = await rpc(rpcUrl, 'broadcast_tx_commit', [
    Buffer.from(signedTx.encode()).toString('base64'),
  ]);
  const failure = findFailure(outcome);
  if (failure) {
    throw new Error(`Transaction ${outcome.transaction?.hash || ''} failed: ${failure}`);
  }
  return outcome;
}

function findFailure(outcome) {
  const check = (status) => {
    if (status && typeof status === 'object' && status.Failure) {
      return JSON.stringify(status.Failure).slice(0, 600);
    }
    return null;
  };
  return (
    check(outcome?.status) ||
    check(outcome?.transaction_outcome?.outcome?.status) ||
    (outcome?.receipts_outcome || [])
      .map((r) => check(r.outcome?.status))
      .find(Boolean) ||
    null
  );
}

export const act = {
  createAccount: () => actions.createAccount(),
  deployContract: (bytes) => actions.deployContract(bytes),
  functionCall: (method, args, gas, deposit) =>
    actions.functionCall(method, typeof args === 'string' ? Buffer.from(args) : args, BigInt(gas), BigInt(deposit)),
  transfer: (amount) => actions.transfer(BigInt(amount)),
  addFullAccessKey: (publicKeyStr) => actions.addFullAccessKey(PublicKey.fromString(publicKeyStr)),
  addFunctionCallKey: (publicKeyStr, contractId, methodNames, allowance) =>
    actions.addFunctionCallAccessKey(PublicKey.fromString(publicKeyStr), contractId, methodNames, BigInt(allowance)),
  deleteKey: (publicKeyStr) => actions.deleteKey(PublicKey.fromString(publicKeyStr)),
};

export function generateKeyPair() {
  const kp = KeyPair.fromRandom('ed25519');
  return { publicKey: kp.getPublicKey().toString(), privateKey: kp.toString() };
}
