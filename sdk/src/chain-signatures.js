/**
 * AgentGuard NEAR Chain Signatures Adapter
 * Enables autonomous AI agents to control native EVM (Base, Ethereum, Arbitrum)
 * and Bitcoin accounts via NEAR's decentralized Threshold MPC network (v1.signer).
 */

import * as nearAPI from 'near-api-js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { ripemd160 } from '@noble/hashes/legacy.js';

export const MPC_CONTRACTS = {
  mainnet: {
    contractId: 'v1.signer',
    rootPublicKey: 'secp256k1:3tFRbMqmoa6AAALMrEFAYCEoHcqKxeW38YptwowBVBtXK1vo36HDbUWuR6EZmoK4JcH6HDkNMGGqP1ouV7VZUWya',
  },
  testnet: {
    contractId: 'v1.signer-prod.testnet',
    rootPublicKey: 'secp256k1:4NfTiv3UsGahebgTaHyD9vF8KYKMBnfd6kh94mK6xv8fGBiJB8TBtFMP5WWXz6B89Ac1fbpzPwAvoyQebemHFwx3',
  },
};

export const EVM_CHAIN_IDS = {
  ethereum: 1,
  base: 8453,
  arbitrum: 42161,
  optimism: 10,
  polygon: 137,
  sepolia: 11155111,
  'base-sepolia': 84532,
  'arbitrum-sepolia': 421614,
};

/**
 * Applies EIP-55 mixed-case checksum formatting to an EVM hex address.
 * @param {string} address - 40-character hex address without 0x
 * @returns {string} Checksummed address with 0x prefix
 */
export function toChecksumAddress(address) {
  const clean = address.toLowerCase().replace(/^0x/, '');
  const hash = Buffer.from(keccak_256(Buffer.from(clean, 'ascii'))).toString('hex');
  let ret = '0x';
  for (let i = 0; i < clean.length; i++) {
    if (parseInt(hash[i], 16) >= 8) {
      ret += clean[i].toUpperCase();
    } else {
      ret += clean[i];
    }
  }
  return ret;
}

/**
 * Derives the child secp256k1 public key using NEAR Chain Signatures MPC algorithm:
 * epsilon = sha256("near-mpc-recovery v0.1.0 epsilon derivation:" + accountId + "," + path)
 * childPoint = rootPoint + epsilon * G
 *
 * @param {Object} params
 * @param {string} params.rootPublicKey - NEAR root public key format (secp256k1:...)
 * @param {string} params.accountId - NEAR account ID (e.g. agent.near)
 * @param {string} [params.path] - Derivation path (e.g. "ethereum,1" or "base,1")
 * @returns {{ point: Object, uncompressedBytes: Uint8Array, compressedBytes: Uint8Array, publicKeyHex: string }}
 */
export function deriveChildPublicKey({ rootPublicKey, accountId, path = 'ethereum,1' }) {
  if (!rootPublicKey || !accountId) {
    throw new Error('rootPublicKey and accountId are required for key derivation');
  }

  const pk = nearAPI.PublicKey.fromString(rootPublicKey);
  const fullHex = '04' + Buffer.from(pk.data).toString('hex');
  const rootPoint = secp256k1.Point.fromHex(fullHex);

  const derivationStr = `near-mpc-recovery v0.1.0 epsilon derivation:${accountId},${path}`;
  const hashBytes = sha256(Buffer.from(derivationStr, 'utf8'));
  const scalar = BigInt('0x' + Buffer.from(hashBytes).toString('hex')) % secp256k1.Point.Fn.ORDER;
  const offsetPoint = secp256k1.Point.BASE.multiply(scalar);
  const childPoint = rootPoint.add(offsetPoint);

  const uncompressedBytes = childPoint.toBytes(false); // 65 bytes (0x04 || X || Y)
  const compressedBytes = childPoint.toBytes(true);     // 33 bytes (0x02/0x03 || X)

  return {
    point: childPoint,
    uncompressedBytes,
    compressedBytes,
    publicKeyHex: Buffer.from(uncompressedBytes).toString('hex'),
  };
}

/**
 * Derives a deterministic foreign blockchain address (EVM or Bitcoin) from a NEAR account.
 *
 * @param {Object} params
 * @param {string} [params.rootPublicKey] - Optional custom root MPC key
 * @param {string} params.accountId - The agent's NEAR account ID
 * @param {string} [params.path] - Derivation path (e.g. "ethereum,1" or "base,1")
 * @param {string} [params.chain] - Target chain ('base', 'ethereum', 'arbitrum', 'bitcoin')
 * @param {string} [params.networkId] - 'mainnet' or 'testnet' (default: 'testnet')
 * @returns {Object} Derived address metadata
 */
export function deriveForeignAddress({
  rootPublicKey = null,
  accountId,
  path = 'ethereum,1',
  chain = 'base',
  networkId = 'testnet',
}) {
  const rootPk = rootPublicKey || MPC_CONTRACTS[networkId]?.rootPublicKey;
  if (!rootPk) {
    throw new Error(`Unsupported networkId: ${networkId}`);
  }

  const normalizedChain = chain.toLowerCase();
  const { uncompressedBytes, compressedBytes, publicKeyHex } = deriveChildPublicKey({
    rootPublicKey: rootPk,
    accountId,
    path,
  });

  // EVM Address Derivation (Ethereum, Base, Arbitrum, Polygon, Optimism)
  if (['base', 'ethereum', 'arbitrum', 'optimism', 'polygon', 'sepolia', 'base-sepolia', 'arbitrum-sepolia'].includes(normalizedChain)) {
    // Keccak-256 of 64-byte uncompressed point without 0x04 prefix
    const rawPoint = uncompressedBytes.slice(1);
    const hash = keccak_256(rawPoint);
    const addressBytes = hash.slice(-20);
    const addressHex = Buffer.from(addressBytes).toString('hex');
    const checksummedAddress = toChecksumAddress(addressHex);

    return {
      chain: normalizedChain,
      address: checksummedAddress,
      path,
      accountId,
      networkId,
      publicKeyHex,
      chainId: EVM_CHAIN_IDS[normalizedChain] || 1,
    };
  }

  // Bitcoin Address Derivation (P2PKH & Native SegWit)
  if (normalizedChain === 'bitcoin' || normalizedChain === 'btc') {
    const sha = sha256(compressedBytes);
    const ripemd = ripemd160(sha);

    // Legacy P2PKH Base58Check Address
    const versionByte = networkId === 'mainnet' ? 0x00 : 0x6f;
    const payload = Buffer.concat([Buffer.from([versionByte]), Buffer.from(ripemd)]);
    const checksum = sha256(sha256(payload)).slice(0, 4);
    const fullP2pkh = Buffer.concat([payload, Buffer.from(checksum)]);
    const legacyAddress = nearAPI.baseEncode(fullP2pkh);

    return {
      chain: 'bitcoin',
      address: legacyAddress,
      legacyAddress,
      hash160Hex: Buffer.from(ripemd).toString('hex'),
      path,
      accountId,
      networkId,
      publicKeyHex,
    };
  }

  throw new Error(`Unsupported chain for derivation: ${chain}`);
}

/**
 * Lightweight recursive RLP encoder for EIP-1559 and legacy EVM transactions.
 * @param {any} input
 * @returns {Buffer} RLP encoded buffer
 */
export function rlpEncode(input) {
  if (Array.isArray(input)) {
    const output = Buffer.concat(input.map(rlpEncode));
    return Buffer.concat([encodeRlpLength(output.length, 192), output]);
  }

  let buf;
  if (Buffer.isBuffer(input)) {
    buf = input;
  } else if (typeof input === 'bigint' || typeof input === 'number') {
    if (input === 0 || input === 0n) {
      buf = Buffer.alloc(0);
    } else {
      let h = input.toString(16);
      if (h.length % 2 !== 0) h = '0' + h;
      buf = Buffer.from(h, 'hex');
    }
  } else if (typeof input === 'string' && input.startsWith('0x')) {
    const clean = input.slice(2);
    buf = Buffer.from(clean.length % 2 !== 0 ? '0' + clean : clean, 'hex');
  } else {
    buf = Buffer.from(input || '');
  }

  if (buf.length === 1 && buf[0] < 128) {
    return buf;
  }
  return Buffer.concat([encodeRlpLength(buf.length, 128), buf]);
}

function encodeRlpLength(len, offset) {
  if (len < 56) {
    return Buffer.from([len + offset]);
  }
  const hexLen = len.toString(16);
  const lBuf = Buffer.from(hexLen.length % 2 === 0 ? hexLen : '0' + hexLen, 'hex');
  return Buffer.concat([Buffer.from([offset + 55 + lBuf.length]), lBuf]);
}

/**
 * Prepares and hashes an EIP-1559 transaction for NEAR Chain Signature signing.
 *
 * @param {Object} txParams
 * @param {string} txParams.to - Recipient EVM address (0x...)
 * @param {bigint|string|number} [txParams.value] - Amount in wei
 * @param {string} [txParams.data] - Contract call data (0x...)
 * @param {number} [txParams.nonce] - Account nonce
 * @param {bigint|string|number} [txParams.gasLimit] - Gas limit (default: 21000)
 * @param {bigint|string|number} [txParams.maxFeePerGas] - Max fee in wei
 * @param {bigint|string|number} [txParams.maxPriorityFeePerGas] - Max priority fee in wei
 * @param {number} [txParams.chainId] - EVM chain ID (default: 8453 for Base)
 * @returns {{ hashHex: string, hashArray: number[], unsignedSerializedHex: string }}
 */
export function buildEvmTransaction({
  to,
  value = 0n,
  data = '0x',
  nonce = 0,
  gasLimit = 21000,
  maxFeePerGas = 2000000000n,
  maxPriorityFeePerGas = 1000000000n,
  chainId = 8453,
}) {
  if (!to || !to.startsWith('0x') || to.length !== 42) {
    throw new Error(`Invalid destination address: ${to}`);
  }

  const unsignedItems = [
    BigInt(chainId),
    BigInt(nonce),
    BigInt(maxPriorityFeePerGas),
    BigInt(maxFeePerGas),
    BigInt(gasLimit),
    to,
    BigInt(value),
    data,
    [], // Access list
  ];

  const rlpPayload = rlpEncode(unsignedItems);
  const envelope = Buffer.concat([Buffer.from([0x02]), rlpPayload]);
  const hash = Buffer.from(keccak_256(envelope));

  return {
    chainId,
    nonce: Number(nonce),
    to,
    value: BigInt(value).toString(),
    data,
    gasLimit: Number(gasLimit),
    maxFeePerGas: BigInt(maxFeePerGas).toString(),
    maxPriorityFeePerGas: BigInt(maxPriorityFeePerGas).toString(),
    unsignedEnvelope: envelope,
    unsignedSerializedHex: '0x' + envelope.toString('hex'),
    hashHex: '0x' + hash.toString('hex'),
    hashArray: Array.from(hash), // 32 bytes array of integers (0..255) for NEAR contract
  };
}

/**
 * Reassembles an EIP-1559 transaction with the threshold signature from NEAR MPC.
 *
 * @param {Object} params
 * @param {Object} params.unsignedTx - Output of buildEvmTransaction
 * @param {string|Object} params.bigR - Affine point or hex of big_r from v1.signer
 * @param {string|Object} params.s - Scalar s from v1.signer
 * @param {number} params.recoveryId - 0 or 1
 * @returns {string} Fully signed raw transaction hex (ready for eth_sendRawTransaction)
 */
export function assembleSignedEvmTransaction({ unsignedTx, bigR, s, recoveryId }) {
  let rHex = typeof bigR === 'string' ? bigR : (bigR.affine_point || bigR.scalar || '');
  let sHex = typeof s === 'string' ? s : (s.scalar || '');

  // Strip leading prefixes if present
  rHex = rHex.replace(/^0x/, '');
  sHex = sHex.replace(/^0x/, '');

  // Affine point might be 33-byte compressed (02/03 + 32-byte X coordinate)
  if (rHex.length === 66 && (rHex.startsWith('02') || rHex.startsWith('03'))) {
    rHex = rHex.slice(2);
  }

  const rBuf = Buffer.from(rHex, 'hex');
  const sBuf = Buffer.from(sHex, 'hex');
  const recId = Number(recoveryId);

  const signedItems = [
    BigInt(unsignedTx.chainId),
    BigInt(unsignedTx.nonce),
    BigInt(unsignedTx.maxPriorityFeePerGas),
    BigInt(unsignedTx.maxFeePerGas),
    BigInt(unsignedTx.gasLimit),
    unsignedTx.to,
    BigInt(unsignedTx.value),
    unsignedTx.data,
    [], // Access list
    recId,
    rBuf,
    sBuf,
  ];

  const signedRlp = rlpEncode(signedItems);
  const signedEnvelope = Buffer.concat([Buffer.from([0x02]), signedRlp]);

  return '0x' + signedEnvelope.toString('hex');
}

/**
 * High-Level NEAR Chain Signatures Orchestrator for AgentGuard
 */
export class ChainSignatures {
  constructor(options = {}) {
    this.networkId = options.networkId || 'testnet';
    this.mpcContractId = options.mpcContractId || MPC_CONTRACTS[this.networkId]?.contractId || 'v1.signer-prod.testnet';
    this.rootPublicKey = options.rootPublicKey || MPC_CONTRACTS[this.networkId]?.rootPublicKey;
    this.vaultContractId = options.vaultContractId || options.contractId || null;
    this.account = options.account || null;
  }

  /**
   * Derives foreign addresses across Base, Ethereum, Arbitrum, or Bitcoin for any NEAR account.
   */
  deriveAddress({ accountId, path = 'ethereum,1', chain = 'base' }) {
    return deriveForeignAddress({
      rootPublicKey: this.rootPublicKey,
      accountId,
      path,
      chain,
      networkId: this.networkId,
    });
  }

  /**
   * Builds an EIP-1559 transaction on the target EVM chain and computes its 32-byte Keccak-256 hash.
   */
  prepareEvmTransaction(txParams) {
    return buildEvmTransaction(txParams);
  }

  /**
   * Assembles the final raw signed EVM transaction from MPC signature coordinates.
   */
  assembleSignedTransaction(params) {
    return assembleSignedEvmTransaction(params);
  }

  /**
   * Dispatches an MPC signing request through the AgentGuard on-chain vault on NEAR.
   * If running locally or without live NEAR account, simulates or executes via RPC.
   */
  async requestSignature({
    payload,
    path = 'ethereum,1',
    keyVersion = 0,
    foreignChain = 'base',
    estimatedAmount = '0',
    attestation = null,
  }) {
    if (!this.account || !this.vaultContractId) {
      throw new Error(
        'ChainSignatures: live NEAR account and AgentGuard vault contract required for MPC signing. Refusing to fabricate a signature.'
      );
    }

    // Call request_chain_signature on the AgentGuard vault contract
    const hashArray = Array.isArray(payload) ? payload : Array.from(Buffer.from(payload.replace(/^0x/, ''), 'hex'));
    if (hashArray.length !== 32) {
      throw new Error(`Payload must be exactly 32 bytes, got ${hashArray.length}`);
    }

    const callArgs = {
      contractId: this.vaultContractId,
      methodName: 'request_chain_signature',
      args: {
        payload: hashArray,
        path,
        key_version: keyVersion,
        foreign_chain: foreignChain,
        estimated_amount: estimatedAmount ? estimatedAmount.toString() : null,
        attestation,
      },
      gas: '280000000000000', // 280 TGas
      attachedDeposit: '50000000000000000000000', // 0.05 NEAR required by MPC
    };

    const outcome = typeof this.account.callFunction === 'function'
      ? await this.account.callFunction(callArgs)
      : await this.account.functionCall(callArgs);

    // Extract the MPC signature coordinates from the receipt's SuccessValue.
    // v1.signer returns { big_r: { affine_point: "03..." }, s: { scalar: "..." }, recovery_id: 0|1 }
    let mpcSignature = null;
    try {
      const receipts = outcome?.receipts_outcome || [];
      for (const receipt of receipts) {
        const sv = receipt?.outcome?.status?.SuccessValue;
        if (sv) {
          const decoded = JSON.parse(Buffer.from(sv, 'base64').toString('utf8'));
          if (decoded && (decoded.big_r || decoded.Big_r)) {
            mpcSignature = {
              big_r: decoded.big_r || decoded.Big_r,
              s: decoded.s || decoded.S,
              recovery_id: decoded.recovery_id ?? decoded.recoveryId ?? 0,
            };
            break;
          }
        }
      }
      // Also check the top-level status SuccessValue (some RPC versions surface it there)
      if (!mpcSignature) {
        const topSv = outcome?.status?.SuccessValue;
        if (topSv) {
          const decoded = JSON.parse(Buffer.from(topSv, 'base64').toString('utf8'));
          if (decoded && (decoded.big_r || decoded.Big_r)) {
            mpcSignature = {
              big_r: decoded.big_r || decoded.Big_r,
              s: decoded.s || decoded.S,
              recovery_id: decoded.recovery_id ?? decoded.recoveryId ?? 0,
            };
          }
        }
      }
    } catch (_) {}

    return {
      success: true,
      transactionHash: outcome?.transaction?.hash || outcome?.transaction_outcome?.id,
      // Surface MPC signature fields at the top level for downstream assembly
      ...(mpcSignature || {}),
      outcome,
    };
  }
}
