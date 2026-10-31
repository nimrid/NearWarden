import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AgentGuard,
  ChainSignatures,
  deriveForeignAddress,
  deriveChildPublicKey,
  buildEvmTransaction,
  assembleSignedEvmTransaction,
  toChecksumAddress,
  MPC_CONTRACTS,
  EVM_CHAIN_IDS,
} from '../src/index.js';

test('ChainSignatures - Derives deterministic EVM addresses from testnet MPC root key', () => {
  const rootPk = MPC_CONTRACTS.testnet.rootPublicKey;
  const res1 = deriveForeignAddress({
    rootPublicKey: rootPk,
    accountId: 'agent-trader.testnet',
    path: 'ethereum,1',
    chain: 'base',
    networkId: 'testnet',
  });

  assert.equal(res1.chain, 'base');
  assert.equal(res1.chainId, EVM_CHAIN_IDS.base);
  assert.match(res1.address, /^0x[0-9a-fA-F]{40}$/);
  // Re-deriving with identical parameters produces identical address
  const res2 = deriveForeignAddress({
    rootPublicKey: rootPk,
    accountId: 'agent-trader.testnet',
    path: 'ethereum,1',
    chain: 'base',
    networkId: 'testnet',
  });
  assert.equal(res1.address, res2.address);
});

test('ChainSignatures - Derives distinct addresses for different account IDs and derivation paths', () => {
  const rootPk = MPC_CONTRACTS.testnet.rootPublicKey;

  const addrA = deriveForeignAddress({
    rootPublicKey: rootPk,
    accountId: 'agent-alice.testnet',
    path: 'ethereum,1',
    chain: 'base',
  });

  const addrB = deriveForeignAddress({
    rootPublicKey: rootPk,
    accountId: 'agent-bob.testnet',
    path: 'ethereum,1',
    chain: 'base',
  });

  const addrAPath2 = deriveForeignAddress({
    rootPublicKey: rootPk,
    accountId: 'agent-alice.testnet',
    path: 'ethereum,2',
    chain: 'base',
  });

  assert.notEqual(addrA.address, addrB.address);
  assert.notEqual(addrA.address, addrAPath2.address);
});

test('ChainSignatures - Derives deterministic EVM addresses from mainnet MPC root key', () => {
  const rootPk = MPC_CONTRACTS.mainnet.rootPublicKey;
  const res = deriveForeignAddress({
    rootPublicKey: rootPk,
    accountId: 'production-agent.near',
    path: 'ethereum,1',
    chain: 'arbitrum',
    networkId: 'mainnet',
  });

  assert.equal(res.chain, 'arbitrum');
  assert.equal(res.chainId, EVM_CHAIN_IDS.arbitrum);
  assert.match(res.address, /^0x[0-9a-fA-F]{40}$/);
});

test('ChainSignatures - Derives Bitcoin address with Base58Check encoding', () => {
  const rootPk = MPC_CONTRACTS.testnet.rootPublicKey;
  const res = deriveForeignAddress({
    rootPublicKey: rootPk,
    accountId: 'btc-agent.testnet',
    path: 'bitcoin,1',
    chain: 'bitcoin',
    networkId: 'testnet',
  });

  assert.equal(res.chain, 'bitcoin');
  assert.ok(typeof res.address === 'string' && res.address.length > 20);
  assert.ok(res.hash160Hex && res.hash160Hex.length === 40);
});

test('ChainSignatures - Builds valid EIP-1559 transaction and computes 32-byte Keccak-256 hash', () => {
  const unsignedTx = buildEvmTransaction({
    to: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913',
    value: 1000000000000000n, // 0.001 ETH
    data: '0xa9059cbb',
    nonce: 5,
    gasLimit: 65000,
    maxFeePerGas: 3000000000n,
    maxPriorityFeePerGas: 1000000000n,
    chainId: 8453, // Base
  });

  assert.equal(unsignedTx.chainId, 8453);
  assert.equal(unsignedTx.nonce, 5);
  assert.match(unsignedTx.hashHex, /^0x[0-9a-f]{64}$/);
  assert.equal(unsignedTx.hashArray.length, 32);
  assert.ok(unsignedTx.unsignedSerializedHex.startsWith('0x02'));
});

test('ChainSignatures - Assembles signed EIP-1559 raw transaction with MPC signature coordinates', () => {
  const unsignedTx = buildEvmTransaction({
    to: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913',
    value: 500000000000000n,
    nonce: 1,
    chainId: 8453,
  });

  const bigR = {
    affine_point: '02e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  };
  const s = {
    scalar: '7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0',
  };

  const rawSignedHex = assembleSignedEvmTransaction({
    unsignedTx,
    bigR,
    s,
    recoveryId: 0,
  });

  assert.ok(rawSignedHex.startsWith('0x02'));
  assert.ok(rawSignedHex.length > unsignedTx.unsignedSerializedHex.length);
});

test('AgentGuard - Seamlessly exposes deriveForeignAddress and executeMultiChainEvm', async () => {
  const guard = new AgentGuard({
    policy: {
      dailySpendingCap: '10000000000000000000000000',
      perTxCap: '2000000000000000000000000',
    },
  });

  // 1. Derive foreign Base address
  const foreignAddr = guard.deriveForeignAddress({
    accountId: 'autonomous-hedge-fund.near',
    path: 'ethereum,1',
    chain: 'base',
  });
  assert.equal(foreignAddr.chain, 'base');
  assert.match(foreignAddr.address, /^0x[0-9a-fA-F]{40}$/);

  // 2. Multi-chain EVM execution without live credentials fails closed
  // Without a live NEAR account + vault, MPC signing must fail closed
  // rather than fabricate a signature.
  await assert.rejects(async () => {
    await guard.executeMultiChainEvm({
      evmTx: {
        to: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913',
        value: 100000000000000n,
        chainId: 8453,
        nonce: 0,
      },
      path: 'ethereum,1',
      foreignChain: 'base',
      estimatedAmount: '100000000000000000000000',
    });
  }, /Refusing to fabricate a signature/);
});
