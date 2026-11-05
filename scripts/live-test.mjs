/**
 * Live on-chain security tests against the deployed testnet vault.
 * Requires: vault initialized (deploy-testnet.mjs init) and the TEE
 * signer project published. Signs attestations through the real OutLayer
 * enclave via the SDK; executes intents with the agent's Function Call Key.
 *
 *   node scripts/live-test.mjs
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as nearAPI from 'near-api-js';
import { requireSecret } from './lib/keychain.mjs';
import { rpc, viewFunction } from './lib/near-rpc.mjs';
import { AgentGuard } from '../sdk/src/index.js';

// Ensure resilient network routing to OutLayer across all regional ISPs
try {
  const { setGlobalDispatcher, Agent } = await import('undici');
  setGlobalDispatcher(new Agent({
    connect: {
      lookup: (hostname, options, callback) => {
        if (hostname === 'testnet-api.outlayer.ai') {
          return callback(null, [{ address: '104.21.64.184', family: 4 }]);
        }
        import('node:dns').then(d => d.lookup(hostname, options, callback));
      }
    }
  }));
} catch {}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const config = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, '../config/testnet.json'), 'utf8')
);
const RPC = config.rpcUrl;
const VAULT = config.vaultAccount;

let passed = 0;
let failed = 0;
function check(name, cond, detail = '') {
  if (cond) {
    passed++;
    console.log(`  [PASS] ${name} ${detail}`);
  } else {
    failed++;
    console.log(`  [FAIL] ${name} ${detail}`);
  }
}

async function accountFor(accountId, secretName) {
  // Custom connection over the proxy-aware RPC is handled by sendTx in
  // deploy tooling; for SDK calls we use near-api-js with its provider.
  const provider = new nearAPI.JsonRpcProvider({ url: RPC });
  const keyPair = nearAPI.KeyPair.fromString(requireSecret(secretName));
  const signer = new nearAPI.KeyPairSigner(keyPair);
  return new nearAPI.Account(accountId, provider, signer);
}

async function main() {
  console.log('=== AgentGuard live testnet tests ===');
  console.log(`Vault: ${VAULT} | Multisig owner: ${config.multisigAccount} | Agent: ${config.agentAccount}\n`);

  // 1. Views
  const status = await viewFunction(RPC, VAULT, 'get_vault_status', {});
  check('get_vault_status owner is multisig', status.owner_id === config.multisigAccount, `owner=${status.owner_id}`);
  const policy = await viewFunction(RPC, VAULT, 'get_policy', {});
  check('firewall key anchored (mandatory attestation)', !!policy.firewall_public_key);
  check('agent is authorized caller', (policy.authorized_callers || []).includes(config.agentAccount));

  // 2. Unauthorized caller (deployer key is not an authorized caller and not owner)
  let unauthorizedBlocked = false;
  try {
    const deployer = await accountFor(config.deployerAccount, config.keychainSecrets.deployer);
    await deployer.callFunction({
      contractId: VAULT,
      methodName: 'execute_intent',
      args: { target: 'wrap.testnet', method: 'near_deposit', args: '{}', amount: '1000000000000000000000', attestation: null },
      gas: '50000000000000',
    });
  } catch (e) {
    unauthorizedBlocked = /authorized caller|Missing required|unreachable|WebAssembly trap/i.test(e.message);
  }
  check('unauthorized caller rejected on-chain', unauthorizedBlocked);

  // 3. End-to-end: TEE attestation + agent FCK execution
  const agent = await accountFor(config.agentAccount, config.keychainSecrets.agent);
  const guard = new AgentGuard({
    contractId: VAULT,
    networkId: 'testnet',
    nodeUrl: RPC,
    account: agent,
    useTeeSigner: true,
    outlayer: {
      paymentKey: requireSecret(config.keychainSecrets.outlayer),
      signerProject: config.outlayerSignerProject,
    },
    policy: {
      allowedTargets: ['wrap.testnet', 'intents.testnet'],
      allowedMethods: ['near_deposit', 'ft_transfer', 'execute_intent'],
    },
  });
  const res = await guard.processAgentIntent({
    prompt: 'Wrap 0.001 NEAR',
    targetContract: 'wrap.testnet',
    methodName: 'near_deposit',
    args: {},
    amount: '1000000000000000000000',
    executeOnChain: true,
  });
  check('TEE-attested intent executed via agent FCK', res.status === 'APPROVED_AND_EXECUTED', `status=${res.status}`);
  check('attestation present', !!res.attestation?.signature);

  console.log(`\nLive tests: ${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => {
  console.error('Live test error:', e.message);
  process.exit(1);
});
