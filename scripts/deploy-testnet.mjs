/**
 * AgentGuard testnet deployment — industry-standard custody layout:
 *
 *   - Deployer key lives only in macOS Keychain (see lib/keychain.mjs).
 *   - Vault owner is a 2-of-3 multisig contract (guard.<deployer>).
 *   - Agent account holds ONLY a Function Call Key scoped to the vault's
 *     execute_intent / request_chain_signature; its full-access key is
 *     deleted after provisioning.
 *   - Vault init requires the TEE-derived firewall public key
 *     (config.firewallPublicKey). Publish enclave/firewall-signer as the
 *     OutLayer project first (dashboard), fetch its public key with the
 *     SDK, put it in config/testnet.json, then run the `init` phase.
 *
 * Usage:
 *   node scripts/deploy-testnet.mjs accounts   # members + agent + multisig account
 *   node scripts/deploy-testnet.mjs multisig   # deploy + init multisig contract
 *   node scripts/deploy-testnet.mjs vault      # deploy vault code to deployer account
 *   node scripts/deploy-testnet.mjs init       # init vault (needs firewallPublicKey)
 *   node scripts/deploy-testnet.mjs status     # balances, code hashes, config
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { requireSecret, setSecret, getSecret } from './lib/keychain.mjs';
import { rpc, viewFunction } from './lib/near-rpc.mjs';
import { sendTx, act, generateKeyPair } from './lib/near-tx.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const configPath = path.join(ROOT, 'config/testnet.json');
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
const RPC = config.rpcUrl;
const DEPLOYER = config.deployerAccount;
const GAS = '300000000000000';
const NEAR = 10n ** 24n;

const deployerKey = () => requireSecret(config.keychainSecrets.deployer, 'Run migrate + rotate first.');

async function accountExists(id) {
  try {
    await rpc(RPC, 'query', { request_type: 'view_account', account_id: id, finality: 'final' });
    return true;
  } catch {
    return false;
  }
}

async function createSubaccount(id, secretName, initialYocto) {
  if (await accountExists(id)) {
    console.log(`  exists: ${id}`);
    return;
  }
  let pair;
  const existing = getSecret(secretName);
  if (existing) {
    const { KeyPair } = await import('near-api-js');
    pair = { privateKey: existing, publicKey: KeyPair.fromString(existing).getPublicKey().toString() };
  } else {
    pair = generateKeyPair();
    setSecret(secretName, pair.privateKey);
  }
  await sendTx({
    rpcUrl: RPC,
    signerId: DEPLOYER,
    privateKey: deployerKey(),
    receiverId: id,
    actions: [
      act.createAccount(),
      act.transfer(initialYocto),
      act.addFullAccessKey(pair.publicKey),
    ],
  });
  console.log(`  created: ${id} (key in Keychain: ${secretName})`);
}

async function phaseAccounts() {
  console.log('Creating member + agent subaccounts...');
  const [, m1, m2] = config.memberAccounts;
  await createSubaccount(m1, config.keychainSecrets.member1, (NEAR / 20n).toString());
  await createSubaccount(m2, config.keychainSecrets.member2, (NEAR / 20n).toString());
  await createSubaccount(config.agentAccount, config.keychainSecrets.agent, (NEAR / 20n).toString());
  await createSubaccount(config.multisigAccount, 'multisig-account-key', ((NEAR * 17n) / 10n).toString());
  console.log('Accounts phase complete.');
}

async function phaseMultisig() {
  const wasm = fs.readFileSync(path.join(ROOT, 'contracts/multisig/out/agent_guard_multisig.wasm'));
  const cred = requireSecret('multisig-account-key');
  console.log(`Deploying multisig (${(wasm.length / 1024).toFixed(0)}K) to ${config.multisigAccount}...`);
  await sendTx({
    rpcUrl: RPC,
    signerId: config.multisigAccount,
    privateKey: cred,
    receiverId: config.multisigAccount,
    actions: [
      act.deployContract(wasm),
      act.functionCall(
        'new',
        JSON.stringify({ members: config.memberAccounts, threshold: config.multisigThreshold }),
        '30000000000000',
        '0'
      ),
    ],
  });
  const cfg = await viewFunction(RPC, config.multisigAccount, 'get_config', {});
  console.log('Multisig config:', JSON.stringify(cfg));
}

async function phaseVault() {
  const wasmPath = path.join(ROOT, 'contracts/out/agent_guard_contract.wasm');
  const wasm = fs.readFileSync(wasmPath);
  console.log(`Deploying vault code (${(wasm.length / 1024).toFixed(0)}K) to ${DEPLOYER}...`);
  await sendTx({
    rpcUrl: RPC,
    signerId: DEPLOYER,
    privateKey: deployerKey(),
    receiverId: DEPLOYER,
    actions: [act.deployContract(wasm)],
  });
  console.log('Vault code deployed (not yet initialized).');
}

async function phaseInit() {
  if (!config.firewallPublicKey) {
    throw new Error(
      'config.firewallPublicKey is null. Publish enclave/firewall-signer as OutLayer project ' +
        `"${config.outlayerSignerProject}" (dashboard), fetch the TEE public key via the SDK ` +
        '(OutLayerClient.anchorFirewallKeyInTee), set it in config/testnet.json, then re-run init. ' +
        'The contract refuses initialization without it.'
    );
  }
  const policy = {
    daily_spending_cap: '10000000000000000000000000',
    per_tx_cap: '2000000000000000000000000',
    allowed_targets: ['wrap.testnet', 'intents.testnet', 'v1.signer-prod.testnet'],
    allowed_methods: ['ft_transfer', 'ft_transfer_call', 'execute_intent', 'storage_deposit', 'near_deposit', 'sign'],
    max_velocity_per_hour: 20,
    emergency_frozen: false,
    firewall_public_key: config.firewallPublicKey,
    max_attestation_age_ms: 300000,
    max_threat_score: 75,
    supervisor_passkey_hash: null,
    mpc_contract_id: 'v1.signer-prod.testnet',
    authorized_callers: [config.agentAccount],
    supervisor_passkey_public_key: config.supervisorPasskeyPublicKey || null,
  };
  console.log(`Initializing vault with owner = multisig ${config.multisigAccount}...`);
  await sendTx({
    rpcUrl: RPC,
    signerId: DEPLOYER,
    privateKey: deployerKey(),
    receiverId: DEPLOYER,
    actions: [
      act.functionCall(
        'new',
        JSON.stringify({ owner_id: config.multisigAccount, policy }).replace(
          /"(daily_spending_cap|per_tx_cap)":"(\d+)"/g,
          '"$1":$2'
        ),
        '30000000000000',
        '0'
      ),
    ],
  });
  const status = await viewFunction(RPC, DEPLOYER, 'get_vault_status', {});
  console.log('Vault status:', JSON.stringify(status));

  // Scope the agent account down to a Function Call Key, then delete its full key.
  console.log('Scoping agent account to Function Call Key only...');
  const agentPrivate = requireSecret(config.keychainSecrets.agent);
  const { KeyPair } = await import('near-api-js');
  const agentKeyPair = KeyPair.fromString(agentPrivate);
  const fck = generateKeyPair();
  await sendTx({
    rpcUrl: RPC,
    signerId: config.agentAccount,
    privateKey: agentPrivate,
    receiverId: config.agentAccount,
    actions: [
      act.addFunctionCallKey(
        fck.publicKey,
        DEPLOYER,
        ['execute_intent', 'request_chain_signature'],
        (NEAR).toString()
      ),
    ],
  });
  setSecret(config.keychainSecrets.agent, fck.privateKey);
  // Delete the full-access key, signed with the full key itself (self-call).
  await sendTx({
    rpcUrl: RPC,
    signerId: config.agentAccount,
    privateKey: agentPrivate,
    receiverId: config.agentAccount,
    actions: [act.deleteKey(agentKeyPair.getPublicKey().toString())],
  });
  console.log('Agent full-access key deleted. Only the scoped Function Call Key remains.');
}

async function phaseStatus() {
  for (const id of [DEPLOYER, config.multisigAccount, config.agentAccount, ...config.memberAccounts.slice(1)]) {
    try {
      const a = await rpc(RPC, 'query', { request_type: 'view_account', account_id: id, finality: 'final' });
      console.log(`${id}: ${(Number(a.amount) / 1e24).toFixed(4)} NEAR, code=${a.code_hash.slice(0, 12)}...`);
    } catch {
      console.log(`${id}: (does not exist)`);
    }
  }
}

const phase = process.argv[2];
const phases = { accounts: phaseAccounts, multisig: phaseMultisig, vault: phaseVault, init: phaseInit, status: phaseStatus };
if (!phases[phase]) {
  console.error(`Usage: node scripts/deploy-testnet.mjs <${Object.keys(phases).join('|')}>`);
  process.exit(1);
}
phases[phase]().catch((e) => {
  console.error('Failed:', e.message);
  process.exit(1);
});
