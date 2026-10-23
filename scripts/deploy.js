/**
 * AgentGuard NEAR Testnet Deployment & Scoped Key Provisioning Script
 *
 * Usage:
 *   NEAR_ACCOUNT_ID=myvault.testnet NEAR_PRIVATE_KEY=ed25519:... node scripts/deploy.js
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import * as nearAPI from 'near-api-js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const WASM_PATH = path.resolve(__dirname, '../contracts/out/agent_guard_contract.wasm');

async function main() {
  console.log('==========================================================');
  console.log('   AgentGuard NEAR Contract Deployment & Key Scoping     ');
  console.log('==========================================================\n');

  if (!fs.existsSync(WASM_PATH)) {
    console.error(`Error: Compiled WASM not found at ${WASM_PATH}`);
    console.error('Run `./scripts/build.sh` first to compile the contract.');
    process.exit(1);
  }

  const wasmBinary = fs.readFileSync(WASM_PATH);
  console.log(`[1/4] Found WASM binary: ${(wasmBinary.length / 1024).toFixed(1)} KB`);

  const accountId = process.env.NEAR_ACCOUNT_ID;
  const privateKey = process.env.NEAR_PRIVATE_KEY;
  const networkId = process.env.NEAR_NETWORK || 'testnet';
  const nodeUrl = process.env.NEAR_NODE_URL || 'https://rpc.testnet.near.org';

  if (!accountId || !privateKey) {
    console.log('\n[INFO] No NEAR_ACCOUNT_ID / NEAR_PRIVATE_KEY provided in environment.');
    console.log('Displaying manual NEAR CLI deployment instructions:\n');
    console.log('1. Deploy contract binary to testnet:');
    console.log(`   near deploy <your-vault>.testnet ${WASM_PATH}`);
    console.log('\n2. Initialize contract:');
    console.log(`   near call <your-vault>.testnet new '{"owner_id": "<your-owner>.testnet"}' --accountId <your-owner>.testnet`);
    console.log('\n3. Add Function Call Key (FCK) restricted to execute_intent for the AI Agent:');
    console.log('   near add-key <your-vault>.testnet <agent_public_key> --method-names execute_intent --allowance 1.0\n');
    console.log('==========================================================');
    return;
  }

  console.log(`[2/4] Connecting to NEAR ${networkId} (${nodeUrl})...`);
  const keyStore = new nearAPI.keyStores.InMemoryKeyStore();
  const keyPair = nearAPI.KeyPair.fromString(privateKey);
  await keyStore.setKey(networkId, accountId, keyPair);

  const near = await nearAPI.connect({
    networkId,
    nodeUrl,
    keyStore,
  });

  const account = await near.account(accountId);

  console.log(`[3/4] Deploying contract binary to ${accountId}...`);
  const deployOutcome = await account.deployContract(wasmBinary);
  console.log(`  Deployed in Tx: ${deployOutcome.transaction.hash}`);

  console.log(`[4/4] Initializing AgentGuard policy vault...`);
  try {
    const initOutcome = await account.functionCall({
      contractId: accountId,
      methodName: 'new',
      args: {
        owner_id: accountId,
        policy: {
          daily_spending_cap: '10000000000000000000000000', // 10 NEAR
          per_tx_cap: '2000000000000000000000000', // 2 NEAR
          allowed_targets: ['intents.near', 'wrap.near', 'v2.ref-finance.near'],
          allowed_methods: ['execute_intent', 'ft_transfer', 'near_deposit'],
          max_velocity_per_hour: 20,
          emergency_frozen: false,
        },
      },
      gas: '30000000000000',
    });
    console.log(`  Initialized in Tx: ${initOutcome.transaction.hash}`);
  } catch (err) {
    if (err.message.includes('Contract already initialized')) {
      console.log('  Contract state already initialized.');
    } else {
      throw err;
    }
  }

  console.log('\n==========================================================');
  console.log('  Deployment Successful!');
  console.log(`  Vault Contract: https://explorer.${networkId}.near.org/accounts/${accountId}`);
  console.log('==========================================================\n');
}

main().catch((err) => {
  console.error('Deployment failed:', err);
  process.exit(1);
});
