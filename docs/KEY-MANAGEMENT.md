# Key Management & Operations Runbook

NearWarden follows standard key-custody practice: no private key is ever
stored in the repository, in a `.env` file, or in application memory longer
than a single signing operation.

## Custody layout

| Key | Custody | Used for | If leaked |
|---|---|---|---|
| Deployer / member keys | macOS Keychain (`agentguard.*` services) via `scripts/lib/keychain.mjs` | Deployments, multisig confirmations | Rotate immediately (below); multisig threshold limits blast radius |
| Vault ownership | 2-of-3 multisig contract (`contracts/multisig`) | `emergency_freeze`, `update_policy`, escalation approval dispatch | One member key alone cannot act |
| Supervisor approvals | WebAuthn P-256 passkey; public key anchored on-chain (`set_supervisor_passkey_public_key`) | High-value escalation approval, verified on-chain | Revoke by anchoring a new public key |
| Firewall attestation key | Derived inside OutLayer Intel TDX enclave (`enclave/firewall-signer`, signing key path `firewall`, `bind: project`) | Signing AI-firewall attestations | Host has no key to leak; rotate by anchoring the new TEE public key on-chain |
| Agent key | Function Call Key only, scoped to `execute_intent` + `request_chain_signature` on the vault, 1 NEAR allowance | Autonomous execution | Bounded by on-chain policy (per-tx, daily, whitelist, velocity); revoke by deleting the key |

## Lifecycle

- **Provisioning:** `scripts/migrate-secrets.sh` (one-time `.env` -> Keychain),
  `scripts/rotate-deployer-key.mjs`, `scripts/deploy-testnet.mjs`.
- **Rotation (deployer/member):** generate a new keypair, add it on-chain
  signed by the old key, store it in Keychain, delete the old key on-chain.
  Never delete the old key before the new one is verified on-chain.
- **Rotation (firewall):** publish a new enclave build/project version; the
  project-bound TEE key survives upgrades by design. To move projects, fetch
  the new public key and call `set_firewall_public_key` via multisig proposal.
- **Revocation (agent):** delete the agent's Function Call Key via multisig
  proposal (`delete_key` on the agent account is not possible by the vault;
  the agent account's remaining keys are managed by its creator — keep the
  creator path in the multisig runbook). Emergency: `emergency_freeze` halts
  all agent execution in one transaction.
- **Incident response:** (1) multisig `emergency_freeze` on the vault,
  (2) rotate any suspected key, (3) review `get_audit_log` on-chain,
  (4) unfreeze via multisig only after review.

## Publishing the TEE signer (OutLayer testnet dashboard)

1. Open the OutLayer testnet dashboard and connect `longdata4360.testnet`.
2. Create project `nearwarden-firewall-signer` (id will be
   `longdata4360.testnet/nearwarden-firewall-signer`).
3. Publish [nearwarden-firewall-signer.wasm](/Users/hng/agent-guard/enclave/firewall-signer/out/nearwarden-firewall-signer.wasm)
   (sha256 `524e9694e8dd054bf9611d68d121e5c9f34eb4fdc33cf7c924b83c968fec57cf`)
   as a WasmUrl version and set it active. The signing key is bound to the
   project, so it survives later version upgrades.
4. Fund the payment key (`longdata4360.testnet` nonce `1`) with at least
   $1 of testnet stablecoin.
5. Tell the operator "enclave live". Then: fetch the TEE public key with
   `OutLayerClient.anchorFirewallKeyInTee`, put it in
   `config/testnet.json` as `firewallPublicKey`, run
   `node scripts/deploy-testnet.mjs init`, then `npm run test:live`.

## Rules

- Secrets come from the Keychain (or a cloud secrets manager in production)
  injected at runtime. CI uses short-lived OIDC credentials, never stored keys.
- Public keys, account ids, and project names are configuration
  (`config/testnet.json`) and are safe to commit. Private keys never are.
- The OutLayer payment key is a bearer credential: store it like a private
  key, scope it with payment-key restrictions, and fund it minimally.
- Testnet and mainnet keys are always separate. Mainnet deployment requires
  hardware-wallet or KMS custody for multisig members, not workstation Keychain.
