/**
 * Deprecated entry point. Deployment is handled by deploy-testnet.mjs,
 * which keeps all private keys in macOS Keychain (never in .env files).
 * Kept as a redirect so old commands fail helpfully instead of silently
 * falling back to plaintext secrets.
 */
console.log('This deployer was replaced. Use:');
console.log('  node scripts/migrate-secrets.sh        # one-time: .env -> Keychain');
console.log('  node scripts/rotate-deployer-key.mjs   # revoke the old exposed key');
console.log('  node scripts/deploy-testnet.mjs status|accounts|multisig|vault|init');
process.exit(1);
