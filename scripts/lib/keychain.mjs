/**
 * macOS Keychain secret access for AgentGuard operator tooling.
 * Secrets are stored as generic passwords under service "agentguard.<name>".
 * Nothing secret is ever read from or written to the repository.
 */
import { execFileSync } from 'node:child_process';

const PREFIX = 'agentguard.';

export function getSecret(name) {
  try {
    return execFileSync(
      'security',
      ['find-generic-password', '-s', PREFIX + name, '-w'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }
    ).trim();
  } catch {
    return null;
  }
}

export function requireSecret(name, hint = '') {
  const value = getSecret(name);
  if (!value) {
    throw new Error(
      `Secret "${name}" not found in macOS Keychain (service ${PREFIX}${name}). ${hint}`
    );
  }
  return value;
}

export function setSecret(name, value) {
  execFileSync(
    'security',
    ['add-generic-password', '-U', '-s', PREFIX + name, '-a', process.env.USER || 'agentguard', '-w', value],
    { stdio: 'ignore' }
  );
}

export function deleteSecret(name) {
  try {
    execFileSync('security', ['delete-generic-password', '-s', PREFIX + name], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}
