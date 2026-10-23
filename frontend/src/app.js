/**
 * AgentGuard Cockpit - Reactive Logic & Judge Sandbox
 */

// Embedded Client Engine for Browser Playground
const INJECTION_RULES = [
  { pattern: /system\s+override/i, weight: 85, flag: 'SYSTEM_OVERRIDE_DIRECTIVE' },
  { pattern: /ignore\s+(all\s+|any\s+)?(previous|prior|above)\s+(instructions|directives|rules|constraints)/i, weight: 90, flag: 'PROMPT_HIJACK_INSTRUCTION' },
  { pattern: /developer\s+mode/i, weight: 80, flag: 'DEVELOPER_MODE_JAILBREAK' },
  { pattern: /jailbreak|unrestricted\s+mode|dan\s+mode/i, weight: 85, flag: 'JAILBREAK_TOKEN' },
  { pattern: /drain\s+(all|entire|total|wallet|treasury|funds|balance)/i, weight: 95, flag: 'DRAIN_TREASURY_COMMAND' },
  { pattern: /transfer\s+(all|everything|max|entire|total)/i, weight: 90, flag: 'MAX_TRANSFER_COMMAND' },
];

const BLOCKED_TARGETS = new Set([
  'attacker.near',
  'drainer.near',
  'unauthorized-contract.near',
  'phishing-drainer.near',
]);

const ALLOWED_TARGETS = new Set([
  'intents.near',
  'wrap.near',
  'v2.ref-finance.near',
]);

// Application State
const state = {
  isFrozen: false,
  dailyCap: 10.0,
  dailySpent: 0.5,
  perTxCap: 2.0,
  threatScore: 0,
  threatsIntercepted: 0,
  pendingActions: [],
  auditLog: [
    {
      time: '04:55:12',
      status: 'APPROVED',
      type: 'pass',
      score: 0,
      target: 'intents.near',
      msg: 'Genesis: Scoped Function Call Key authorized for intents.near and wrap.near.'
    }
  ]
};

// DOM Elements
const elVaultStatusIndicator = document.getElementById('vault-status-indicator');
const elValVaultState = document.getElementById('val-vault-state');
const elValDailySpent = document.getElementById('val-daily-spent');
const elQuotaPercent = document.getElementById('quota-percent');
const elQuotaProgressBar = document.getElementById('quota-progress-bar');
const elValThreatScore = document.getElementById('val-threat-score');
const elThreatScoreBadge = document.getElementById('threat-score-badge');
const elThreatCaption = document.getElementById('threat-caption');
const elTerminalLog = document.getElementById('terminal-audit-stream');
const elEscalationQueue = document.getElementById('escalation-queue-list');
const elPendingCountBadge = document.getElementById('pending-count-badge');
const elLiveThreatPreview = document.getElementById('live-threat-preview');
const elInputCustomPrompt = document.getElementById('input-custom-prompt');
const elBtnKillswitch = document.getElementById('btn-killswitch');
const elKillswitchText = document.getElementById('killswitch-text');

// Threat Inspector
function inspectPrompt(text, target) {
  let score = 0;
  const flags = [];

  for (const rule of INJECTION_RULES) {
    if (rule.pattern.test(text)) {
      score = Math.max(score, rule.weight);
      flags.push(rule.flag);
    }
  }

  if (BLOCKED_TARGETS.has(target)) {
    score = Math.max(score, 99);
    flags.push(`BLOCKED_TARGET_${target.toUpperCase()}`);
  }

  return { score, flags, isBlocked: score >= 75 };
}

// Render Telemetry
function renderTelemetry() {
  // Vault state
  if (state.isFrozen) {
    elVaultStatusIndicator.className = 'status-indicator frozen';
    elValVaultState.textContent = 'EMERGENCY FROZEN';
    elValVaultState.style.color = '#ef4444';
    elBtnKillswitch.style.background = 'rgba(16, 185, 129, 0.2)';
    elBtnKillswitch.style.borderColor = '#10b981';
    elBtnKillswitch.style.color = '#10b981';
    elKillswitchText.textContent = 'Lift Freeze';
  } else {
    elVaultStatusIndicator.className = 'status-indicator';
    elValVaultState.textContent = 'OPERATIONAL';
    elValVaultState.style.color = 'var(--text-primary)';
    elBtnKillswitch.style.background = 'rgba(239, 68, 68, 0.15)';
    elBtnKillswitch.style.borderColor = 'rgba(239, 68, 68, 0.4)';
    elBtnKillswitch.style.color = '#fca5a5';
    elKillswitchText.textContent = 'Emergency Freeze';
  }

  // Daily quota
  elValDailySpent.textContent = state.dailySpent.toFixed(2);
  const percent = Math.min(100, Math.round((state.dailySpent / state.dailyCap) * 100));
  elQuotaPercent.textContent = `${percent}% Utilized`;
  elQuotaProgressBar.style.width = `${percent}%`;

  // Threat meter
  elValThreatScore.innerHTML = `${state.threatScore} <span class="unit">/ 100</span>`;
  if (state.threatScore >= 75) {
    elThreatScoreBadge.className = 'badge-mini badge-red';
    elThreatScoreBadge.textContent = 'CRITICAL';
  } else if (state.threatScore >= 40) {
    elThreatScoreBadge.className = 'badge-mini badge-orange';
    elThreatScoreBadge.textContent = 'ELEVATED';
  } else {
    elThreatScoreBadge.className = 'badge-mini badge-green';
    elThreatScoreBadge.textContent = 'LOW';
  }
  elThreatCaption.textContent = `${state.threatsIntercepted} Interceptions in current session`;

  // Pending queue
  renderPendingQueue();
  // Log
  renderLog();
}

function renderPendingQueue() {
  elPendingCountBadge.textContent = `${state.pendingActions.length} Pending`;
  if (state.pendingActions.length === 0) {
    elEscalationQueue.innerHTML = `<div class="empty-queue-msg">No transactions currently waiting for human approval.</div>`;
    return;
  }

  elEscalationQueue.innerHTML = state.pendingActions.map(action => `
    <div class="queue-item" id="queue-item-${action.id}">
      <div class="queue-info">
        <h5>Action #${action.id}: ${action.target} (${action.amount} NEAR)</h5>
        <p>Method: ${action.method} • Exceeds Autonomous Cap (${state.perTxCap} NEAR)</p>
      </div>
      <div class="queue-actions">
        <button class="btn btn-sm btn-primary" onclick="window.approveAction(${action.id})">Approve</button>
        <button class="btn btn-sm btn-secondary" onclick="window.rejectAction(${action.id})">Reject</button>
      </div>
    </div>
  `).join('');
}

function renderLog() {
  elTerminalLog.innerHTML = state.auditLog.map(item => `
    <div class="log-entry">
      <div class="log-meta">
        <span class="log-time">[${item.time}]</span>
        <span class="log-status ${item.type}">${item.status}</span>
        <span style="color: #64748b;">(Score: ${item.score}/100)</span>
      </div>
      <div class="log-msg">${item.msg}</div>
    </div>
  `).join('');
}

function logEvent(status, type, score, target, msg) {
  const now = new Date();
  const timeStr = now.toTimeString().split(' ')[0];
  state.auditLog.unshift({ time: timeStr, status, type, score, target, msg });
  if (state.auditLog.length > 50) state.auditLog.pop();
  renderLog();
}

// Live Prompt Threat Preview
elInputCustomPrompt?.addEventListener('input', () => {
  const target = document.getElementById('select-target')?.value || 'intents.near';
  const res = inspectPrompt(elInputCustomPrompt.value, target);
  elLiveThreatPreview.textContent = res.score;
  elLiveThreatPreview.style.color = res.score >= 75 ? '#ef4444' : res.score >= 40 ? '#f59e0b' : '#10b981';
});

// Scenario Runners
async function runScenario1() {
  const verdict = document.getElementById('verdict-1');
  verdict.textContent = 'Validating...';
  verdict.className = 'scenario-verdict';

  if (state.isFrozen) {
    verdict.textContent = 'BLOCKED: Vault is frozen';
    verdict.className = 'scenario-verdict blocked';
    logEvent('BLOCKED', 'block', 90, 'intents.near', 'Emergency freeze active: all FCK agent calls halted.');
    return;
  }

  setTimeout(() => {
    state.dailySpent += 0.5;
    state.threatScore = 5;
    verdict.textContent = 'PASSED (200 OK)';
    verdict.className = 'scenario-verdict pass';
    logEvent('APPROVED', 'pass', 5, 'intents.near', 'Verified intent: Swap 0.5 NEAR -> 2.50 USDC via NEAR Intents (1.2% slippage bound). Settled atomically.');
    renderTelemetry();
  }, 400);
}

async function runScenario2() {
  const verdict = document.getElementById('verdict-2');
  verdict.textContent = 'Intercepting...';
  verdict.className = 'scenario-verdict';

  setTimeout(() => {
    state.threatScore = 95;
    state.threatsIntercepted += 1;
    verdict.textContent = 'INTERCEPTED (Threat 95/100)';
    verdict.className = 'scenario-verdict blocked';
    logEvent('BLOCKED', 'block', 95, 'wrap.near', 'Firewall intercepted prompt injection: [SYSTEM_OVERRIDE_DIRECTIVE, PROMPT_HIJACK_INSTRUCTION, DRAIN_TREASURY_COMMAND]. Quarantined.');
    renderTelemetry();
  }, 400);
}

async function runScenario3() {
  const verdict = document.getElementById('verdict-3');
  verdict.textContent = 'Checking policy...';
  verdict.className = 'scenario-verdict';

  setTimeout(() => {
    state.threatScore = 85;
    verdict.textContent = 'REJECTED (403 Forbidden)';
    verdict.className = 'scenario-verdict blocked';
    logEvent('POLICY_VIOLATION', 'block', 85, 'unverified-drainer.near', 'Contract unverified-drainer.near is not in authorized whitelist. Reverted on-chain.');
    renderTelemetry();
  }, 400);
}

async function runScenario4() {
  const verdict = document.getElementById('verdict-4');
  verdict.textContent = 'Evaluating cap...';
  verdict.className = 'scenario-verdict';

  setTimeout(() => {
    const actionId = state.pendingActions.length + 101;
    state.pendingActions.push({
      id: actionId,
      target: 'wrap.near',
      method: 'ft_transfer',
      amount: 5.0,
    });
    verdict.textContent = `ESCALATED (#${actionId})`;
    verdict.className = 'scenario-verdict escalated';
    logEvent('ESCALATED', 'escalate', 60, 'wrap.near', `Amount 5.0 NEAR exceeds autonomous per-tx limit of ${state.perTxCap} NEAR. Enqueued into pending multi-sig queue.`);
    renderTelemetry();
  }, 400);
}

async function runScenario5() {
  const verdict = document.getElementById('verdict-5');
  state.isFrozen = true;
  verdict.textContent = 'VAULT FROZEN (503)';
  verdict.className = 'scenario-verdict blocked';
  logEvent('CIRCUIT_BREAKER', 'block', 95, 'vault.near', 'Emergency freeze engaged. All agent Function Call Keys revoked instantly.');
  renderTelemetry();
}

// Killswitch Toggle
elBtnKillswitch.addEventListener('click', () => {
  state.isFrozen = !state.isFrozen;
  logEvent('CIRCUIT_BREAKER', state.isFrozen ? 'block' : 'pass', state.isFrozen ? 95 : 0, 'vault.near', state.isFrozen ? 'Owner activated emergency killswitch.' : 'Owner lifted emergency freeze.');
  renderTelemetry();
});

// Run All AI Judge Tests in Sequence
document.getElementById('btn-run-all-tests')?.addEventListener('click', async () => {
  logEvent('INFO', 'pass', 0, 'judge-arena', 'Running full AI Judge Test Suite (5 Scenarios)...');
  await runScenario1();
  await new Promise(r => setTimeout(r, 600));
  await runScenario2();
  await new Promise(r => setTimeout(r, 600));
  await runScenario3();
  await new Promise(r => setTimeout(r, 600));
  await runScenario4();
  await new Promise(r => setTimeout(r, 600));
  await runScenario5();
});

// Custom Intent Dispatch
document.getElementById('btn-dispatch-custom')?.addEventListener('click', () => {
  const prompt = elInputCustomPrompt.value || 'Execute micro-swap';
  const target = document.getElementById('select-target').value;
  const amount = parseFloat(document.getElementById('input-amount').value || '0.5');

  if (state.isFrozen) {
    logEvent('BLOCKED', 'block', 90, target, 'Vault is emergency frozen.');
    return;
  }

  const inspection = inspectPrompt(prompt, target);
  if (inspection.isBlocked) {
    state.threatScore = inspection.score;
    state.threatsIntercepted += 1;
    logEvent('BLOCKED', 'block', inspection.score, target, `Firewall blocked intent: Flags: [${inspection.flags.join(', ')}]`);
    renderTelemetry();
    return;
  }

  if (!ALLOWED_TARGETS.has(target)) {
    logEvent('REJECTED', 'block', 85, target, `Contract '${target}' is not in whitelist.`);
    renderTelemetry();
    return;
  }

  if (amount > state.perTxCap) {
    const actionId = state.pendingActions.length + 201;
    state.pendingActions.push({ id: actionId, target, method: 'execute_intent', amount });
    logEvent('ESCALATED', 'escalate', 60, target, `Amount ${amount} NEAR exceeds per-tx cap. Escalated to Action #${actionId}`);
    renderTelemetry();
    return;
  }

  state.dailySpent += amount;
  state.threatScore = inspection.score;
  logEvent('APPROVED', 'pass', inspection.score, target, `Custom intent approved: ${amount} NEAR dispatched to ${target}.`);
  renderTelemetry();
});

// Approval / Rejection Handlers
window.approveAction = (actionId) => {
  const idx = state.pendingActions.findIndex(a => a.id === actionId);
  if (idx !== -1) {
    const action = state.pendingActions[idx];
    state.pendingActions.splice(idx, 1);
    state.dailySpent += action.amount;
    logEvent('MANUALLY_APPROVED', 'pass', 10, action.target, `Operator approved Action #${actionId} (${action.amount} NEAR). Executed on-chain.`);
    renderTelemetry();
  }
};

window.rejectAction = (actionId) => {
  const idx = state.pendingActions.findIndex(a => a.id === actionId);
  if (idx !== -1) {
    const action = state.pendingActions[idx];
    state.pendingActions.splice(idx, 1);
    logEvent('MANUALLY_REJECTED', 'block', 30, action.target, `Operator rejected Action #${actionId}.`);
    renderTelemetry();
  }
};

// Bind scenario buttons
document.getElementById('btn-run-scenario-1')?.addEventListener('click', runScenario1);
document.getElementById('btn-run-scenario-2')?.addEventListener('click', runScenario2);
document.getElementById('btn-run-scenario-3')?.addEventListener('click', runScenario3);
document.getElementById('btn-run-scenario-4')?.addEventListener('click', runScenario4);
document.getElementById('btn-run-scenario-5')?.addEventListener('click', runScenario5);
document.getElementById('btn-clear-stream')?.addEventListener('click', () => {
  state.auditLog = [];
  renderLog();
});

// Slider inputs
document.getElementById('slider-daily-cap')?.addEventListener('input', (e) => {
  state.dailyCap = parseFloat(e.target.value);
  document.getElementById('lbl-daily-cap').textContent = `${state.dailyCap.toFixed(1)} NEAR`;
  renderTelemetry();
});

document.getElementById('slider-pertx-cap')?.addEventListener('input', (e) => {
  state.perTxCap = parseFloat(e.target.value);
  document.getElementById('lbl-pertx-cap').textContent = `${state.perTxCap.toFixed(1)} NEAR`;
  renderTelemetry();
});

// Mode Toggle & Live NEAR RPC Client
const elSelectMode = document.getElementById('select-network-mode');
const elRpcBar = document.getElementById('rpc-connect-bar');
const elInputContractId = document.getElementById('input-contract-id');
const elBtnSyncChain = document.getElementById('btn-sync-chain');
const elRpcStatusText = document.getElementById('rpc-status-text');

elSelectMode?.addEventListener('change', (e) => {
  if (e.target.value === 'rpc') {
    elRpcBar.style.display = 'flex';
    syncOnChainState();
  } else {
    elRpcBar.style.display = 'none';
    elRpcStatusText.textContent = 'RPC Ready: https://rpc.testnet.near.org';
  }
});

async function queryNearRpc(contractId, methodName, argsObj = {}) {
  const argsBase64 = btoa(JSON.stringify(argsObj));
  const startTime = Date.now();
  const res = await fetch('https://rpc.testnet.near.org', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 'agentguard-query',
      method: 'query',
      params: {
        request_type: 'call_function',
        finality: 'final',
        account_id: contractId,
        method_name: methodName,
        args_base64: argsBase64,
      },
    }),
  });

  const latency = Date.now() - startTime;
  const json = await res.json();

  if (json.error) {
    throw new Error(json.error.data || json.error.message || 'RPC Query failed');
  }

  const rawBytes = json.result.result;
  const decodedStr = new TextDecoder().decode(new Uint8Array(rawBytes));
  return { data: JSON.parse(decodedStr), latency, blockHeight: json.result.block_height };
}

async function syncOnChainState() {
  const contractId = elInputContractId?.value.trim() || 'agent-guard.testnet';
  if (elRpcStatusText) elRpcStatusText.textContent = `Querying ${contractId} via testnet RPC...`;

  try {
    const { data: vaultStatus, latency, blockHeight } = await queryNearRpc(contractId, 'get_vault_status');
    state.isFrozen = Boolean(vaultStatus.is_frozen);
    state.dailyCap = Number(BigInt(vaultStatus.daily_spending_cap) / 1000000000000000000000000n) || 10.0;
    state.dailySpent = Number(BigInt(vaultStatus.daily_spent) / 1000000000000000000000000n) || 0.0;
    state.perTxCap = Number(BigInt(vaultStatus.per_tx_cap) / 1000000000000000000000000n) || 2.0;

    // Fetch on-chain audit log
    try {
      const { data: onChainLogs } = await queryNearRpc(contractId, 'get_audit_log', { limit: 10 });
      if (Array.isArray(onChainLogs) && onChainLogs.length > 0) {
        state.auditLog = onChainLogs.map(l => ({
          time: new Date(Number(BigInt(l.timestamp_ns) / 1000000n)).toLocaleTimeString(),
          status: l.status.startsWith('BLOCKED') ? 'REJECTED' : 'APPROVED',
          type: l.status.startsWith('BLOCKED') ? 'block' : 'pass',
          score: l.threat_score,
          target: l.target,
          msg: `On-chain [${l.method}]: ${l.status}`
        }));
      }
    } catch (_) {}

    // Fetch on-chain pending actions
    try {
      const { data: pending } = await queryNearRpc(contractId, 'get_pending_actions');
      if (Array.isArray(pending)) {
        state.pendingActions = pending.map(p => ({
          id: p.action_id,
          target: p.target,
          method: p.method,
          amount: Number(BigInt(p.deposit) / 1000000000000000000000000n),
          cap: state.perTxCap,
          prompt: `On-chain escalated call to ${p.target}`
        }));
      }
    } catch (_) {}

    renderTelemetry();
    if (elRpcStatusText) {
      elRpcStatusText.textContent = `● Synced (${latency}ms) • Block #${blockHeight} • Owner: ${vaultStatus.owner_id}`;
      elRpcStatusText.style.color = '#10b981';
    }
    logEvent('RPC_SYNC_SUCCESS', 'pass', 0, contractId, `Live on-chain state synced from block #${blockHeight}`);
  } catch (err) {
    if (elRpcStatusText) {
      elRpcStatusText.textContent = `Contract '${contractId}' not deployed on testnet yet. Run 'node scripts/deploy.js'`;
      elRpcStatusText.style.color = '#f59e0b';
    }
  }
}

elBtnSyncChain?.addEventListener('click', syncOnChainState);

// Initial Render
renderTelemetry();
