/**
 * AgentGuard OutLayer TEE Custody Integration Client
 * Wraps OutLayer (api.outlayer.ai / testnet-api.outlayer.ai) agent custody endpoints,
 * Intel TDX enclave wallets, payment keys, NEAR Intents integration, and account binding.
 */



export class OutLayerClient {
  constructor(options = {}) {
    this.network = options.network || (process.env.OUTLAYER_NETWORK || 'testnet');
    this.baseUrl = this.network === 'testnet'
      ? 'https://testnet-api.outlayer.ai'
      : 'https://api.outlayer.ai';
    this.paymentKey = options.paymentKey || process.env.OUTLAYER_API_KEY || null;
    this.apiKey = options.apiKey || null;
    this.walletId = options.walletId || null;
    this.nearAccountId = null;

    // Intel TDX TEE firewall signer (OutLayer project). The signing key is
    // derived inside the enclave; this client never holds a private key.
    this.signerProject = options.signerProject || process.env.OUTLAYER_SIGNER_PROJECT || null;
    this._teePublicKeyString = null;
    this._fetch = options.fetchImpl || fetch;

    // Parse owner account from payment key format (e.g. "blackquokka5481.testnet:1:secret")
    if (this.paymentKey && this.paymentKey.includes(':')) {
      const parts = this.paymentKey.split(':');
      this.paymentOwner = parts[0];
      this.paymentNonce = parts[1];
      this.nearAccountId = parts[0];
    } else {
      this.paymentOwner = options.paymentOwner || null;
      this.paymentNonce = options.paymentNonce || null;
      this.nearAccountId = options.nearAccountId || null;
    }
  }

  /**
   * Queries the live balance of an OutLayer Payment Key.
   */
  async getPaymentKeyBalance() {
    if (!this.paymentOwner || !this.paymentNonce) {
      if (this.paymentKey && this.paymentKey.includes(':')) {
        const parts = this.paymentKey.split(':');
        this.paymentOwner = parts[0];
        this.paymentNonce = parts[1];
      } else {
        throw new Error('Payment key (owner:nonce:secret) required to check balance');
      }
    }

    const url = `${this.baseUrl}/public/payment-keys/${this.paymentOwner}/${this.paymentNonce}/balance`;
    const response = await fetch(url);
    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`Failed to query payment key balance (${response.status}): ${errText}`);
    }
    return await response.json();
  }

  /**
   * Registers a new TEE-held custody wallet inside an Intel TDX hardware enclave.
   */
  async registerWallet() {
    try {
      const response = await fetch(`${this.baseUrl}/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(this.paymentKey ? { 'X-Payment-Key': this.paymentKey } : {}),
        },
        body: JSON.stringify({}),
      });

      if (!response.ok) {
        throw new Error(`OutLayer registration failed: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      this.apiKey = data.api_key;
      this.walletId = data.wallet_id;
      this.nearAccountId = data.near_account_id;

      return {
        success: true,
        apiKey: data.api_key,
        walletId: data.wallet_id,
        nearAccountId: data.near_account_id,
        handoffUrl: data.handoff_url,
        trial: data.trial,
      };
    } catch (err) {
      throw new Error(`OutLayer registration failed: ${err.message}`);
    }
  }

  /**
   * Ensures an active authenticated session key exists, registering if necessary.
   */
  async ensureSession() {
    if (!this.apiKey) {
      const reg = await this.registerWallet();
      if (reg.apiKey) {
        this.apiKey = reg.apiKey;
      }
    }
    if (!this.apiKey) {
      throw new Error('OutLayer session unavailable: no API key (register a custody wallet first)');
    }
    return this.apiKey;
  }

  /**
   * Queries the agent's derived hardware address for a given chain (e.g. 'near', 'evm', 'solana').
   */
  async getWalletAddress(chain = 'near') {
    await this.ensureSession();

    const response = await fetch(`${this.baseUrl}/wallet/v1/address?chain=${chain}`, {
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch wallet address (${response.status}): ${await response.text()}`);
    }
    return await response.json();
  }

  /**
   * Fetches supported token catalog across 20+ chains and NEAR Intents (Defuse asset IDs).
   */
  async getTokens() {
    await this.ensureSession();

    const response = await fetch(`${this.baseUrl}/wallet/v1/tokens`, {
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to query tokens (${response.status}): ${await response.text()}`);
    }
    return await response.json();
  }

  /**
   * Fetches a live swap quote via OutLayer's NEAR Intents / 1Click bridge.
   */
  async getSwapQuote({ tokenIn, tokenOut, amountIn, minAmountOut }) {
    await this.ensureSession();

    const response = await fetch(`${this.baseUrl}/wallet/v1/intents/swap/quote`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        token_in: tokenIn,
        token_out: tokenOut,
        amount_in: amountIn,
        ...(minAmountOut ? { min_amount_out: minAmountOut } : {}),
      }),
    });

    if (!response.ok) {
      throw new Error(`Failed to get swap quote (${response.status}): ${await response.text()}`);
    }
    return await response.json();
  }

  /**
   * Queries the TEE enclave decrypted policy for this wallet.
   */
  async getPolicy() {
    await this.ensureSession();

    const response = await fetch(`${this.baseUrl}/wallet/v1/policy`, {
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to get policy (${response.status}): ${await response.text()}`);
    }
    return await response.json();
  }

  /**
   * Comprehensive connectivity and health check for OutLayer services.
   */
  async checkConnection() {
    const report = {
      network: this.network,
      baseUrl: this.baseUrl,
      paymentKeyConfigured: !!this.paymentKey,
      paymentOwner: this.paymentOwner,
      paymentKeyBalance: null,
      teeSessionActive: false,
      walletAddress: null,
      tokensAvailableCount: 0,
      status: 'DISCONNECTED',
    };

    try {
      if (this.paymentOwner && this.paymentNonce) {
        report.paymentKeyBalance = await this.getPaymentKeyBalance();
      }
      const reg = await this.registerWallet();
      if (reg && reg.success) {
        report.teeSessionActive = true;
        report.walletId = reg.walletId;
        const addr = await this.getWalletAddress('near');
        report.walletAddress = addr.address;
        const tokensData = await this.getTokens();
        report.tokensAvailableCount = tokensData?.tokens?.length || 0;
        report.status = 'CONNECTED';
      }
    } catch (err) {
      report.status = 'ERROR';
      report.error = err.message;
    }

    return report;
  }

  /**
   * Dispatches a secure call to a TEE-isolated project hosted on OutLayer.
   */
  async callProject(projectOwner, projectName, inputData = {}) {
    if (!this.paymentKey) {
      throw new Error('OUTLAYER_API_KEY (X-Payment-Key) not configured.');
    }

    const url = `${this.baseUrl}/call/${projectOwner}/${projectName}`;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Payment-Key': this.paymentKey,
        'X-Compute-Limit': '10000', // $0.01 max micro-budget
      },
      body: JSON.stringify({ input: inputData }),
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`OutLayer call failed (${response.status}): ${errText}`);
    }

    return await response.json();
  }

  /**
   * Generates a policy specification compatible with OutLayer account-binding
   */
  buildBindingPolicy({
    dailyCap = '10000000000000000000000000',
    perTxCap = '2000000000000000000000000',
    allowedPayees = ['intents.near', 'wrap.near'],
  }) {
    return {
      version: '1.0',
      spending_caps: {
        daily: dailyCap,
        per_transaction: perTxCap,
      },
      address_rules: {
        mode: 'whitelist',
        allowed_addresses: allowedPayees,
      },
      transaction_types: ['call', 'transfer'],
      allowed_tokens: ['native', 'usdc.near', 'wrap.near'],
    };
  }

  /**
   * Calls the firewall signer module running inside the OutLayer Intel TDX
   * enclave. The signing key is derived by the keystore inside the TEE;
   * this client never generates, holds, or sees a private key.
   */
  async callSignerModule(input) {
    if (!this.signerProject) {
      throw new Error(
        'OutLayer TEE signer not configured: set OUTLAYER_SIGNER_PROJECT (e.g. owner.testnet/agentguard-firewall-signer). Refusing to sign locally.'
      );
    }
    if (!this.paymentKey) {
      throw new Error('OutLayer payment key not configured: inject OUTLAYER_API_KEY from your secrets manager.');
    }
    const [owner, project] = this.signerProject.split('/');
    if (!owner || !project) {
      throw new Error(`Invalid OUTLAYER_SIGNER_PROJECT "${this.signerProject}"; expected "<owner>/<project>"`);
    }
    const response = await this._fetch(`${this.baseUrl}/call/${owner}/${project}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Payment-Key': this.paymentKey,
        'X-Compute-Limit': '10000',
      },
      body: JSON.stringify({ input }),
    });
    if (!response.ok) {
      throw new Error(`OutLayer signer call failed (${response.status}): ${await response.text()}`);
    }
    const data = await response.json();
    if (data.status !== 'completed') {
      throw new Error(`OutLayer signer execution failed: ${data.error || data.status}`);
    }
    const output = typeof data.output === 'string' ? JSON.parse(data.output) : data.output;
    if (!output || output.status !== 'ok') {
      throw new Error(`OutLayer signer refused: ${output?.message || 'unknown error'}`);
    }
    return { output, attestationUrl: data.attestation_url || null, callId: data.call_id || null };
  }

  /**
   * Fetches the TEE-derived firewall public key (ed25519:...) from the enclave.
   * Despite the historical name, no key is created or anchored on the host:
   * the key is derived inside the TEE from the project and caller.
   */
  async anchorFirewallKeyInTee(_options = {}) {
    const { output, attestationUrl } = await this.callSignerModule({ operation: 'public_key' });
    this._teePublicKeyString = output.public_key;
    return {
      success: true,
      publicKey: output.public_key,
      enclave: {
        type: 'INTEL_TDX',
        hardware_sealed: true,
        project: this.signerProject,
        attestation_url: attestationUrl,
        status: 'TEE_DERIVED',
      },
    };
  }

  /** True when the TEE signer is configured (project + payment key present). */
  isTeeSignerAnchored() {
    return !!(this.signerProject && this.paymentKey);
  }

  /** Returns the last fetched TEE public key, or null if not fetched yet. */
  getTeePublicKey() {
    return this._teePublicKeyString;
  }

  /**
   * Requests an attestation signature from inside the TEE enclave. The
   * enclave composes the digest from parsed fields and refuses threat
   * scores above its threshold. No signing happens on this host.
   */
  async signAttestationViaTee({
    target,
    method,
    args,
    amount,
    threatScore,
    timestampMs = Date.now(),
    nonce = Math.floor(Math.random() * 1_000_000_000_000),
  }) {
    const argsStr = typeof args === 'string' ? args : JSON.stringify(args || {});
    const { output, attestationUrl } = await this.callSignerModule({
      operation: 'sign_attestation',
      target,
      method,
      args: argsStr,
      amount: (amount ?? '0').toString(),
      threat_score: threatScore,
      timestamp_ms: timestampMs,
      nonce,
    });
    this._teePublicKeyString = output.public_key || this._teePublicKeyString;
    return {
      threat_score: output.threat_score,
      timestamp_ms: output.timestamp_ms,
      nonce: output.nonce,
      signature: output.signature,
      tee_proof: {
        enclave_type: 'INTEL_TDX',
        hardware_sealed: true,
        signer_public_key: output.public_key,
        project: this.signerProject,
        attestation_url: attestationUrl,
      },
    };
  }
}
