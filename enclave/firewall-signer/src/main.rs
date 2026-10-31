//! AgentGuard Firewall Signer — runs inside an OutLayer Intel TDX enclave.
//!
//! The ed25519 signing key is derived by the OutLayer keystore inside the
//! TEE for this project and caller. This component never sees the key: it
//! names it by path (`firewall`) and the host signs. The enclave refuses to
//! sign any intent whose threat score exceeds the policy threshold, and it
//! composes the signed digest itself from parsed fields — it never signs
//! caller-supplied bytes or digests.

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[cfg(target_arch = "wasm32")]
#[used]
#[link_section = "outlayer.manifest"]
static OUTLAYER_MANIFEST: [u8; include_bytes!("../manifest.json").len()] =
    *include_bytes!("../manifest.json");

mod signing_keys_host {
    wit_bindgen::generate!({
        world: "signing-keys-host",
        path: "wit",
    });
}
use signing_keys_host::outlayer::signing_keys::api as signing_keys;

const MAX_THREAT_SCORE: u64 = 75;
const KEY_PATH: &str = "firewall";

#[derive(Debug, Deserialize, Default)]
struct Input {
    #[serde(default)]
    operation: String,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    method: Option<String>,
    /// JSON string of the intent arguments (as passed to the vault contract).
    #[serde(default)]
    args: Option<String>,
    /// Amount in yoctoNEAR, as a decimal string.
    #[serde(default)]
    amount: Option<String>,
    #[serde(default)]
    threat_score: Option<u64>,
    #[serde(default)]
    timestamp_ms: Option<u64>,
    #[serde(default)]
    nonce: Option<u64>,
}

fn err(message: String) -> Value {
    json!({ "status": "err", "message": message })
}

fn public_key_answer() -> Value {
    match signing_keys::public_key(KEY_PATH, None) {
        Ok(bytes) => {
            if bytes.len() != 32 {
                return err(format!("unexpected public key length {}", bytes.len()));
            }
            json!({
                "status": "ok",
                "public_key": format!("ed25519:{}", bs58::encode(&bytes).into_string()),
                "public_key_hex": hex::encode(&bytes),
            })
        }
        Err(e) => err(format!("public_key refused: {e}")),
    }
}

fn sign_attestation(input: &Input) -> Value {
    let (target, method, args, amount, threat_score, timestamp_ms, nonce) = match (
        &input.target,
        &input.method,
        &input.args,
        &input.amount,
        input.threat_score,
        input.timestamp_ms,
        input.nonce,
    ) {
        (Some(t), Some(m), Some(a), Some(amt), Some(ts), Some(tms), Some(n)) => {
            (t, m, a, amt, ts, tms, n)
        }
        _ => {
            return err(
                "sign_attestation requires target, method, args, amount, threat_score, timestamp_ms, nonce"
                    .to_string(),
            )
        }
    };

    // Enclave policy gate: refuse to sign unsafe intents.
    if threat_score > MAX_THREAT_SCORE {
        return err(format!(
            "threat score {threat_score} exceeds enclave maximum of {MAX_THREAT_SCORE}; signing refused"
        ));
    }
    if amount.parse::<u128>().is_err() {
        return err("amount must be a decimal integer string (yoctoNEAR)".to_string());
    }

    // Compose the digest inside the enclave, exactly as the vault contract
    // recomputes it: sha256("{target}:{method}:{args}:{amount}:{ts}:{nonce}").
    let digest_input = format!("{target}:{method}:{args}:{amount}:{timestamp_ms}:{nonce}");
    let digest = Sha256::digest(digest_input.as_bytes());

    match signing_keys::sign(KEY_PATH, None, &digest) {
        Ok(signature) => {
            if signature.len() != 64 {
                return err(format!("unexpected signature length {}", signature.len()));
            }
            let public_key = match signing_keys::public_key(KEY_PATH, None) {
                Ok(bytes) if bytes.len() == 32 => {
                    format!("ed25519:{}", bs58::encode(&bytes).into_string())
                }
                _ => String::new(),
            };
            json!({
                "status": "ok",
                "threat_score": threat_score,
                "timestamp_ms": timestamp_ms,
                "nonce": nonce,
                "signature": hex::encode(&signature),
                "public_key": public_key,
            })
        }
        Err(e) => err(format!("sign refused: {e}")),
    }
}

fn run(input: &Input) -> Value {
    match input.operation.as_str() {
        "public_key" => public_key_answer(),
        "sign_attestation" => sign_attestation(input),
        other => err(format!("unknown operation {other:?}; one of public_key, sign_attestation")),
    }
}

fn main() {
    use std::io::Read;
    let mut raw = String::new();
    let _ = std::io::stdin().read_to_string(&mut raw);
    let trimmed = raw.trim();
    let parsed: Value = if trimmed.is_empty() {
        json!({})
    } else {
        serde_json::from_str(trimmed).unwrap_or(Value::Null)
    };
    // HTTPS API wraps the input as {"input": {...}}; accept both shapes.
    let inner = parsed.get("input").cloned().unwrap_or(parsed);
    let answer = match serde_json::from_value::<Input>(inner) {
        Ok(input) => run(&input),
        Err(e) => err(format!("input is not a JSON object this signer reads: {e}")),
    };
    use std::io::Write;
    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(answer.to_string().as_bytes());
    let _ = stdout.flush();
}
