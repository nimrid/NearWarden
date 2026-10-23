#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "  Building AgentGuard Smart Contract (WASM32 Release)"
echo "=========================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONTRACTS_DIR="${ROOT_DIR}/contracts"
OUT_DIR="${CONTRACTS_DIR}/out"

mkdir -p "${OUT_DIR}"

cd "${CONTRACTS_DIR}"

echo "Running Rust tests..."
cargo test

echo "Compiling to wasm32-unknown-unknown..."
cargo build --target wasm32-unknown-unknown --release

WASM_SRC="${CONTRACTS_DIR}/target/wasm32-unknown-unknown/release/agent_guard_contract.wasm"
WASM_DEST="${OUT_DIR}/agent_guard_contract.wasm"

cp "${WASM_SRC}" "${WASM_DEST}"

WASM_SIZE=$(ls -lh "${WASM_DEST}" | awk '{print $5}')

echo "=========================================================="
echo "  Build Complete!"
echo "  Artifact: ${WASM_DEST}"
echo "  Size: ${WASM_SIZE}"
echo "=========================================================="
