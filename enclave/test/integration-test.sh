#!/usr/bin/env bash
# Integration tests for the introspector enclave.
#
# Boots an EIF that runs introspector inside the framework, then asserts:
#   1. /health returns 200            (enclave reaches a ready state)
#   2. HTTP/2 ALPN is negotiated      (framework's TLS edge advertises h2)
#   3. enclave-client GetInfo over native gRPC succeeds with the right PCR0
#      (exercises Middleware bypass + h2c revProxy + introspector's
#      grpc.Server.ServeHTTP)
#   4. enclave-client rejects a wrong PCR0 at the attestation handshake
#      (proves attestation pinning isn't a silent no-op)
#   5. HTTP/1.1 still serves /health  (backward compat with non-h2 clients)
set -euo pipefail

HOST_TLS_PORT="${HOST_TLS_PORT:-8443}"
BASE_URL="${ENCLAVE_URL:-https://localhost:${HOST_TLS_PORT}}"
PCR_FILE="${PCR_FILE:-/test/app/.enclave/artifacts/pcr.json}"

CURL="curl -sk --max-time 10"
PASSED=0
FAILED=0
TOTAL=0

pass() { echo "  PASS: $1"; PASSED=$((PASSED + 1)); TOTAL=$((TOTAL + 1)); }
fail() { echo "  FAIL: $1 — $2"; FAILED=$((FAILED + 1)); TOTAL=$((TOTAL + 1)); }

echo "=== Integration tests against $BASE_URL ==="
echo ""

# Test 1: /health returns 200.
echo "[1/6] Health check"
HEALTH_CODE=$($CURL -o /dev/null -w '%{http_code}' "${BASE_URL}/health" 2>/dev/null || echo "000")
if [ "$HEALTH_CODE" = "200" ]; then
  pass "Health endpoint returns 200"
else
  fail "Health endpoint" "expected 200, got HTTP $HEALTH_CODE"
fi

# Test 2: HTTP/2 ALPN negotiation.
echo "[2/6] HTTP/2 ALPN negotiation"
H2_OUT=$(curl -sk --http2 -o /dev/null -w '%{http_version}' --max-time 10 \
  "${BASE_URL}/health" 2>/dev/null || echo "")
if [ "$H2_OUT" = "2" ]; then
  pass "ALPN negotiated h2 (http_version=$H2_OUT)"
else
  fail "HTTP/2 negotiation" "expected http_version=2, got '$H2_OUT'"
fi

# Test 3: native gRPC GetInfo via enclave-client (attestation-verified).
echo "[3/6] enclave-client GetInfo (native gRPC + attestation)"
if [ ! -f "$PCR_FILE" ]; then
  fail "enclave-client GetInfo" "PCR file not found at $PCR_FILE"
else
  PCR0=$(jq -r '.PCR0' "$PCR_FILE")
  INFO_OUT=$(/usr/local/bin/grpc-client \
    -url "${BASE_URL}" \
    -pcr0 "${PCR0}" \
    -insecure-skip-cose 2>&1 || true)
  if echo "$INFO_OUT" | grep -q '^Signer Pubkey:'; then
    PUBKEY=$(echo "$INFO_OUT" | awk '/^Signer Pubkey:/ {print $3}' | head -1)
    pass "GetInfo succeeded (signer_pubkey=${PUBKEY:0:16}...)"
  else
    fail "enclave-client GetInfo" "stdout: ${INFO_OUT:0:300}"
  fi
fi

# Test 4: attestation rejection with wrong PCR0.
echo "[4/6] enclave-client rejects wrong PCR0"
WRONG_PCR0="00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
REJECT_OUT=$(/usr/local/bin/grpc-client \
  -url "${BASE_URL}" \
  -pcr0 "${WRONG_PCR0}" \
  -insecure-skip-cose 2>&1 || echo "EXITED_NONZERO")
if echo "$REJECT_OUT" | grep -qiE 'PCR0|attestation|mismatch'; then
  pass "client rejected wrong PCR0"
else
  fail "PCR0 rejection" "expected an attestation error, got: ${REJECT_OUT:0:200}"
fi

# Test 5: native gRPC SubmitTx (exercises the full RPC payload + framework
# routing for a *write* path, not just GetInfo). Uses a non-finalizer closure
# so introspector signs and returns without dialing the mock-arkd downstream.
echo "[5/6] enclave-client SubmitTx (native gRPC + attestation)"
if [ ! -f "$PCR_FILE" ]; then
  fail "enclave-client SubmitTx" "PCR file not found at $PCR_FILE"
else
  PCR0=$(jq -r '.PCR0' "$PCR_FILE")
  SUBMIT_OUT=$(/usr/local/bin/grpc-client \
    -url "${BASE_URL}" \
    -pcr0 "${PCR0}" \
    -insecure-skip-cose \
    -rpc submit-tx 2>&1 || true)
  if echo "$SUBMIT_OUT" | grep -q '^SubmitTx OK:'; then
    pass "SubmitTx succeeded ($(echo "$SUBMIT_OUT" | grep '^SubmitTx OK:' | head -1 | sed 's/^SubmitTx OK: *//'))"
  else
    fail "enclave-client SubmitTx" "stdout: ${SUBMIT_OUT:0:500}"
  fi
fi

# Test 6: HTTP/1.1 backward compatibility.
echo "[6/6] HTTP/1.1 backward compatibility"
H1_OUT=$(curl -sk --http1.1 -o /dev/null -w '%{http_version}' --max-time 10 \
  "${BASE_URL}/health" 2>/dev/null || echo "")
if [ "$H1_OUT" = "1.1" ]; then
  pass "HTTP/1.1 still serves /health (http_version=$H1_OUT)"
else
  fail "HTTP/1.1 compat" "expected http_version=1.1, got '$H1_OUT'"
fi

echo ""
echo "=== Results: $PASSED passed, $FAILED failed (of $TOTAL) ==="
[ "$FAILED" -gt 0 ] && exit 1
exit 0
