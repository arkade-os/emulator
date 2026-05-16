#!/usr/bin/env bash
# End-to-end local enclave test runner.
#
# Starts mock AWS services, seeds parameters, optionally builds a test EIF
# from the skeleton app, boots it in QEMU, runs smoke tests, and cleans up.
#
# Usage:
#   ./run.sh              Build skeleton test app EIF, then run full test
#   ./run.sh <path-to-eif>  Use a pre-built EIF
#
# Prerequisites (pick one):
#   nix develop ./test   (provides QEMU, vhost-device-vsock, gvproxy, awscli)
#   docker compose --profile test run --build test-runner  (all-in-one Docker)
#
# Additional requirements:
#   docker compose       (for mock services, unless SKIP_MOCK_SERVICES=1)
#   enclave CLI          (for building EIF, only if no EIF path given)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT_PATH="$(realpath "$0")"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$SCRIPT_DIR"

# boot_qemu: bring up AF_VSOCK fabric (vhost-device-vsock + heartbeat),
# then boot the EIF in QEMU emulating a Nitro Enclave. The supervisor,
# running out-of-band, provides gvproxy (vsock:1024) and the IMDS
# forwarder (vsock:8002) — see supervisor/gvproxy.go + supervisor/imds_proxy.go.
#
# Called two ways:
#   1. From run.sh's main flow, via watchdog (ENCLAVE_START_CMD) in the
#      supervisor — invokes this script with `--boot-only <eif>`.
#   2. Directly from run.sh on wait_for_enclave (for manual invocation).
boot_qemu() {
  local eif_path="${1:?Usage: boot_qemu <path-to-eif>}"

  echo $$ > /tmp/enclave-boot.pid

  if [ ! -f "$eif_path" ]; then
    echo "Error: EIF not found at $eif_path" >&2
    return 1
  fi
  eif_path="$(realpath "$eif_path")"

  local guest_cid="${GUEST_CID:-4}"
  local memory="${MEMORY:-4G}"
  local vsock_socket="/tmp/vhost${guest_cid}.socket"
  local boot_timeout="${BOOT_TIMEOUT:-300}"
  local host_tls_port="${HOST_TLS_PORT:-8443}"

  local qemu_pid hb_pid vsock_pid
  qemu_pid="" hb_pid="" vsock_pid=""

  _boot_qemu_cleanup() {
    echo "" 2>/dev/null
    echo "=== Cleaning up ===" 2>/dev/null
    [ -n "$qemu_pid" ] && kill "$qemu_pid" 2>/dev/null && echo "  Stopped QEMU ($qemu_pid)" 2>/dev/null
    [ -n "$hb_pid" ] && kill "$hb_pid" 2>/dev/null && echo "  Stopped heartbeat ($hb_pid)" 2>/dev/null
    [ -n "$vsock_pid" ] && kill "$vsock_pid" 2>/dev/null && echo "  Stopped vhost-device-vsock ($vsock_pid)" 2>/dev/null
    rm -f "$vsock_socket" /tmp/enclave-boot.pid
  }
  trap _boot_qemu_cleanup EXIT

  # Kill any stale processes from previous runs.
  killall vhost-device-vsock 2>/dev/null || true
  pkill -f heartbeat.py 2>/dev/null || true
  sleep 0.5
  rm -f "$vsock_socket"

  if [ ! -e /dev/vsock ]; then
    echo "Error: /dev/vsock not found. Load vsock + vsock_loopback kernel modules." >&2
    return 1
  fi

  echo "=== Starting vhost-device-vsock ==="
  echo "  CID:        $guest_cid"
  echo "  Socket:     $vsock_socket"
  echo "  Forward:    CID 1 (loopback)"
  vhost-device-vsock \
    --vm "guest-cid=${guest_cid},socket=${vsock_socket},forward-cid=1,forward-listen=9001+9002" &
  vsock_pid=$!
  sleep 1
  if ! kill -0 "$vsock_pid" 2>/dev/null; then
    echo "Error: vhost-device-vsock failed to start" >&2
    return 1
  fi

  echo "=== Starting heartbeat responder ==="
  python3 "$SCRIPT_DIR/heartbeat.py" &
  hb_pid=$!
  sleep 0.5
  if ! kill -0 "$hb_pid" 2>/dev/null; then
    echo "Error: heartbeat responder failed to start" >&2
    return 1
  fi

  # gvproxy (L2 networking over vsock:1024) and the IMDS vsock forwarder
  # (vsock:8002) are provided by the out-of-band supervisor. Port
  # forwarding is configured via GVPROXY_FORWARD_PORTS (set below).

  echo ""
  echo "=== Booting QEMU enclave ==="
  echo "  EIF:    $eif_path"
  echo "  Memory: $memory"
  local accel cpu_opt
  if [ -e /dev/kvm ]; then
    accel="--enable-kvm"
    cpu_opt="-cpu host"
    echo "  KVM:    enabled"
  else
    accel="-accel tcg"
    cpu_opt="-cpu max"
    echo "  KVM:    not available, using TCG (slow)"
  fi
  qemu-system-x86_64 \
    -M "nitro-enclave,vsock=c,id=test-enclave" \
    -kernel "$eif_path" \
    -nographic \
    -m "$memory" \
    $accel \
    $cpu_opt \
    -chardev "socket,id=c,path=${vsock_socket}" &
  qemu_pid=$!
  echo "  PID:    $qemu_pid"
  echo ""

  # Wait for the enclave to become ready.
  echo "=== Waiting for enclave to boot (timeout: ${boot_timeout}s) ==="
  local seconds=0
  while [ $seconds -lt "$boot_timeout" ]; do
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
      echo "Error: QEMU exited unexpectedly" >&2
      wait "$qemu_pid" || true
      return 1
    fi
    local http_code
    http_code=$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' \
      "https://localhost:${host_tls_port}/health" 2>/dev/null || echo "000")
    if [ "$http_code" = "200" ] || [ "$http_code" = "503" ]; then
      local health
      health=$(curl -sk --max-time 5 "https://localhost:${host_tls_port}/health" 2>/dev/null || echo "{}")
      echo "  Enclave responding (${seconds}s) — HTTP $http_code"
      echo "  Health: $health"
      echo ""
      echo "=== Enclave running ==="
      echo "  Health:        https://localhost:${host_tls_port}/health"
      echo "  Enclave info:  https://localhost:${host_tls_port}/v1/enclave-info"
      echo "  App:           https://localhost:${host_tls_port}/"
      wait "$qemu_pid"
      return 0
    fi
    sleep 2
    seconds=$((seconds + 2))
  done
  echo "Error: Enclave did not become ready within ${boot_timeout}s" >&2
  return 1
}

# Subcommand dispatch: when invoked as a launcher-shim (from the
# supervisor's ENCLAVE_START_CMD), run just boot_qemu and exit. Avoids
# re-running the main integration-test flow inside the launcher.
if [ "${1:-}" = "--boot-only" ]; then
  shift
  boot_qemu "$@"
  exit $?
fi

# Auto-enter Nix dev shell if required tools are missing.
if ! command -v vhost-device-vsock &>/dev/null || ! command -v qemu-system-x86_64 &>/dev/null; then
  echo "Required tools not found, entering nix develop ..."
  exec nix develop "${SCRIPT_DIR}" --command "$0" "$@"
fi

# Use pre-built binaries (Docker test-runner) or build from source (nix develop).
if command -v enclave-cli &>/dev/null && command -v supervisor &>/dev/null; then
  ENCLAVE_CLI="$(command -v enclave-cli)"
  ENCLAVE_SUPERVISOR="$(command -v supervisor)"
  echo "Using pre-built binaries"
elif command -v go &>/dev/null; then
  ENCLAVE_CLI="/tmp/enclave-cli"
  ENCLAVE_SUPERVISOR="/tmp/supervisor"
  echo "Building enclave CLI and supervisor..."
  (cd "$REPO_ROOT" && go build -o "$ENCLAVE_CLI" ./cli/cmd/enclave)
  (cd "$REPO_ROOT" && go build -o "$ENCLAVE_SUPERVISOR" ./supervisor/cmd/supervisor)
  # Seed the artifacts dir with the real v1 supervisor binary so the first
  # tofu_apply uploads it (not an empty placeholder) to the staging S3
  # key. Step 7 later overwrites this file with a v2 variant to force
  # Step 10 down the swap path.
  mkdir -p "${SCRIPT_DIR}/app/.enclave/artifacts"
  cp "$ENCLAVE_SUPERVISOR" "${SCRIPT_DIR}/app/.enclave/artifacts/supervisor"
else
  echo "Error: neither pre-built binaries (enclave-cli, supervisor) nor Go compiler found" >&2
  exit 1
fi


echo "  CLI:  $ENCLAVE_CLI"
echo "  Supervisor: $ENCLAVE_SUPERVISOR"
echo ""

# Reset image.eif to pristine v1; migration test-runs overwrite it.
V1_EIF="${SCRIPT_DIR}/app/.enclave/artifacts/image-v1.eif"
if [ -f "$V1_EIF" ]; then
  echo "  Resetting image.eif to pristine v1..."
  cp -f "$V1_EIF" "${SCRIPT_DIR}/app/.enclave/artifacts/image.eif"
  cp -f "${SCRIPT_DIR}/app/.enclave/artifacts/pcr-v1.json" \
        "${SCRIPT_DIR}/app/.enclave/artifacts/pcr.json" 2>/dev/null || true
fi
rm -f "${SCRIPT_DIR}/app/.enclave/artifacts/image.eif.backup"
: > /tmp/boot-qemu.log


# --- OpenTofu helpers ---
TOFU_DIR="${SCRIPT_DIR}/app/tofu"
LOCALSTACK="--endpoint-url http://127.0.0.1:4566 --region us-east-1"
export ENCLAVE_CONFIG="${SCRIPT_DIR}/app/enclave/enclave.yaml"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
# AWS CLI endpoint overrides for localstack — needed by null_resource local-exec
# provisioners which bypass the tofu provider config.
export AWS_ENDPOINT_URL_KMS="${AWS_ENDPOINT_URL_KMS:-http://127.0.0.1:4566}"
export AWS_ENDPOINT_URL_SSM="${AWS_ENDPOINT_URL_SSM:-http://127.0.0.1:4566}"
export AWS_ENDPOINT_URL_STS="${AWS_ENDPOINT_URL_STS:-http://127.0.0.1:4566}"
export AWS_ENDPOINT_URL_S3="${AWS_ENDPOINT_URL_S3:-http://127.0.0.1:4566}"

tofu_apply() {
  # Always regenerate tfvars — paths differ between host and Docker.
  # `enclave tofu` is merge-only-new (existing files are skipped) so the
  # committed test-app scaffold would mask CLI changes. Delete the
  # CLI-managed root and module main.tf first to force a fresh emit; the
  # rest of the tree (modules/backend, templates, etc.) is left untouched.
  rm -f "${TOFU_DIR}/main.tf" "${TOFU_DIR}/modules/enclave/main.tf"

  echo "  Generating terraform.tfvars.json..."

  # Ensure artifact placeholders exist for tofu's filemd5() (local mode
  # doesn't actually use these S3 objects — the enclave boots from QEMU).
  # Only image.eif and supervisor are uploaded now; gvproxy is vendored
  # into the supervisor binary itself.
  mkdir -p "${SCRIPT_DIR}/app/.enclave/artifacts"
  for f in image.eif supervisor; do
    [ -f "${SCRIPT_DIR}/app/.enclave/artifacts/$f" ] || touch "${SCRIPT_DIR}/app/.enclave/artifacts/$f"
  done

  (cd "${SCRIPT_DIR}/app" && LOCAL_DEPLOYMENT=true "$ENCLAVE_CLI" tofu > "${SCRIPT_DIR}/tofu-scaffold.log" 2>&1) \
    || { cat "${SCRIPT_DIR}/tofu-scaffold.log"; return 1; }

  # Write local backend config for testing (enclave build generates S3 backend.tf for production).
  cat > "${TOFU_DIR}/backend.tf" <<BACKEND
terraform {
  backend "local" {
    path = "${TOFU_DIR}/terraform.tfstate"
  }
}
BACKEND

  # Override provider to point at localstack.
  cat > "${TOFU_DIR}/provider_override.tf" <<'OVERRIDE'
provider "aws" {
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  endpoints {
    s3  = "http://127.0.0.1:4566"
    ssm = "http://127.0.0.1:4566"
    sts = "http://127.0.0.1:4566"
    iam = "http://127.0.0.1:4566"
    kms = "http://127.0.0.1:4566"
    ec2 = "http://127.0.0.1:4566"
  }
}
OVERRIDE

  echo "  tofu init..."
  tofu -chdir="$TOFU_DIR" init -input=false > ${SCRIPT_DIR}/tofu-init.log 2>&1 || { cat ${SCRIPT_DIR}/tofu-init.log; return 1; }
  # env_values overrides are supplied via an auto-loaded tfvars file (the env-file
  # mechanism). tofu auto-loads any *.auto.tfvars.json next to the root module on
  # every plan/apply, so overrides stick across both the initial deploy and the
  # later migration apply without us repeating them on the command line.
  cat > "${TOFU_DIR}/env_values.auto.tfvars.json" <<EOF
{
  "env_values": {
    "TEST_RUNTIME_OVERRIDE": "override-from-tofu",
    "TEST_RUNTIME_OVERRIDE_ENVFILE": "override-from-envfile"
  }
}
EOF

  echo "  tofu apply..."
  tofu -chdir="$TOFU_DIR" apply -auto-approve -input=false -compact-warnings > ${SCRIPT_DIR}/tofu-apply.log 2>&1 || { echo "  tofu apply FAILED:"; tail -20 ${SCRIPT_DIR}/tofu-apply.log; return 1; }
  echo "  tofu apply OK (log: ${SCRIPT_DIR}/tofu-apply.log)"
}

tofu_destroy() {
  # Ensure provider override + tfvars exist for destroy to work.
  if [ -f "${TOFU_DIR}/terraform.tfstate" ]; then
    tofu -chdir="$TOFU_DIR" destroy -auto-approve -input=false > ${SCRIPT_DIR}/tofu-destroy.log 2>&1 || true
  fi
  rm -f "${TOFU_DIR}/terraform.tfstate"* "${TOFU_DIR}/provider_override.tf" "${TOFU_DIR}/backend.tf" 2>/dev/null || true
  rm -rf "${TOFU_DIR}/.terraform" "${TOFU_DIR}/.artifacts" 2>/dev/null || true
}

EIF_PATH="${1:-}"
SUP_PID=""

cleanup() {
  echo ""
  echo "=== Tearing down ==="
  tofu_destroy
  # Kill supervisor relauncher (which TERM-traps and kills its child supervisor).
  [ -n "${SUP_PID:-}" ] && kill -TERM "$SUP_PID" 2>/dev/null && wait "$SUP_PID" 2>/dev/null || true
  # Belt-and-suspenders: if the supervisor's child survived, kill it too.
  if [ -f /tmp/supervisor.pid ]; then
    kill "$(cat /tmp/supervisor.pid)" 2>/dev/null || true
    rm -f /tmp/supervisor.pid
  fi
  rm -f /tmp/supervisor-relauncher.sh
  # Kill enclave (boot_qemu) via PID file.
  if [ -f /tmp/enclave-boot.pid ]; then
    kill "$(cat /tmp/enclave-boot.pid)" 2>/dev/null || true
    sleep 1
  fi
  echo "Destroy Mock Services..."
  docker compose down -v 2>/dev/null || true
  echo "Done."
}
trap cleanup EXIT

# Wait for enclave Init to complete (health returns 200).
# Reads boot PID from /tmp/enclave-boot.pid to detect crashes.
wait_for_enclave() {
  local label="${1:-}"
  local boot_timeout="${BOOT_TIMEOUT:-300}"
  local init_timeout="${INIT_TIMEOUT:-120}"

  echo "  Waiting for enclave boot (timeout: ${boot_timeout}s)..."
  SECONDS=0
  while [ $SECONDS -lt "$boot_timeout" ]; do
    # Check if boot_qemu is still running.
    if [ -f /tmp/enclave-boot.pid ]; then
      local pid
      pid=$(cat /tmp/enclave-boot.pid)
      if ! kill -0 "$pid" 2>/dev/null; then
        echo "Error: boot_qemu exited unexpectedly${label:+ ($label)}" >&2
        exit 1
      fi
    fi
    HTTP_CODE=$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' \
      "https://localhost:${HOST_TLS_PORT:-8443}/health" 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "503" ]; then
      echo "  Enclave responding (${SECONDS}s) — HTTP $HTTP_CODE"
      break
    fi
    sleep 2
  done

  if [ $SECONDS -ge "$boot_timeout" ]; then
    echo "Error: enclave did not become ready within ${boot_timeout}s${label:+ ($label)}" >&2
    exit 1
  fi

  echo "  Waiting for Init to complete (timeout: ${init_timeout}s)..."
  SECONDS=0
  while [ $SECONDS -lt "$init_timeout" ]; do
    if [ -f /tmp/enclave-boot.pid ]; then
      local pid
      pid=$(cat /tmp/enclave-boot.pid)
      if ! kill -0 "$pid" 2>/dev/null; then
        echo "Error: boot_qemu exited unexpectedly${label:+ ($label)}" >&2
        exit 1
      fi
    fi
    HTTP_CODE=$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' \
      "https://localhost:${HOST_TLS_PORT:-8443}/health" 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then
      echo "  Init complete (${SECONDS}s)"
      break
    fi
    if [ "$HTTP_CODE" = "503" ]; then
      STATUS=$(curl -sk --max-time 5 "https://localhost:${HOST_TLS_PORT:-8443}/v1/enclave-info" 2>/dev/null \
        | jq -r '.error // "unknown"' 2>/dev/null || echo "unknown")
      echo "  Init in progress (${SECONDS}s): $STATUS"
    fi
    sleep 5
  done

  if [ $SECONDS -ge "$init_timeout" ]; then
    echo "Error: Init did not complete within ${init_timeout}s${label:+ ($label)}" >&2
    curl -sk --max-time 5 "https://localhost:${HOST_TLS_PORT:-8443}/v1/enclave-info" 2>/dev/null || true
    echo ""
    echo "  Boot log (errors and init):"
    grep -i 'error\|fail\|init\|KMS\|secret\|policy\|decrypt' /tmp/boot-qemu.log 2>/dev/null | tail -30 | sed 's/^/    /' || echo "    (no boot log)"
    echo ""
    echo "  runtime init logs (Application says):"
    grep 'Application says' /tmp/boot-qemu.log 2>/dev/null | head -30 | sed 's/^/    /' || echo "    (none)"
    exit 1
  fi
}

echo "==============================="
echo " Enclave Local Test Runner"
echo "==============================="
echo ""

# Detect if running inside Docker test-runner (no Nix, no docker CLI).
IN_DOCKER=false
if [ -f /.dockerenv ] || grep -q docker /proc/1/cgroup 2>/dev/null; then
  IN_DOCKER=true
fi

# Step 0: Build test EIF from skeleton app.
echo "=== [0/9] Building test EIF from skeleton app ==="
if [ -n "$EIF_PATH" ] && [ -f "$EIF_PATH" ]; then
  echo "  Using provided EIF: $EIF_PATH"
elif [ "$IN_DOCKER" = true ]; then
  # Inside Docker: use pre-built EIFs from mounted volume (built on host).
  if [ -f "app/.enclave/artifacts/image.eif" ]; then
    EIF_PATH="app/.enclave/artifacts/image.eif"
    echo "  Using pre-built EIF: $EIF_PATH"
    if [ -f "app/.enclave/artifacts/image-v2.eif" ]; then
      echo "  Migration EIF: app/.enclave/artifacts/image-v2.eif"
    else
      echo "  WARN: No migration EIF (image-v2.eif) — Step 7 will reuse same EIF"
    fi
  else
    echo "  Error: EIF must be pre-built when running inside Docker" >&2
    echo "  Build it on the host first: cd test/app && enclave build" >&2
    exit 1
  fi
else
  # On host: build v1 EIF, then v2 with different version for migration testing.
  ENCLAVE_YAML="${SCRIPT_DIR}/app/enclave/enclave.yaml"
  ARTIFACTS="${SCRIPT_DIR}/app/.enclave/artifacts"
  ORIG_VERSION=$(grep '^version:' "$ENCLAVE_YAML" | awk '{print $2}')

  echo "  Building v1 EIF (version ${ORIG_VERSION})..."
  (cd app && "$ENCLAVE_CLI" build)
  EIF_PATH="app/.enclave/artifacts/image.eif"
  V1_PCR0=$(jq -r '.PCR0' "${ARTIFACTS}/pcr.json")
  cp "${ARTIFACTS}/pcr.json" "${ARTIFACTS}/pcr-v1.json"
  echo "  v1 PCR0: ${V1_PCR0:0:16}..."

  # Build v2 with previous_pcr0 set to v1's PCR0.
  # This exercises the runtime's previousPCR0 validation during v2 Init:
  # the enclave checks that ENCLAVE_PREVIOUS_PCR0 (baked from enclave.yaml)
  # matches MigrationPreviousPCR0 in SSM (stored by v1's start-migration).
  echo "  Building v2 EIF (version 0.0.2, previous_pcr0=${V1_PCR0:0:16}...)..."
  sed -i 's/^version: .*/version: 0.0.2/' "$ENCLAVE_YAML"
  if grep -q '^previous_pcr0:' "$ENCLAVE_YAML"; then
    sed -i "s/^previous_pcr0: .*/previous_pcr0: \"${V1_PCR0}\"/" "$ENCLAVE_YAML"
  else
    echo "" >> "$ENCLAVE_YAML"
    echo "previous_pcr0: \"${V1_PCR0}\"" >> "$ENCLAVE_YAML"
  fi
  (cd app && "$ENCLAVE_CLI" build)
  cp "${ARTIFACTS}/image.eif" "${ARTIFACTS}/image-v2.eif"
  cp "${ARTIFACTS}/pcr.json" "${ARTIFACTS}/pcr-v2.json"
  echo "  v2 PCR0: $(jq -r '.PCR0' "${ARTIFACTS}/pcr-v2.json" | cut -c1-16)..."

  # Restore v1 as the active EIF (genesis for first boot).
  sed -i "s/^version: .*/version: ${ORIG_VERSION}/" "$ENCLAVE_YAML"
  sed -i '/^previous_pcr0:/d' "$ENCLAVE_YAML"
  (cd app && "$ENCLAVE_CLI" build)
  echo "  Restored v1"
fi
echo ""

# Step 1: Start mock services (skipped inside Docker — compose handles it).
echo "=== [1/9] Starting mock services ==="
if [ "$IN_DOCKER" = true ]; then
  echo "  Skipped (services managed by docker compose)"
else
  docker compose down -v 2>/dev/null || true
  docker compose up -d --build --wait
fi
echo ""

# Step 2: Deploy to localstack via OpenTofu and start supervisor.
echo "=== [2/9] Deploying to localstack via tofu ==="

# Clean up any stale state from previous runs.
tofu_destroy

tofu_apply

# tofu leaves SSM /dev/my-app/KMSKeyID = "UNSET"; the enclave's EnsureKeyID
# calls CreateKey on the first boot, registers the new ID, and locks the
# policy to its own PCR0 at creation time.

# Start supervisor on the host (like production EC2 host).
# Configured with stop/start commands that manage boot_qemu via PID file.
# We run supervisor under a tiny relauncher script that loops "run supervisor; wait;
# relaunch" — the test's analog of systemd Restart=always in production.
# This lets ENCLAVE_SUPERVISOR_RESTART_CMD just kill the current supervisor process; the
# supervisor resurrects it with the updated on-disk binary.
echo "  Starting supervisor..."
EIF_ABS_PATH="$(realpath "$EIF_PATH")"

SUPERVISOR_PIDFILE=/tmp/supervisor.pid
SUP_RELAUNCHER=/tmp/supervisor-relauncher.sh
cat > "$SUP_RELAUNCHER" <<'SUPER'
#!/usr/bin/env bash
set -u
SUP_BIN="$1"
PIDFILE="$2"
child=""
trap '[ -n "$child" ] && kill -TERM "$child" 2>/dev/null; [ -n "$child" ] && wait "$child" 2>/dev/null; rm -f "$PIDFILE"; exit 0' TERM INT
while :; do
  "$SUP_BIN" &
  child=$!
  echo "$child" > "$PIDFILE"
  wait "$child" 2>/dev/null || true
  sleep 1
done
SUPER
chmod +x "$SUP_RELAUNCHER"

export ENCLAVE_AWS_REGION=us-east-1
export ENCLAVE_DEPLOYMENT="${ENCLAVE_DEPLOYMENT:-dev}"
export ENCLAVE_APP_NAME="${ENCLAVE_APP_NAME:-my-app}"
export ENCLAVE_SUPERVISOR_ADDR="127.0.0.1:8444"
# The supervisor runs in-process gvproxy (vsock:1024) and IMDS forwarder
# (vsock:8002) just as it does in prod. Only the enclave launcher differs:
# QEMU stands in for nitro-cli via ENCLAVE_START_CMD below.
#
# Forward enclave TLS (443 inside) to unprivileged 8443 on the host so
# the test can curl https://localhost:8443/health without root.
export GVPROXY_FORWARD_PORTS="8443:443 7073"
# Point the in-process IMDS forwarder at mock-imds instead of the real
# 169.254.169.254 (which isn't reachable from the test container).
export IMDS_PROXY_TARGET="127.0.0.1:1338"
export ENCLAVE_MIGRATION_COOLDOWN="1m"
# Shorten commit-poll timeout so rollback tests don't wait 5min for the default.
export ENCLAVE_MIGRATION_COMMIT_TIMEOUT="45s"
export ENCLAVE_URL="https://127.0.0.1:8443"
export ENCLAVE_EIF_PATH="$EIF_ABS_PATH"
export ENCLAVE_SUPERVISOR_BINARY_PATH="$ENCLAVE_SUPERVISOR"
export ENCLAVE_SUPERVISOR_RESTART_CMD="kill \$(cat $SUPERVISOR_PIDFILE)"
export ENCLAVE_STOP_CMD="kill \$(cat /tmp/enclave-boot.pid) 2>/dev/null; sleep 3"
export ENCLAVE_START_CMD="nohup \"$SCRIPT_PATH\" --boot-only \"$EIF_ABS_PATH\" >> /tmp/boot-qemu.log 2>&1 &"
export AWS_ENDPOINT_URL_KMS="http://127.0.0.1:4000"
export AWS_ENDPOINT_URL_SSM="http://127.0.0.1:4566"
export AWS_ENDPOINT_URL_STS="http://127.0.0.1:4566"
export AWS_ENDPOINT_URL_S3="http://127.0.0.1:4566"
export AWS_ENDPOINT_URL_LOGS="http://127.0.0.1:4566"
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

"$SUP_RELAUNCHER" "$ENCLAVE_SUPERVISOR" "$SUPERVISOR_PIDFILE" &
SUP_PID=$!
sleep 2

if ! kill -0 "$SUP_PID" 2>/dev/null; then
  echo "Error: supervisor relauncher failed to start" >&2
  exit 1
fi
if [ ! -s "$SUPERVISOR_PIDFILE" ]; then
  echo "Error: supervisor pidfile not populated by relauncher" >&2
  exit 1
fi
echo "  Supervisor relauncher running (PID $SUP_PID), supervisor child PID $(cat "$SUPERVISOR_PIDFILE") on http://127.0.0.1:8444"
echo ""

# Step 3: The supervisor's watchdog launches the enclave via
# ENCLAVE_START_CMD (→ boot_qemu) on its own. We just wait for it to
# come up.
echo "=== [3/9] Booting enclave in QEMU ==="
wait_for_enclave "initial boot"
echo ""

# Verify the locked KMS policy includes the default RootRecovery statement.
# The enclave's selfApplyKMSPolicy() runs at boot and calls PutKeyPolicy on
# the local-kms mock (port 4000). After boot, the policy should carry the
# fourth statement granting AWS account root the recovery action set.
KMS_KEY_ID=$(aws ssm get-parameter --name "/dev/my-app/KMSKeyID" \
  --endpoint-url "http://127.0.0.1:4566" --region us-east-1 \
  --query 'Parameter.Value' --output text 2>/dev/null || echo "")
if [ -n "$KMS_KEY_ID" ]; then
  POLICY=$(aws kms get-key-policy --key-id "$KMS_KEY_ID" --policy-name default \
    --endpoint-url "http://127.0.0.1:4000" --region us-east-1 \
    --query 'Policy' --output text 2>/dev/null || echo "")
  if echo "$POLICY" | jq -e '.Statement[] | select(.Sid=="RootRecovery") | (.Action | index("kms:PutKeyPolicy"))' >/dev/null 2>&1; then
    RR_PRINCIPAL=$(echo "$POLICY" | jq -r '.Statement[] | select(.Sid=="RootRecovery") | .Principal.AWS')
    echo "  PASS: KMS policy includes RootRecovery with kms:PutKeyPolicy (principal=${RR_PRINCIPAL})"
  else
    echo "  FAIL: KMS policy missing RootRecovery + kms:PutKeyPolicy (default is_kms_key_locked=false should produce this)" >&2
    echo "  policy: $POLICY" >&2
    exit 1
  fi
  # Sanity: root must NOT have direct Decrypt — recovery is via PutKeyPolicy.
  if echo "$POLICY" | jq -e '.Statement[] | select(.Sid=="RootRecovery") | (.Action | index("kms:Decrypt"))' >/dev/null 2>&1; then
    echo "  FAIL: RootRecovery must not grant kms:Decrypt directly to root (breaks attested-only-decrypt invariant)" >&2
    exit 1
  fi
else
  echo "  WARN: could not read KMSKeyID from SSM, skipping policy check"
fi
echo ""

# Step 4: Run integration tests.
echo "=== [4/9] Running integration tests ==="
./integration-test.sh
echo ""

# === [4/4] Done. Migration / rollback / recovery phases not exercised in
# the introspector test — those are covered by the introspector-enclave
# test suite. Tear down here for a fast turnaround.
echo ""
echo "=== Teardown ==="
if [ -f /tmp/enclave-boot.pid ]; then
  kill "$(cat /tmp/enclave-boot.pid)" 2>/dev/null || true
fi
echo "Done."
