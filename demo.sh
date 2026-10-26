#!/usr/bin/env bash
# One-command software demo of the face-liveness / capture-binding engine against the MOCK SBI device.
#
#   ./demo.sh            (macOS / Linux; needs Java 11+, curl, and Python 3 with tools/mock-sbi/requirements.txt)
#
# INPUTS ARE SIMULATED (mock device, synthetic face motion, scripted attacks, placeholder PAD model);
# DECISIONS ARE REAL (the actual engine, models, signature verification and policy). [MOCK] evidence only:
# not real-device validation, and nothing here measures PAD accuracy.
# Exit status: 0 = demo ran and no attack was accepted; 2 = an attack was accepted; 1 = setup or run failure.
set -uo pipefail
export ORT_DISABLE_TELEMETRY="${ORT_DISABLE_TELEMETRY-1}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
OUT="$ROOT/demo-output"
JAR="liveness-core/target/liveness-core-phase0-all.jar"
GOLD="research/fixtures/golden"
LFW="research/data/sklearn/lfw_home/lfw"
PORT_LIVE=4791
PORT_STATIC=4792

say() { printf '\n== %s\n' "$*"; }
die() { printf 'demo: %s\n' "$*" >&2; exit 1; }

# ---- prerequisites --------------------------------------------------------------------------------------------------
command -v java >/dev/null || die "Java 11+ not found on PATH"
command -v curl >/dev/null || die "curl not found on PATH"
if [ -x "$ROOT/.tools/.venv/bin/python" ]; then PY="$ROOT/.tools/.venv/bin/python"; else PY="$(command -v python3 || true)"; fi
[ -n "$PY" ] || die "Python 3 not found"
"$PY" -c "import cv2, numpy, cryptography" 2>/dev/null \
  || die "Python packages missing for $PY: run  python3 -m pip install -r tools/mock-sbi/requirements.txt"
[ -f "$GOLD/g02_image_T1.jpg" ] || die "fixtures missing: $GOLD"
[ -f "models/onnx/manifest.json" ] || die "models missing: models/onnx/manifest.json"
SWAP_ALT="$GOLD/g05_Allyson_Felix_0001.jpg"                       # optional LFW data improves the swap scenario only
[ -f "$LFW/Colin_Powell/Colin_Powell_0001.jpg" ] && SWAP_ALT="$LFW/Colin_Powell/Colin_Powell_0001.jpg"
if [ ! -f "$JAR" ]; then
  say "building liveness-core (first run only; Maven downloads dependencies if not cached)"
  MVN="$ROOT/.tools/apache-maven-3.9.9/bin/mvn"; [ -x "$MVN" ] || MVN="$(command -v mvn || true)"
  [ -n "$MVN" ] || die "jar missing and Maven not found (install Maven 3.9+ or build liveness-core first)"
  (cd liveness-core && "$MVN" -B -q -DskipTests package) || die "build failed"
fi
mkdir -p "$OUT"

MOCK_PID=""
cleanup() { [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null; wait "$MOCK_PID" 2>/dev/null; MOCK_PID=""; }
trap cleanup EXIT INT TERM
start_mock() {
  local port=$1; shift
  "$PY" -u tools/mock-sbi/mock_sbi.py --port "$port" --fps 15 "$@" > "$OUT/mock_$port.log" 2>&1 &
  MOCK_PID=$!
  for _ in $(seq 1 60); do
    curl -s -m 1 -X MOSIPDISC "http://127.0.0.1:$port/device" -d '{}' >/dev/null 2>&1 && return 0
    kill -0 "$MOCK_PID" 2>/dev/null || die "mock device failed to start (see $OUT/mock_$port.log)"
    sleep 0.5
  done
  die "mock device did not answer on port $port"
}
scenarios() {
  local port=$1 name=$2; shift 2
  java -Xmx1g -jar "$JAR" session-scenarios --root . --port "$port" --trust tools/mock-sbi/keys/trust.pem \
       --threads 1 --out "$OUT/$name.json" "$@" > /dev/null 2> "$OUT/$name.log" || die "scenario run failed (see $OUT/$name.log)"
}

# ---- run ------------------------------------------------------------------------------------------------------------
say "1/2 live (animated) mock device: genuine user and attacks   [about 1-2 minutes]"
start_mock "$PORT_LIVE" --motion animate --source "$GOLD/g02_image_T1.jpg" \
    --swap-image-alt "$SWAP_ALT" --inject-image "$GOLD/g05_Allyson_Felix_0001.jpg"
# genuine user: 3 independent sessions (the placeholder PAD is uncertain about half the time, so one run may RETRY)
scenarios "$PORT_LIVE" genuine --repeat 3 --scenarios genuine
# attacks and faults (the replay needs an earlier genuine capture from this same mock device)
scenarios "$PORT_LIVE" attacks --scenarios \
    replay-previous-response,txn-mismatch,tamper,stream-inject-other-subject,capture-swap-other-person,skew+30s
cleanup

say "2/2 static-photo mock device (a still photo replayed on the stream)"
start_mock "$PORT_STATIC" --motion static-replay --source "$GOLD/g02_image_T1.jpg"
scenarios "$PORT_STATIC" static --scenarios whole-stream --stream-kind static
cleanup

# ---- summary --------------------------------------------------------------------------------------------------------
"$PY" "$ROOT/tools/demo_summary.py" "$OUT"
STATUS=$?
[ "$STATUS" -eq 0 ] || printf 'demo: an attack was ACCEPTED (exit %s)\n' "$STATUS" >&2
exit "$STATUS"
