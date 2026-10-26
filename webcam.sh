#!/usr/bin/env bash
# Live webcam test of the face-liveness engine.
#
#   ./webcam.sh                    MacBook webcam (camera 0), window with live decisions; SPACE = new trial, Q = quit
#   ./webcam.sh --camera 1         another camera index
#   ./webcam.sh --video clip.mp4   replay a video file through the SAME path (rehearsal, no camera)
#   ./webcam.sh --headless 3       3 trials without a window (prints results, writes webcam-output/report.json)
#   ./webcam.sh --ui               Liveness Studio in your browser (local only; needs: cd frontend && npm install && npm run build)
#   ./webcam.sh --ui --no-open     same, but only print the URL
#
# Path: camera -> SBI EMULATOR (tools/mock-sbi, TEST keys, NOT a certified device) -> SBI STREAM/RCAPTURE ->
# the real Java engine (face detection, MiniFASNet PAD, session rules, signed-capture binding). The decision shown is
# the engine's. The PAD model is a public model NOT evaluated for this setup: single trials are not accuracy evidence.
set -uo pipefail
export ORT_DISABLE_TELEMETRY="${ORT_DISABLE_TELEMETRY-1}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
OUT="$ROOT/webcam-output"
JAR="liveness-core/target/liveness-core-phase0-all.jar"
PORT=4795
SOURCE="0"
HEADLESS=""
UI=""
OPEN="--open-browser"
while [ $# -gt 0 ]; do
  case "$1" in
    --camera) SOURCE="$2"; shift 2 ;;
    --video) SOURCE="$2"; [ -f "$SOURCE" ] || { echo "webcam: video not found: $SOURCE" >&2; exit 1; }; shift 2 ;;
    --headless) HEADLESS="$2"; shift 2 ;;
    --ui) UI=1; shift ;;
    --no-open) OPEN=""; shift ;;
    *) echo "webcam: unknown option $1" >&2; exit 1 ;;
  esac
done
die() { printf 'webcam: %s\n' "$*" >&2; exit 1; }

command -v java >/dev/null || die "Java 11+ not found on PATH"
command -v curl >/dev/null || die "curl not found on PATH"
if [ -x "$ROOT/.tools/.venv/bin/python" ]; then PY="$ROOT/.tools/.venv/bin/python"; else PY="$(command -v python3 || true)"; fi
[ -n "$PY" ] || die "Python 3 not found"
"$PY" -c "import cv2, numpy, cryptography" 2>/dev/null \
  || die "Python packages missing for $PY: run  python3 -m pip install -r tools/mock-sbi/requirements.txt"
if [ ! -f "$JAR" ]; then
  MVN="$ROOT/.tools/apache-maven-3.9.9/bin/mvn"; [ -x "$MVN" ] || MVN="$(command -v mvn || true)"
  [ -n "$MVN" ] || die "jar missing and Maven not found"
  echo "building liveness-core (first run only)"
  (cd liveness-core && "$MVN" -B -q -DskipTests package) || die "build failed"
fi
mkdir -p "$OUT"

MOCK_PID=""
cleanup() { [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null; wait "$MOCK_PID" 2>/dev/null; MOCK_PID=""; }
trap cleanup EXIT INT TERM
echo "starting SBI emulator on camera '$SOURCE' (first time on macOS: allow camera access for your terminal app)"
"$PY" -u tools/mock-sbi/mock_sbi.py --port "$PORT" --fps 15 --camera "$SOURCE" > "$OUT/emulator.log" 2>&1 &
MOCK_PID=$!
for _ in $(seq 1 80); do
  curl -s -m 1 -X MOSIPDISC "http://127.0.0.1:$PORT/device" -d '{}' >/dev/null 2>&1 && break
  if ! kill -0 "$MOCK_PID" 2>/dev/null; then
    tail -3 "$OUT/emulator.log" >&2
    die "SBI emulator stopped (camera not available?). See $OUT/emulator.log and docs/demo/WEBCAM.md"
  fi
  sleep 0.25
done
curl -s -m 1 -X MOSIPDISC "http://127.0.0.1:$PORT/device" -d '{}' >/dev/null 2>&1 || die "SBI emulator did not start"

ARGS=(webcam-live --root . --port "$PORT" --trust tools/mock-sbi/keys/trust.pem --out "$OUT/report.json")
[ -n "$HEADLESS" ] && ARGS+=(--headless --trials "$HEADLESS")
if [ -n "$UI" ]; then
  [ -f "frontend/dist/index.html" ] || echo "note: frontend not built, the API will run without a page. Build it: cd frontend && npm install && npm run build" >&2
  ARGS+=(--serve --camera-label "$SOURCE" --ui-dir frontend/dist)
  [ -n "$OPEN" ] && ARGS+=("$OPEN")
  echo "Liveness Studio will print its URL below (local only, token-protected). Press Ctrl-C to stop." >&2
fi
# extra engine options for experiments, e.g.  WEBCAM_ARGS="--embed-every 2" ./webcam.sh   (word-split on purpose)
# shellcheck disable=SC2206
[ -n "${WEBCAM_ARGS:-}" ] && ARGS+=($WEBCAM_ARGS)
java -Xmx1g -jar "$JAR" "${ARGS[@]}"
STATUS=$?
echo "trial report: $OUT/report.json"
exit "$STATUS"
