# Liveness Studio

A local browser front end for the MOSIP face-liveness engine (`liveness-core`). It shows what the Java engine does with
camera frames: the live feed, the stages it runs, the integrity checks on the signed capture, and the engine's own
decision. **It never decides anything itself.**

React 19 · TypeScript · Vite · Tailwind 4 · Lucide icons. Fonts are bundled (no CDN), and the page makes no external
requests.

## Run it

```bash
# one time: build the interface (a built copy is served by the engine, so Node is only needed to build or develop)
cd frontend && npm install && npm run build && cd ..

./webcam.sh --ui                 # real camera -> SBI emulator -> Java engine -> this UI (opens your browser)
./webcam.sh --ui --no-open       # print the address instead of opening it
./webcam.sh --video clip.mp4 --ui   # rehearse the real engine path from a video file, no camera needed
```

The engine prints `UI_URL=http://127.0.0.1:<port>/#t=<token>`. The token is random per run and lives in the URL
fragment, so it is never sent anywhere. Press **Ctrl-C** (or call `POST /api/quit`) to stop; the camera and all
processes are released.

The browser and demo modes need no engine at all: `cd frontend && npm run dev` (Node 20.19+ or 22+), open the printed address.

### If `npm install` / `npm test` fails with "Cannot find native binding"

Vite 8 uses a native bundler delivered as an optional dependency, and npm sometimes skips it. Install the one for your
machine without saving it, for example on Apple silicon:

```bash
npm install --no-save @rolldown/binding-darwin-arm64@1.2.15
```

## The three modes

| | Real engine | This browser | Demo |
|---|---|---|---|
| Where it runs | The Java engine on this machine, through the local API | The face models, in this browser tab (ONNX Runtime Web, WebAssembly) | Fixed scripts in `src/lib/demo.ts` |
| Camera | The engine's own feed | Your camera, only after you press Start; analysed on this device | None (optional positioning preview, not analysed) |
| Decisions | The engine's session state machine, including the signed capture | A port of the engine's *passive* rules. **No signed capture exists**, so the best result is **Passive checks passed**, never Verified | Scripted, labelled **Simulated** |
| Uploads | Nothing leaves your machine | **Nothing is uploaded or stored**; models and wasm are static files | Nothing |
| Hosted site | No | Yes | Yes |
| Stored trials | `...trials.v1.real` | `...trials.v1.browser` | `...trials.v1.demo` (never mixed) |

The mode is always visible in the header and each mode has its own banner.

### How "This browser" works

`src/engine/` is a port of the Java pipeline: YuNet detection and decoding, the quality gates (face size, light, sharpness),
MiniFASNet scoring and fusion, the landmark-aligned motion check (affine registration), and the passive session rules
(3 attack frames reject, median at or above 0.80, motion required, 10 s limit). The models are the same files the Java engine
loads (`public/models/`); each is checked against the SHA-256 pinned in `models/onnx/manifest.json` before use.

**Parity with the reference** (`npm run build:parity`, local only, needs the research fixtures): on the 20 golden images the browser
code found the same faces as the Python reference on every image (including three multi-face images), with box and landmark error
0.00 px and PAD scores within 2e-6. The browser decodes JPEGs and scales video differently from OpenCV, so live scores can differ
slightly from the Java engine; nothing here is an accuracy figure.

What the browser **cannot** do: the signed-capture checks (signature, certificate chain, nonce, device identity, replay), the
signed-capture PAD gate, and the stream/capture subject match. Those screens show "unavailable", never "passed".

## The screens

- **Verify**: camera, session status, result with the engine's decision, reason code and next step, and the PAD trace.
- **Pipeline**: the eight stages the engine runs, in its real order, with measured durations.
- **Security integrity**: the checks on the signed capture. A valid signature shows the capture channel is intact; it
  does not prove the person was live.
- **Evaluation lab**: stage a scenario (photo, screen replay, ...), run it, compare *expected* with *engine decided*.
- **Analytics**: from recorded trials only; "No data yet" when empty; small samples are flagged preliminary; CSV/JSON export.
- **Diagnostics**: one trial in detail (events, scores, timings, policy in force).

## What is real and what is not

- Real: the decisions, reason codes, PAD scores, timings, counters, stage and check states (derived from what the
  engine actually did, in the binder's real order) when a real engine is connected.
- Not claimed: accuracy. The PAD model is public and uncalibrated, the device is an emulator with TEST keys, and
  single trials are anecdotes. A trial labelled "attack" is not auto-rejected, and one labelled "genuine" is not
  auto-accepted: the engine never sees the label.

## Tests

```bash
npm run typecheck     # tsc
npm test              # 50 unit tests: outcome mapping, derivation tables, parsing, analytics, export, storage, copy, demo
npm run build         # type-check + production build into dist/
```

Browser checks (camera permission denied, camera missing/busy/disconnected, track cleanup, demo outcomes, cancel and
double-click protection, empty analytics, filters, exports, responsive widths, reduced motion, wrong token, engine
offline) were run with Playwright against the real engine; see `docs/frontend/IMPLEMENTATION_REPORT.md`.
