# Liveness Studio: face liveness and presentation-attack detection for the MOSIP Registration Client

A research prototype built for MOSIP Decode PS-04. It combines a Java liveness engine (`liveness-core`), a mock SBI face
device with a webcam mode, and a browser interface.

> **Read this first.** This is a prototype, **not production-ready, not security-certified, and it makes no accuracy
> claim.** The presentation-attack model (MiniFASNet) is a public model that has **not** been evaluated or calibrated
> for this setup. The device is an **emulator with TEST keys**, not a certified device, and nothing has run against a real
> SBI device. A single trial is an anecdote, not a measurement. The decision thresholds are provisional.

## Try it without installing anything

**https://liveness-studio.vercel.app** runs the face models **in your own browser** (WebAssembly): press Start, allow the camera,
and the detector, the attack-score model and the motion check run on your device. Nothing is uploaded or stored. A browser has no
certified capture device, so there is no signed capture and the best result is *Passive checks passed*, never *Verified*. A
scripted **Demo** mode is also there.

## What is in this repository

| Path | What it is |
|---|---|
| `liveness-core/` | Java 11 engine and CLI: face detection (YuNet), passive PAD (MiniFASNet), session state machine, signed-capture binding (RS256, nonce, timestamp, replay, device identity), local API |
| `tools/mock-sbi/` | Mock SBI 1.0 face device (MockMDS wire format, fault and attack modes, optional webcam source). **Its keys are TEST-ONLY: never use them anywhere real.** |
| `frontend/` | Liveness Studio (React, TypeScript, Vite, Tailwind). Real-engine and demo-only builds |
| `models/` | Third-party models, their licences, and the hash manifest the engine enforces |
| `docs/` | Architecture proposal, demo script, frontend and deployment notes |
| `webcam.sh`, `demo.sh` | Launchers (see below) |
| `Dockerfile` (in `frontend/`), `docker-compose.yml`, `render.yaml` | Hosting the demo-only site |

Internal research notes, raw experiment results, face datasets and the problem-statement PDF are **not** part of this
public repository (the datasets belong to third parties).

## Run it locally

Prerequisites: JDK 11+ (tested with 21), Maven 3.9+ (first build downloads dependencies), `curl`, Python 3 with
`python3 -m pip install -r tools/mock-sbi/requirements.txt`, and Node 20.19+ or 22+ for the frontend.

```bash
cd frontend && npm install && npm run build && cd ..
./webcam.sh --ui             # your webcam -> SBI emulator -> Java engine -> your browser (local only)
./webcam.sh --headless 3     # three trials without a window; writes webcam-output/report.json
./webcam.sh --video clip.mp4 --ui   # rehearse the real engine path from a video file, no camera needed
```

On macOS, allow camera access for your terminal app first (System Settings, Privacy & Security, Camera).
Details and troubleshooting: `docs/demo/WEBCAM.md` and `frontend/README.md`.

### What will not work from a fresh clone

- **`./demo.sh`** and **part of the Java test suite** need face fixtures from third-party research datasets
  (`research/`). They are not redistributed here, so those parts cannot run without supplying your own fixtures.
- The 50 frontend unit tests (`cd frontend && npm test`) and the build do not need them.

## Live webcam test

```bash
./webcam.sh        # MacBook camera -> SBI emulator (TEST keys) -> real engine; SPACE = new trial, Q = quit
```

Real camera frames go through the same engine path for every trial (a real person or a face video on a screen). The
window shows face detection, stream and capture PAD, latency and the engine's own decision. The device is an emulator
with TEST keys, and the PAD model is a public model **not evaluated** for this setup, so trials are not accuracy
evidence. Setup (macOS camera permission), result meanings and troubleshooting: `docs/demo/WEBCAM.md`.

## Liveness Studio (browser interface)

```bash
cd frontend && npm install && npm run build && cd ..   # once
./webcam.sh --ui                                       # camera -> engine -> your browser, local only
```

A front end for the engine: live camera feed, the stages the engine runs, the integrity checks on the signed capture,
an evaluation lab, analytics from recorded trials and diagnostics. It only displays what the engine reports; it never
decides. **Real engine** and **Demo** (scripted, clearly simulated) are separate modes with separate stored trials.
Setup, screens and limits: `frontend/README.md`; the local API: `docs/frontend/LOCAL_API_DESIGN.md`.

## Deploying the demo

`docs/deploy/DEPLOYMENT.md`. Only the demo-only build is meant to be hosted publicly. The real engine reads a camera on
the machine running it, so it is run locally.

## Licences

Third-party model licences are in `models/third_party/`. Project code licence: to be decided by the owner (none is granted
by default).
