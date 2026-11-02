# Liveness Studio: project documentation

Face liveness and presentation-attack detection (PAD) for the MOSIP Registration Client. Built for MOSIP Decode, problem
statement PS-04.

**Who this is for:** evaluators who want to understand what was built and how far to trust it, and engineers who want to run,
change or extend it. Start with sections 1 and 2; the rest is reference.

**Status in one paragraph.** This is a research prototype. The engine, the local API, the browser interface and the tests work
and have been run end to end. The attack-detection model is a **public model that has not been evaluated or calibrated** for this
setup, the capture device is an **emulator with test keys** rather than a certified device, and **no real SBI device, reference
host or accuracy measurement exists**. Nothing here is production-ready or security-certified, and no accuracy claim is made.

---

## Contents

1. [What it is and what it is not](#1-what-it-is-and-what-it-is-not)
2. [Try it in two minutes](#2-try-it-in-two-minutes)
3. [How it works](#3-how-it-works)
4. [How a decision is made](#4-how-a-decision-is-made)
5. [Security model](#5-security-model)
6. [The three modes](#6-the-three-modes)
7. [Repository tour](#7-repository-tour)
8. [Local API reference](#8-local-api-reference)
9. [Settings and thresholds](#9-settings-and-thresholds)
10. [Testing and verification](#10-testing-and-verification)
11. [Deployment](#11-deployment)
12. [Privacy and data handling](#12-privacy-and-data-handling)
13. [Known limitations](#13-known-limitations)
14. [Troubleshooting](#14-troubleshooting)
15. [Glossary](#15-glossary)
16. [Credits and licences](#16-credits-and-licences)

---

## 1. What it is and what it is not

The MOSIP Registration Client captures a face through a certified device (the *SBI*, Secure Biometric Interface). The device
offers two things: a live **video stream** (unsigned) and a **signed capture** (the image that is actually enrolled). A common
weakness follows from that split: someone can show a live face on the stream and put a photo, a screen or another person at the
moment of capture.

This project checks both channels and ties them together:

- **On the stream:** detects the face, checks its quality, scores each frame with a PAD model, and looks for natural facial
  movement so a still image cannot pass.
- **On the capture:** verifies the device signature and certificate chain, that the response answers this request (fresh nonce),
  is recent, comes from the same device, was not seen before, and shows the **same person** as the stream.
- **In the session:** a fail-closed state machine with attempt limits, which separates *attacks by the person* from *tampering on
  the device channel*, so an attacker cannot lock a genuine person out.

It ships as three parts: a Java engine (`liveness-core`), a mock SBI device with a webcam mode (`tools/mock-sbi`), and a browser
interface called **Liveness Studio** (`frontend`).

**What it is not.** It is not a certified liveness product, it has not been tested against real devices or real attacks, and a
single trial it shows is an anecdote, not a measurement. See [section 13](#13-known-limitations).

## 2. Try it in two minutes

### Option A: the hosted site (nothing to install)

Open **https://liveness-studio.vercel.app**. Choose **This browser**, press **Start verification**, and allow the camera.
The face models run on your device; nothing is uploaded. Smile or speak naturally for a few seconds (blinking alone is often too
small for the motion check to register). The best possible result is **Passive checks passed**. It can never say *Verified*,
because a browser has no signed capture. **Demo** mode plays scripted, clearly labelled simulated outcomes.

### Option B: the full engine on your own machine

Prerequisites: JDK 11 or newer, Maven 3.9+, `curl`, Python 3 with the packages in `tools/mock-sbi/requirements.txt`, and
Node 20.19+ or 22+ to build the interface.

```bash
python3 -m pip install -r tools/mock-sbi/requirements.txt
cd frontend && npm install && npm run build && cd ..
./webcam.sh --ui          # your webcam -> SBI emulator -> Java engine -> your browser
```

On macOS, first allow camera access for your terminal app (System Settings, Privacy & Security, Camera). Stop with **Ctrl-C**.

Other launchers:

| Command | What it does |
|---|---|
| `./webcam.sh --ui --no-open` | Same, but prints the address instead of opening a browser |
| `./webcam.sh --video clip.mp4 --ui` | Runs the real engine path on a video file; no camera needed |
| `./webcam.sh --headless 3` | Three trials without a window; writes `webcam-output/report.json` |
| `./webcam.sh` | The older desktop window (SPACE or 1/2/3 starts a trial, Q quits) |
| `./demo.sh` | Scripted attack scenarios against the mock device (needs research fixtures that are not published) |

### Reading a result

The decision is always the engine's own. `Verified` means every stage passed including a signed capture. `Retry required`
means the engine is not confident and fails closed (this is normal, not an error). `Rejected` means evidence of an attack or of a
different person. `Passive checks passed` (browser mode only) means the passive stages passed with no signed capture.

## 3. How it works

```
 camera ──> SBI device (emulator in this project)
               │ 15 fps M-JPEG stream (unsigned)         │ signed capture on request (RS256 JWS, ISO 19794-5 face record)
               ▼                                         ▼
        ┌───────────────────── liveness-core (Java) ─────────────────────┐
        │  per frame:  decode → YuNet face detection → quality gates     │
        │              → MiniFASNet PAD (2 scales, fused) → aligned crop │
        │  session:    attack count · median score · motion check        │
        │              READY? ──yes──> request signed capture (fresh nonce)
        │  capture:    signature → chain → replay → device → nonce →     │
        │              time window → record format → one face →          │
        │              PAD gate → same person as the stream              │
        │  decision:   VERIFIED / RETRY / REJECTED (+ attribution)       │
        └───────────────┬────────────────────────────────────────────────┘
                        │ local HTTP API (loopback, token) 
                        ▼
              Liveness Studio (browser)  ── or ──  the same passive pipeline running in the browser (no capture)
```

**One driver.** A single thread advances the session and triggers the signed capture; everything else only reads. The browser
interface never decides anything: it renders the engine's outcome.

**Stages, in the order the engine runs them**

| # | Stage | Model or rule |
|---|---|---|
| 1 | Face detection | YuNet (OpenCV Zoo, MIT); exactly one face required |
| 2 | Image-quality gates | face height, brightness, sharpness |
| 3 | Passive attack check | MiniFASNetV2 (wide context) and V1SE (tight context), fused by averaging P(real) |
| 4 | Temporal evidence | landmark-aligned crops registered by affine Lucas-Kanade; needs real facial movement |
| 5 | Signed capture and device integrity | RS256, trust chain, replay, device identity, nonce, time window, record format, face count |
| 6 | Signed-capture PAD gate | the same PAD model on the signed image |
| 7 | Subject match | SFace embeddings: is the capture the same person seen on the stream? |
| 8 | Engine decision | the session state machine |

## 4. How a decision is made

All numbers are the **current defaults**: provisional, uncalibrated, and chosen for the mock device and test data. None is an
accuracy claim. They are read from the engine, never hard-coded in the interface.

**Frame level** (a frame that fails a gate is kept but never scored):

| Check | Rule |
|---|---|
| Face count | exactly 1 (detector score at least 0.6) |
| Face size | height at least 80 px (in the 960-wide analysis frame) |
| Exposure | mean grey between 40 and 220 |
| Sharpness | Laplacian variance at least 15 |
| Frozen frame | a byte-identical repeat of the previous frame is never evidence |

**Passive stage** (collecting evidence, 10 s limit):

| Rule | Value |
|---|---|
| Attack | 3 or more frames in the attempt scoring below **0.20** → rejected (`STREAM_PAD_ATTACK`) |
| Enough evidence | at least 8 usable frames spanning at least 1 s in the last 3 s |
| Motion | at least one frame pair above the motion trigger (0.40) in the last 5 s, from at least 10 pairs; otherwise `STATIC_REPLAY_SUSPECT` |
| Confidence | median (lower) score over the last 3 s at least **0.80**, otherwise `PASSIVE_UNCERTAIN_NO_CHALLENGE` |

**Capture stage:**

| Check | Result if it fails |
|---|---|
| Valid JSON, one biometric, no device error | rejected, channel event |
| RS256 signature, then certificate chain and trust | rejected, channel event |
| Not a byte-identical replay | rejected, channel event |
| Same device identity | rejected |
| Transaction ID equals the fresh nonce | rejected, channel event (absent nonce is a device fault) |
| Timestamp inside the request window (±5 s) and session (±120 s) | device fault or rejection |
| Face record well formed | rejected |
| Exactly one face | rejected |
| Capture PAD below 0.20 | rejected (`CAPTURE_PAD_ATTACK`) |
| At least 3 stream face samples, median similarity at least 0.50 | rejected (`SUBJECT_MISMATCH`) |
| Capture PAD between 0.20 and 0.80 | retry (`CAPTURE_UNCERTAIN`) |
| Every frontal face sample in the attempt matches the capture at 0.50 or better | otherwise `SUBJECT_CHANGED` |

**Limits:** 3 attempts per person; 1 attack event tolerated (the second locks); 1 channel integrity event tolerated per device
channel (the second locks the channel until an administrator resets it, with an audit record).

**Attribution.** Attacks by the person (capture or stream PAD attack, subject change, device mismatch, subject mismatch) count
against the person. Tampering on the device channel (bad signature, replay, wrong nonce, untrusted device) counts against the
**channel**, because it cannot be tied to the person. Device faults (a missing nonce, malformed content after authentication,
a clock outside the window) carry no attack event.

## 5. Security model

**What the engine protects against**

| Threat | Defence |
|---|---|
| Tampered capture | RS256 signature, certificate chain with expiry and optional revocation (CRL) |
| Replayed capture | replay cache of response hashes |
| A response meant for another request | fresh random nonce echoed in the signed data |
| Stale or future-dated capture | time window checks, with clock-discontinuity detection |
| Another device answering | device identity matching |
| Stream shows one person, capture another | stream-versus-capture subject match; whole-attempt subject check |
| Still photo as the stream | motion check on landmark-aligned crops |
| Frozen or looped stream | frozen-frame check |
| Presentation attack (photo, screen, mask) | PAD model on the stream and on the signed capture |
| Locking a genuine person out by tampering | channel counter kept apart from the person's counter |

**What it does not prove.** A valid signature shows the capture channel is intact. It does **not** show the face was live: a
photo or a screen held to a genuine, trusted camera is still signed. Telling those apart is the PAD model's job, and that
model's accuracy is unknown. SBI 1.0 streams are unsigned, so a same-person video injected on the stream can only be stopped by
the capture-time PAD and the motion check; a signed-stream prototype exists but is off by default and would need a specification
change.

**Honest example of the limit.** In testing, a still photo scored **0.82** on the PAD model, above the 0.80 accept line. Only the
motion check stopped it. Treat the PAD score as one weak signal, not a verdict.

**Fail-closed behaviour.** Any unusable model output (NaN, out of range, wrong shape), analyzer failure, or internal error ends
in an error or retry, never an acceptance. A PAD score outside 0 to 1, or a malformed face embedding, never binds a capture.

## 6. The three modes

| | Real engine | This browser | Demo |
|---|---|---|---|
| Runs | Java engine on your machine, via the local API | The face models in your browser tab (ONNX Runtime Web, WebAssembly, single thread) | Fixed scripts |
| Camera | The engine's own feed | Yours, only after you press Start | None (optional positioning preview) |
| Decisions | Full state machine including the signed capture | Port of the passive rules; no signed capture | Scripted, marked **Simulated** |
| Best outcome | Verified | Passive checks passed | Scripted |
| Uploads | Nothing leaves your machine | Nothing uploaded or stored | Nothing |
| On the hosted site | No | Yes | Yes |
| Stored trials (browser storage) | `liveness-studio.trials.v1.real` | `...v1.browser` | `...v1.demo` (never mixed) |

The browser port reproduces the Java pipeline: on the 20 golden test images it found the same faces as the Python reference on
every image, with 0.00 px box and landmark error and attack scores within 2e-6. Live video is decoded and scaled by the browser
rather than OpenCV, so live scores can differ slightly from the Java engine.

## 7. Repository tour

```
liveness-core/                 Java 11 engine and CLI
  src/main/java/io/mosip/liveness/
    vision/                    image ops, YuNet, MiniFASNet, SFace, model loading with hash checks
    pipeline/                  per-frame pipeline, embedding sampler, live stream benchmark
    session/                   state machine, policy, evidence store, motion detector, attempt ledger
    binding/                   capture binder (the ordered checks), result types
    sbi/                       SBI client, MJPEG parser, JWS verification, ISO face record
    integration/               adapter between frames and the session
    streamauth/                signed-stream prototype (off by default)
    live/                      trial controller, snapshot builder, local API server, desktop window
    tools/                     CLI commands (probe, bench-*, bind-scenarios, session-scenarios, webcam-live)
tools/mock-sbi/                mock SBI 1.0 face device (Python): fault and attack modes, webcam and video-file sources
frontend/                      Liveness Studio (React 19, TypeScript, Vite, Tailwind 4)
  src/engine/                  in-browser port of the pipeline and passive rules
  src/lib/                     outcome mapping, reason copy, analytics, export, demo scripts, API client
  src/state/                   engine provider (three modes), camera hook
  src/pages/                   Verify, Pipeline, Integrity, Lab, Analytics, Diagnostics
  public/models/               the three ONNX models served to the browser
models/                        models used by the Java engine, licences, SHA-256 manifest
docs/                          this file, architecture proposal, demo script, frontend and deployment notes
webcam.sh, demo.sh             launchers
docker-compose.yml, render.yaml   hosting configuration for the static site
```

**Key classes.** `FramePipeline` (per frame), `LivenessSession` (decision state machine), `CaptureBinder` (ordered capture
checks), `LiveTrialController` (one trial at a time, drives the signed capture), `LiveSnapshot` (turns an outcome into the JSON
the interface renders), `LiveApiServer` (loopback HTTP API).

## 8. Local API reference

Served by `./webcam.sh --ui` on `127.0.0.1` at a random port. Every `/api` call needs the per-run token (header `X-Token`, or
`?t=` for media). The address is printed as `UI_URL=http://127.0.0.1:<port>/#t=<token>`.

| Method and path | Purpose |
|---|---|
| `GET /api/status` | Latest snapshot: trial, decision, frame, PAD scores, timings, counters, 8 stages, 11 integrity checks, events |
| `GET /api/history` | Every finished or abandoned trial this run |
| `GET /api/info` | Thresholds in force and the device and model disclosure |
| `GET /api/frame.jpg` | Newest camera frame (204 before the first) |
| `GET /api/stream.mjpg` | Live preview, at most 4 viewers |
| `POST /api/trial` | Start a trial; body `{"label": null or "scenario_label"}`; at most one per 250 ms |
| `POST /api/cancel` | Cancel the running trial (recorded as cancelled, never a decision) |
| `POST /api/quit` | Stop the run and write `webcam-output/report.json` |

**Safeguards:** loopback only; `Host` must be loopback; foreign `Origin` refused on POST; bodies capped at 4 KB; labels must
match `[a-z][a-z0-9_]{0,31}`; errors carry a code and a short message, never a stack trace; frames are served from memory and
never written or logged. Types: `frontend/src/types.ts`; design notes: `docs/frontend/LOCAL_API_DESIGN.md`.

## 9. Settings and thresholds

| Setting | Default | Where |
|---|---|---|
| Stream accept / attack | 0.80 / 0.20 | `SessionPolicy.streamAccept`, `streamAttack` |
| Attack frames to reject | 3 | `SessionPolicy.attackMinFrames` |
| Capture PAD accept / attack | 0.80 / 0.20 | `CaptureBinder.Policy` (`conservativeAcceptGate`) |
| Subject similarity | 0.50 | `CaptureBinder.Policy.subjectMinCosine`, `SessionPolicy.subjectMinCosine` |
| Motion trigger | 0.40 | `SessionPolicy.staticPhotoThreshold` |
| Attempts / attack events / channel events | 3 / 1 / 1 | `SessionPolicy` |
| Collect / ready / capture time limits | 10 s / 5 s / 15 s | `SessionPolicy` |
| Face height / brightness / sharpness gates | 80 px / 40–220 / 15 | `FramePipeline.Config` |
| Detector width and thresholds | 320 px, score 0.6, NMS 0.3 | `Phase0Models` |

`SessionPolicy.validate()` rejects NaN, negative or overflow-sized values (every millisecond limit is capped at 24 hours). The
browser port mirrors these defaults in `frontend/src/engine/session.ts` and `pipeline.ts`.

## 10. Testing and verification

| Suite | Command | Last full result |
|---|---|---|
| Java engine, API, edge cases | `cd liveness-core && mvn -B clean package` (about 10 minutes; keep the machine awake) | 321 tests, 0 failures |
| Frontend unit tests | `cd frontend && npm test` | 92 tests, 0 failures |
| Frontend type-check and build | `npm run typecheck`, `npm run build` | clean |
| Mock device | `python -m unittest tools/mock-sbi/test_camera_source.py` | 3 of 3 |
| Browser-versus-reference parity | `npm run build:parity` (local only; needs research fixtures) | same faces on 20 of 20 images, 0.00 px, PAD within 2e-6 |

**What the Java tests cover:** every outcome path of the state machine with a fake clock; the capture binder's ordering; exact
threshold boundaries (0.80, 0.20, 0.50, the 3-frame attack count) from both sides; randomized invariants (an invalid response
never reaches VERIFIED); concurrency; the attempt ledger (tamper-evident, restart-safe); certificate revocation; the local API's
authentication, Host and Origin checks, rate limits and stream cleanup; extreme and malformed inputs.

**What was checked in a real browser (Playwright):** all six screens at three widths, camera denied, missing, busy and
disconnected, camera release on turn-off and on leaving the screen, every scripted outcome, cancel and double-click protection,
exports, reduced motion, a wrong token, the engine disappearing, and the in-browser engine on a moving face (passes), a still
photo (retry), and on the production site.

**What was not verified:** a physical webcam driven through the browser, browsers other than Chromium, screen readers, touch,
and any real SBI device.

## 11. Deployment

Only the **hosted build** is meant for public hosting: static files, about 19 MB (the 15 MB WebAssembly runtime, brotli-compressed
in transit, and three models of 3.7 MB). The real engine reads a camera on its own machine and is run locally.

```bash
cd frontend && npm install && npm run build:demo     # writes dist-demo/ (needs Node 20.19+ or 22+)
```

| Target | Notes |
|---|---|
| Vercel | `frontend/vercel.json` carries the routing rule and security headers; deploy the built folder with `vercel deploy --prod` |
| Docker | `frontend/Dockerfile` (Node 22 build, then non-root nginx), `docker-compose.yml`; publishes to `127.0.0.1:8080` by default. Not built on the author's machine because the Docker daemon was not running |
| Render | `render.yaml` mirrors the same static image; untested |
| Other static hosts | `public/_redirects` and `_headers` are included for Netlify and Cloudflare Pages |

The security policy must allow WebAssembly (`script-src 'self' 'wasm-unsafe-eval'`); the configs already do. Details:
`docs/deploy/DEPLOYMENT.md`.

## 12. Privacy and data handling

- **Hosted site and browser mode:** frames are read from your camera in memory, analysed on your device, and discarded. Nothing is
  uploaded, logged or stored. Only compact trial records (outcome, scores, timings, counts) are kept in your browser's local
  storage, and you can export or clear them. No face images or embeddings are in those records or in the exports.
- **Local engine:** frames stay in memory, the API is loopback-only and token-protected, and reports contain results, not images.
- **No external requests:** fonts, models and the runtime are served from the same origin; there is no analytics or telemetry.
  ONNX Runtime telemetry is disabled in the Java launchers.
- **Test data:** the test fixtures are third-party research images and are **not** included in this repository.

## 13. Known limitations

1. **PAD accuracy is unknown.** The model is public and uncalibrated for this camera and these attacks. It can score a photo as
   real. No false-accept or false-reject rate has been measured.
2. **The motion check cannot see blinks on a typical webcam.** Measured on one MacBook camera: a blink scored no higher than
   holding still; smiling or speaking did. A live person who holds still gets `STATIC_REPLAY_SUSPECT`. The interface says so.
3. **The same-person rule is strict.** Every frontal face sample in the attempt must match the capture at 0.50 or better. About
   1 frame in 60 of a real person's natural movement falls below that, so genuine users can be rejected (`SUBJECT_CHANGED`).
4. **No real device.** Everything ran against a mock device with test keys. Behaviour on certified hardware, real latency and
   real fault modes are untested.
5. **No challenge step.** Uncertainty always ends in a retry; there is no "turn your head" prompt.
6. **Browser mode has no signed capture** by construction (see section 6).
7. **First visit is slow on weak connections** (about 4 MB compressed to download, then cached).
8. **Tooling:** the interface needs Node 20.19+ or 22+ (older Node builds but cannot run the preview server); on some machines npm
   skips Vite's native binding (the fix is in `frontend/README.md`); the Java suite is timing-sensitive, so a machine that sleeps
   mid-run produces false failures.
9. **A fresh clone cannot run everything:** `demo.sh` and part of the Java suite need the unpublished research fixtures.

## 14. Troubleshooting

| Symptom | What to do |
|---|---|
| Camera black, or "not authorized to capture video" | Allow your terminal app in System Settings › Privacy & Security › Camera, then restart it |
| `./webcam.sh --ui` says the frontend is not built | `cd frontend && npm install && npm run build` |
| "Cannot find native binding" from npm | `npm install --no-save @rolldown/binding-darwin-arm64@1.2.15` (use the package for your platform) |
| Always `STATIC_REPLAY_SUSPECT` for a real face | Smile or speak naturally; blinking and small head moves are too small on many cameras |
| `INSUFFICIENT_EVIDENCE` | One face, centred, well lit, at least 80 px tall in the frame; no one else in view |
| `CAPTURE_UNCERTAIN` | The signed capture scored between 0.20 and 0.80. Retry; do not lower the threshold to pass |
| `SUBJECT_CHANGED` on your own face | Face the camera steadily for the whole attempt (a known strictness, see 13.3) |
| "Engine not answering" in the interface | The local engine stopped; restart `./webcam.sh --ui` |
| Browser mode: models fail to start | Needs https or localhost (hash checks use a secure context); check the connection and retry |
| Java tests fail with `CLOCK_DISCONTINUITY` | The machine slept mid-run; rerun with `caffeinate -i` |
| Port or camera busy | Close other apps using the camera; stop any earlier `webcam.sh` (`pkill -f "webcam-live\|mock_sbi"`) |

## 15. Glossary

| Term | Meaning |
|---|---|
| **PAD** | Presentation-attack detection: telling a live face from a photo, screen or mask |
| **SBI** | Secure Biometric Interface, the MOSIP standard for capture devices |
| **RCAPTURE / STREAM** | SBI calls: a signed capture on request, and the unsigned live video |
| **Nonce / transaction ID** | A fresh random value the device must echo inside the signed data |
| **JWS, RS256, x5c** | The signed container, its signature algorithm, and the embedded certificate chain |
| **Embedding** | A numeric face description used only to compare two images within one attempt |
| **Cosine similarity** | How alike two embeddings are (1 = identical direction); the same-person rule uses 0.50 |
| **Fail closed** | When unsure or broken, refuse or retry; never accept |
| **Channel event** | A failure on the device link that cannot be pinned on the person |
| **Passive checks passed** | Browser-mode outcome: passive stages passed, no signed capture, not a verification |
| **APCER / BPCER** | Attack and genuine error rates; none have been measured here |

## 16. Credits and licences

| Component | Licence |
|---|---|
| YuNet face detector (OpenCV Zoo) | MIT |
| MiniFASNet, MiniVision Silent-Face-Anti-Spoofing | Apache-2.0 |
| SFace face recognition (OpenCV Zoo) | Apache-2.0 (used by the Java engine only; not shipped to the browser) |
| ONNX Runtime (Java and Web) | MIT |
| React, Vite, Tailwind CSS, Lucide | MIT / ISC |
| Fonts: Schibsted Grotesk, JetBrains Mono | SIL OFL, bundled locally |

Licence texts for the models are in `models/third_party/` and `frontend/public/models/`. The project's own code carries no
licence yet: the owner has not chosen one, so by default nobody may reuse it.
