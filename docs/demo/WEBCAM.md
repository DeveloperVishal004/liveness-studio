# Live webcam test

Test the engine with the MacBook camera: a real person, then a face video played on a phone or another screen held in
front of the camera.

```bash
./webcam.sh            # window with the live feed and the engine's decisions; SPACE = new trial, Q = quit
```

## What runs (same path for every trial)

```
MacBook camera ──> SBI EMULATOR (tools/mock-sbi --camera 0, TEST-ONLY keys) ──SBI STREAM──> liveness-core
                                         └──────────── signed RCAPTURE (sharpest real frame) ───────┘
liveness-core: receipt tag → YuNet face detection → quality gates → MiniFASNet PAD → session rules
               → (only if the session is READY) RCAPTURE → signature/nonce/time/device/subject binding
               → capture PAD gate → engine decision
```

There is no "real person" mode and no "attack" mode. The engine sees frames and decides. The window only displays.

## What each part demonstrates

| Part | Status in this test |
|---|---|
| Webcam capture | **Real**: live MacBook camera frames, sent over the SBI STREAM wire format |
| SBI device | **Emulator**: signs captures with TEST keys. Not a certified device; its signature proves nothing about the physical scene |
| Face detection | **Real model** (YuNet). A detected face is **never** treated as liveness |
| PAD classification | **Real trained public model** (MiniVision MiniFASNetV2 + V1SE). **Not evaluated or calibrated** for this camera, lighting or attack type; the 0.80/0.20 thresholds are provisional |
| Engine enforcement | **Real**: passive rules (median stream P(real) ≥ 0.80 over 3 s, < 0.20 = attack frames, static-photo check), signed-capture binding, capture PAD gate (≥ 0.80 bind, < 0.20 attack, otherwise retry) |

**A laptop or phone screen replay is a physical presentation attack.** The nonce, signature and replay-cache
protections stop *digital* replays of signed captures. They cannot tell whether the camera saw a live face or a screen.
Only PAD can, and this PAD model's accuracy for screen replays on this camera is **unknown**. A screen replay that ends
VERIFIED is an honest result and a known limitation, not a bug in the window.

## Setup (once)

1. Prerequisites as for `./demo.sh`: JDK 11+, `curl`, Python 3 with `python3 -m pip install -r tools/mock-sbi/requirements.txt`.
2. **Camera permission (macOS):** run `./webcam.sh` from **Terminal** (or iTerm). The first time, macOS asks to let
   Terminal use the camera; allow it. If you missed the prompt, go to System Settings › Privacy & Security › Camera,
   enable Terminal, then quit and reopen Terminal.

## Running trials

1. `./webcam.sh` opens a window with the live feed.
2. Press **SPACE** to start a trial. Each trial is a fresh session. Face the camera 40–70 cm away in even light, blink
   and move slightly. A frozen pose looks like a photo.
3. The headline shows the engine decision: green **VERIFIED**, yellow **NOT ACCEPTED – retry: reason**, red **REJECTED:
   reason**. The lines below show:
   - face detection, and whether the frame is PAD-eligible;
   - stream PAD P(real), last and median;
   - capture PAD and bind time;
   - per-frame latency;
   - the subject and channel counters.
4. For the screen test, play a video of a face on a phone or second screen, hold it in front of the camera and press
   SPACE. Same path, same thresholds.
5. Press **Q** to quit. Every trial is recorded in `webcam-output/report.json`.

Rehearse without a camera: `./webcam.sh --video some_face_clip.mp4`. Run trials without a window:
`./webcam.sh --headless 3`.

## Reading the result

| Engine result | Meaning |
|---|---|
| `VERIFIED` | Stream PAD passed, the static check saw natural motion, the signed capture was bound (nonce, time, device, same person) and capture PAD ≥ 0.80 |
| `retry: CAPTURE_UNCERTAIN` | Capture PAD between 0.20 and 0.80: the conservative gate refuses and asks for a retry |
| `retry: PASSIVE_UNCERTAIN_NO_CHALLENGE` | Stream PAD median stayed below 0.80 for 10 s; there is no challenge engine yet, so no capture is taken |
| `retry: STATIC_REPLAY_SUSPECT` | No facial movement large enough in the last 5 s. **Measured on a real 960x540 webcam: a normal blink scores no higher than holding still, so blinking alone does not satisfy it; smiling or speaking does** (see "Measured motion scores") |
| `retry: INSUFFICIENT_EVIDENCE` | Face too small (under 80 px), too blurred, or not detected long enough |
| `REJECTED: STREAM_PAD_ATTACK` / `CAPTURE_PAD_ATTACK` | PAD below 0.20 on several stream frames, or on the signed capture |
| `REJECTED: … SUBJECT_MISMATCH` / `SUBJECT_CHANGED` | A different person in the capture than on the stream |

## Measured motion scores (one person, one MacBook camera, one room, 8 s per phase, in-memory only)

The static-image check fires when at least one consecutive frame pair scores above 0.40. The threshold was calibrated on
synthetic data, where blinks scored 0.41-0.76. On the real camera:

| Activity | Largest pair score | Pairs > 0.40 |
|---|---|---|
| holding still | 0.309 | 0 |
| blinking, head still | 0.297 | 0 |
| moving the head | 0.325 | 0 |
| smiling and talking | 0.606 | 4 |

So on this camera the check is only satisfied by larger facial movement (smile, speech). It is **not** a blink detector
here, and the 0.40 value is uncalibrated for real cameras. Lowering it is not safe on this evidence: blink scores sit
inside the noise of a still face. A calibration needs measurements of a physical photo and a screen replay on the same
camera; that is an owner decision and has not been made. The window shows a hint, which is guidance only.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `SBI emulator stopped (camera not available?)` or `not authorized to capture video` | Grant camera access to Terminal (Setup 2), quit any app using the camera (FaceTime, Zoom, browser) |
| Window opens but stays black | Wait about 2 s; check `webcam-output/emulator.log`; try `--camera 1` for an external camera |
| Always `INSUFFICIENT_EVIDENCE` | Move closer and improve light: the face must be ≥ 80 px high and sharp |
| Always `PASSIVE_UNCERTAIN_NO_CHALLENGE` | The model scores you below 0.80 in this light or at this distance. That is the provisional threshold working; do **not** lower it to make the demo pass |
| `STATIC_REPLAY_SUSPECT` for a real person | Smile or speak naturally while looking at the camera (blinking and small head moves are not enough on this camera) |
| Port 4795 already in use | Another `webcam.sh` is running; close it |

## Not claimed

Single trials are anecdotes, not measurements. No APCER/BPCER figure exists for this model on this camera. A
representative, consented evaluation is required (an internal protocol, not part of this repository), and
collecting that data is not yet authorised. Do not record or keep images of other people while testing; the tool
itself stores no frames.
