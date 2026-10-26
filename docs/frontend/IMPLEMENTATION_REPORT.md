# Liveness Studio: implementation report

Local only. Nothing was pushed, committed or sent anywhere. No threshold, signature, nonce, replay, trust or attempt-limit
check was changed for the interface.

## What was built

- **Backend (Java, `liveness-core/.../live/`)**: `LiveApiServer` (loopback HTTP API, token, Host/Origin checks, size and
  rate limits), `LiveSnapshot` (derives the 8 pipeline stages and 11 integrity checks from what the engine actually did, in
  the binder's real order), and additions to `LiveTrialController` (trial id, timings, event timeline, cancel, frame
  statistics). `webcam.sh --ui` launches everything.
- **Frontend (`frontend/`)**: React 19, TypeScript, Vite 8, Tailwind 4, Lucide. Six screens: Verify, Pipeline, Security
  integrity, Evaluation lab, Analytics, Diagnostics. Real and Demo modes.

## Results

| Check | Result |
|---|---|
| Java suite (clean build, Mac kept awake) | 321 tests, 0 failures (302 before + 19 new: `LiveSnapshotTest` 10, `LiveApiServerTest` 9) |
| `./demo.sh` | exit 0, 0 of 6 attacks accepted |
| Python camera-source tests | 3 of 3 |
| Frontend `tsc`, unit tests, production build | clean, 50 of 50, built |
| Browser checks (Playwright, against the REAL engine on a video source) | see below |

Browser checks performed: initial load; navigation of all six screens at 1440, 820 and 390 px with no horizontal
overflow; real trial start, live stage updates, real decision (Retry required, CAPTURE_UNCERTAIN) with explanation;
demo banner; camera permission denied, camera missing, camera busy, camera disconnected; camera tracks stopped on
turn-off, on disconnect and on leaving the screen; every scripted demo outcome (only the verified script verifies);
cancel; double-click protection; lab expectation versus engine decision; empty analytics, filters, confirmation before
clear, real/demo separation; CSV and JSON export contents; reduced motion; wrong token; engine disappearing; clean
shutdown (0 leftover processes); no console errors from the app itself.

## Defects found and fixed during this work

1. Integrity checks before the first failing one were shown "not checked" instead of "passed" (caught by the table test).
2. A NaN score could leak the word "NaN" into explanatory text.
3. A preview stream slot was never freed if the camera stalled (now a keep-alive detects closed viewers).
4. The Cancel button replaced Start in the same place, so a double-click could start and instantly cancel a trial.
5. After "Clear", a finished trial on screen was recorded again.
6. The status ladder marked phases done that the engine never reached.
7. Tabular figures were applied to all text, spacing full stops oddly.
8. Polling kept retrying after a refused token.

## Not verified / limits

- The browser was driven against the engine on a **video file** source. A physical webcam was not used in the browser
  session (it was used earlier through the command line). The browser camera preview in demo mode was tested with a
  stubbed `getUserMedia`, not a physical device.
- Only Chromium (Playwright) was used. Firefox and Safari, screen readers and touch were not tested.
- Context7 requires authorisation in this environment, so library versions were checked against the npm registry.
- The PAD model is public and uncalibrated, the device is an emulator with TEST keys, and trial results are anecdotes.
  Nothing here is an accuracy measurement or a production-readiness claim.
- Open product decisions from earlier remain (motion check cannot see blinks on this camera; the same-person rule is
  strict for natural head movement). The interface explains both honestly but does not change them.
