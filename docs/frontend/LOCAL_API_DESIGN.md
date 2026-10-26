# Local API for the frontend (IMPLEMENTED: `LiveApiServer`, `LiveSnapshot`)

Goal: let a browser UI show exactly what the Swing window shows today, without moving any decision into the frontend.

## Principles

1. **The frontend never decides.** Every decision, reason and score comes from `LiveTrialController.Status` (the engine's session outcome), passed through unchanged. The UI renders; it does not compute "live".
2. **One driver.** `controller.poll()` advances the session and triggers the capture, so exactly one ticker thread calls it (every ~33 ms) and caches the snapshot. HTTP handlers only read the cache. Today the Swing paint loop is that driver; the server replaces it, it does not add a second one.
3. **Local only, no new dependencies.** JDK `com.sun.net.httpserver`, bound to `127.0.0.1`, random port, printed at start.
4. **No biometric persistence.** Frames are served from memory only (the latest one) and never written to disk or logged.

## Endpoints (as implemented)

All `/api` calls need the per-run token: header `X-Token`, or `?t=` for media (an `<img>` cannot set headers). Reads are GET,
changes are POST. Typed schemas: `frontend/src/types.ts` mirrors `LiveSnapshot.toJson` field for field and `parseSnapshot`
rejects any response that does not match.

| Method + path | Purpose | Body / response |
|---|---|---|
| `GET /api/status` | Latest snapshot (cached; the ticker is the only caller of `controller.poll()`) | `trial`, `decision`, `frame`, `pad`, `timing`, `counters`, `camera`, `ineligibleCounts`, `stages[8]`, `integrity[11]`, `events[]` |
| `GET /api/history` | Every finished or abandoned trial this run | array of snapshots |
| `GET /api/info` | Thresholds actually in force, device and model disclosure | JSON |
| `GET /api/frame.jpg` | Newest camera frame (204 before the first) | `image/jpeg`, `no-store` |
| `GET /api/stream.mjpg` | Live preview, at most 4 viewers; a keep-alive frees slots when the camera stalls | `multipart/x-mixed-replace` |
| `POST /api/trial` | Start a trial (restarts any running one, which is kept as unfinished). Min 250 ms between starts | `{"label": null \| "[a-z][a-z0-9_]{0,31}"}` |
| `POST /api/cancel` | Cancel the running trial; recorded as `CANCELLED`, never a decision | `{}` |
| `POST /api/quit` | Stop the run; the report is written and the camera released | `{}` |

Not implemented from the original design: Server-Sent Events (the UI polls `/api/status` at about 8 Hz, which is simpler
and robust to reconnects).

## Security (local does not mean trusted)

- Bind `127.0.0.1` only; reject any request whose `Host` header is not `127.0.0.1:<port>` or `localhost:<port>` (DNS-rebinding defence).
- A random per-launch token, required on **every** `/api` call (reads included, because frames are biometric). It is handed to the page through the URL fragment that `webcam.sh` opens, so another local web page can neither read nor start anything.
- CORS: none by default (the page is served by the same server, same origin).
- Request bodies capped at 4 KB; `POST /api/trial` rate-limited (a trial start joins a worker thread).
- Errors never include stack traces or file paths.

## Frontend (proposal)

A single static page served by the same server (`/`), so `./webcam.sh --ui` stays one command. It shows: the live preview with the face box, the engine headline (green VERIFIED / amber retry / red REJECTED), PAD median and last, capture PAD, latency, counters, the hint, the history table, and the permanent disclosure from `/api/info`. A separate React app is possible later; the API above does not change.

## Tests to write with it (contract + edge)

- Every status field equals the controller's `Status` (no rewriting of verdict text).
- Missing/wrong token -> 401; wrong `Host` -> 403; body > 4 KB -> 413; unknown path -> 404; wrong method -> 405.
- 100 rapid `POST /api/trial` leave no leaked workers and keep every abandoned trial in `/api/history`.
- Two concurrent `GET /api/status` readers never see a torn snapshot while the ticker updates it.
- A client that disconnects mid-stream releases its resources.
- `/api/frame.jpg` before any frame -> 204, not an error.
- Closing the server twice is harmless; shutdown joins the ticker before the models close.

## Not in scope here

Changing any threshold or rule; the motion-check and same-person decisions; accuracy evaluation; remote access of any kind.
