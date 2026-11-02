# Hosting Liveness Studio

Nothing here has been published. These are the ready-to-use pieces and the decisions that are yours.

## What can and cannot be hosted

| Piece | Hostable on a public site? | Why |
|---|---|---|
| **Hosted build** (`npm run build:demo`) | Yes | Static files only. Offers **This browser** (the face models run on the visitor's own device through WebAssembly; the camera starts only on their click; nothing is uploaded or stored) and the scripted **Demo**. No server, no `/api` calls. About 19 MB: the wasm runtime (15 MB) and the three models (3.7 MB), fetched from the same origin and cached. |
| **Real engine** (Java + camera) | No, not as a normal website | It reads a camera on the machine running it and uses an emulated device with TEST keys. Hosting it would mean sending people's face images to a server: a privacy and consent decision, and not a certified device. Run it locally with `./webcam.sh --ui`. |

The hosted site needs a Content-Security-Policy that allows WebAssembly (`script-src 'self' 'wasm-unsafe-eval'`); the configs in
this repo already include it.

## Option A: Docker (needs Docker Desktop running)

```bash
docker compose up --build              # http://127.0.0.1:8080
# or
docker build -t liveness-studio-demo frontend
docker run --rm -p 127.0.0.1:8080:8080 liveness-studio-demo
```

Runs as a non-root user with a read-only filesystem, no capabilities, and security headers (CSP, no-referrer, nosniff).
It is published to `127.0.0.1` only; change the compose port to `8080:8080` to share it on your network.
**Not yet built or run here:** the Docker daemon was not running on this machine, so the Dockerfile is untested.

## Option B: a static host

Build once, upload `frontend/dist-demo`:

```bash
cd frontend && npm install && npm run build:demo     # needs Node 20.19+ or 22+
```

| Host | Notes |
|---|---|
| Netlify / Cloudflare Pages | `dist-demo/_redirects` (SPA fallback) and `_headers` (CSP etc.) are already included |
| Vercel | `frontend/vercel.json` has the rewrite and headers |
| GitHub Pages | No SPA fallback: copy `index.html` to `404.html` after building |

## Before anything goes public (your call)

1. **Public or private?** Public means anyone can open it and the project becomes visible. A private or unlisted link (password, team-only) limits that.
2. **Which platform and account?** Publishing needs your credentials; I do not have and will not ask for them.
3. **Wording check.** The banner and footer already say it is a research prototype, simulated, not certified, no accuracy claim. Keep those.
4. **Release gates and production claims** stay as they are: nothing here is ratified or production-ready.

## Decided: public, Vercel for the frontend

Publish **only the `frontend/` folder**. That uploads the interface (about 700 KB built) and none of the models, fixtures,
research data or Java code. Checked: the built site contains no access token and no local paths.

```bash
cd frontend
npx vercel login          # you do this: it opens your browser; I never see your credentials
npx vercel --prod         # accept the detected settings; vercel.json already sets the build
```

`frontend/vercel.json` sets: install `npm install`, build `npm run build:demo`, output `dist-demo`, the SPA rewrite, and
security headers. In the Vercel project settings choose **Node.js 22.x** (Vite 8 needs 20.19+). If the build fails with
"Cannot find native binding", set the install command to `npm install --no-save @rolldown/binding-linux-x64-gnu@1.2.15 && npm install`.
Untested on Vercel: I cannot deploy from here.

## Render

`render.yaml` deploys the **same demo-only image** as a Render web service, so Render can mirror the demo. It is not the
engine. A public, working "backend" would mean visitors send camera frames to a server, which needs its own design (see below).

### What a public engine would need (not built)

- Frames uploaded from the visitor's browser (explicit consent screen, no storage, deletion on disconnect).
- Per-visitor sessions, rate limits and abuse protection, because anyone could start CPU-heavy trials.
- A legal and privacy decision about processing biometric data from the public, and a statement that the device is an
  emulator with TEST keys and the model is uncalibrated.
- Sample images or video must have a licence that allows publishing; the repository's fixtures come from research datasets.
