import { Camera as CameraIcon, CameraOff, RefreshCw, VideoOff } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { previewUrl } from '../lib/api'
import { frameGuidance } from '../lib/copy'
import { fmtScore } from '../lib/format'
import { outcomeKind, OUTCOME_LABEL } from '../lib/outcome'
import { useEngine, type PadPoint } from '../state/engine'
import type { CameraState } from '../state/camera'
import type { Thresholds } from '../types'
import { OUTCOME_TONE } from './ui'

const CAM_MESSAGE: Partial<Record<CameraState['kind'], { title: string; body: string }>> = {
  denied: { title: 'Camera access was blocked', body: 'Allow camera access for this site in the address-bar lock menu (or your system privacy settings), then turn the preview on again.' },
  unavailable: { title: 'No camera found', body: 'Connect a camera, or check that no other app has taken it, then try again.' },
  busy: { title: 'The camera is in use', body: 'Another app is using the camera. Close it and try again.' },
  disconnected: { title: 'The camera disconnected', body: 'The camera stopped sending video. Reconnect it and turn the preview on again.' },
}

function Layer({ name, value, tone }: { name: string; value: string; tone: string }) {
  return (
    <div className="min-w-0 border-l border-rule px-3 odd:border-l-0 sm:odd:border-l">
      <div className="text-xs text-slate">{name}</div>
      <div className={`text-sm font-medium leading-snug ${tone}`}>{value}</div>
    </div>
  )
}

/** What each mode shows: the engine's own feed (real), the visitor's camera analysed in this browser (browser), or a scripted placeholder (demo). */
export function CameraStage({ compact = false }: { compact?: boolean }) {
  const { mode, snapshot, connection, camera: cam, modelStatus } = useEngine()
  const videoRef = useRef<HTMLVideoElement>(null)
  const [imgFailed, setImgFailed] = useState(false)
  const [retry, setRetry] = useState(0)
  const live = cam.state.kind === 'live' ? cam.state : null

  useEffect(() => {
    if (videoRef.current) videoRef.current.srcObject = live ? live.stream : null
  }, [live])
  useEffect(() => {
    setImgFailed(false)
  }, [mode, connection, retry])
  useEffect(() => {
    if (mode === 'real') cam.stop() // the local engine has its own camera; the browser camera belongs to the other modes
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode])

  const W = snapshot.frame.width || 960
  const H = snapshot.frame.height || 540
  const f = snapshot.frame
  const kind = outcomeKind(snapshot)
  const guide = frameGuidance(f.faceCount, f.ineligibleReason, f.eligible)
  const showBox = f.faceBox && f.faceBox.length >= 4 && snapshot.trial.active
  const boxColor = f.eligible ? 'var(--color-signal)' : 'var(--color-warn)'
  const brackets = () => `M28 ${28 + 46}V28H${28 + 46} M${W - 28 - 46} 28H${W - 28}V${28 + 46} M${W - 28} ${H - 28 - 46}V${H - 28}H${W - 28 - 46} M${28 + 46} ${H - 28}H28V${H - 28 - 46}`
  const mirror = mode !== 'real' && !!live // selfie view: the picture and the engine's overlay are mirrored together

  let media: React.ReactNode = null
  let overlayNote: React.ReactNode = null
  if (mode === 'real') {
    const url = connection === 'connected' ? previewUrl() : null
    if (!url) {
      overlayNote = <Notice icon={<VideoOff size={22} />} title="Waiting for the engine" body={connection === 'connecting' ? 'Connecting to the local engine…' : 'The engine is not reachable, so there is no camera feed.'} />
    } else if (snapshot.camera.framesReceived === 0) {
      overlayNote = <Notice icon={<CameraIcon size={22} />} title="Camera starting" body="The engine has not received a frame yet. If this lasts, check that your terminal app may use the camera in System Settings › Privacy & Security › Camera." />
    } else if (imgFailed) {
      overlayNote = <Notice icon={<CameraOff size={22} />} title="Preview interrupted" body="The preview stream closed." action={<button className="btn" onClick={() => setRetry((n) => n + 1)}><RefreshCw size={14} /> Reconnect preview</button>} />
    } else {
      media = <img key={`${url}-${retry}`} src={url} alt="Live camera feed, as assessed by the engine" className="absolute inset-0 h-full w-full object-contain" onError={() => setImgFailed(true)} />
      if (!snapshot.camera.streaming) overlayNote = <Notice icon={<CameraOff size={22} />} title="Camera feed stopped" body="No new frames have arrived for a few seconds. The camera may be disconnected or in use elsewhere." compact />
    }
  } else if (live) {
    media = <video ref={videoRef} autoPlay muted playsInline aria-label={mode === 'browser' ? 'Your camera, analysed in this browser' : 'Browser camera preview (positioning only)'} className="absolute inset-0 h-full w-full object-contain" />
  } else {
    const m = CAM_MESSAGE[cam.state.kind]
    const title = m ? m.title : mode === 'browser' ? 'Camera is off' : 'Scripted demo, no camera'
    const body = m
      ? m.body
      : mode === 'browser'
        ? 'Press Start verification. Your camera turns on in this browser and the models run on this device. Nothing is uploaded.'
        : 'The numbers and stages are simulated. Turn on the optional preview below to check how your face sits in the guide; it is not analysed.'
    media = (
      <div className="absolute inset-0 flex items-end justify-center bg-[radial-gradient(ellipse_at_center,#15233b,#0a1322_70%)] pb-5">
        <div className="max-w-md rounded-sm bg-abyss/85 px-4 py-2 text-center">
          <p className="text-sm text-paper">{title}</p>
          {!compact && <p className="mt-0.5 text-xs text-slate">{body}</p>}
        </div>
      </div>
    )
  }
  if (mode === 'browser' && modelStatus.state === 'loading') {
    overlayNote = <Notice icon={<RefreshCw size={22} className="animate-spin" />} title="Loading the models" body={`${modelStatus.label || 'Starting'} (${Math.round(modelStatus.fraction * 100)}% overall). About 4 MB to download the first time, then cached. Each model is checked against its pinned hash.`} />
  } else if (mode === 'browser' && modelStatus.state === 'error' && !snapshot.trial.active) {
    overlayNote = <Notice icon={<CameraOff size={22} />} title="The models could not start" body={modelStatus.message ?? 'Unknown error.'} />
  }

  const trialOn = snapshot.trial.number > 0
  const cameraLayer =
    mode === 'real'
      ? snapshot.camera.streaming ? { v: 'Streaming', t: 'text-ok' } : snapshot.camera.framesReceived > 0 ? { v: 'Stopped', t: 'text-warn' } : { v: 'No frames', t: 'text-warn' }
      : mode === 'browser'
        ? live ? { v: 'On this device', t: 'text-ok' } : { v: 'Off', t: 'text-slate' }
        : live ? { v: 'Preview only', t: 'text-signal' } : { v: 'Simulated', t: 'text-slate' }
  const faceLayer = !trialOn ? { v: '—', t: 'text-slate' } : f.faceCount === 1 ? (f.eligible ? { v: 'One face, usable', t: 'text-ok' } : { v: 'One face, not usable', t: 'text-warn' }) : f.faceCount === 0 ? { v: 'No face', t: 'text-warn' } : f.faceCount > 1 ? { v: `${f.faceCount} faces`, t: 'text-warn' } : { v: '—', t: 'text-slate' }
  const padLayer = !trialOn || snapshot.pad.stream.median == null ? { v: '—', t: 'text-slate' } : { v: `median ${fmtScore(snapshot.pad.stream.median)}`, t: 'text-paper' }
  const decLayer = { v: OUTCOME_LABEL[kind], t: OUTCOME_TONE[kind] }

  return (
    <div>
      <div className={`relative overflow-hidden rounded-lg border border-rule bg-black ${compact ? 'aspect-[16/10]' : 'aspect-video'}`}>
        <div className={`absolute inset-0 ${mirror ? '-scale-x-100' : ''}`}>
          {media}
          <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet" className="pointer-events-none absolute inset-0 h-full w-full" aria-hidden="true">
            <path d={brackets()} stroke={snapshot.trial.active ? 'var(--color-signal)' : 'rgb(140 157 181 / 0.7)'} strokeWidth="3" fill="none" strokeLinecap="round" />
            <ellipse cx={W / 2} cy={H / 2} rx={W * 0.16} ry={H * 0.36} stroke="rgb(230 237 247 / 0.45)" strokeWidth="2" strokeDasharray="6 8" fill="none" />
            {showBox && f.faceBox && <rect x={f.faceBox[0]} y={f.faceBox[1]} width={f.faceBox[2]} height={f.faceBox[3]} stroke={boxColor} strokeWidth="3" fill="none" rx="4" />}
          </svg>
        </div>
        {overlayNote && <div className="absolute inset-0 grid place-items-center bg-abyss/80 p-4">{overlayNote}</div>}
        {mode === 'demo' && <span className="absolute left-3 top-3 rounded-sm bg-warn/90 px-2 py-0.5 text-xs font-semibold text-[#2a1c00]">Simulated</span>}
        {mode === 'browser' && live && <span className="absolute left-3 top-3 rounded-sm bg-abyss/85 px-2 py-0.5 text-xs font-medium text-signal">Live · analysed on this device</span>}
      </div>
      <div className={`mt-3 grid grid-cols-2 gap-y-2 rounded-md border border-rule bg-deck py-2 ${compact ? '' : 'sm:grid-cols-4'}`} role="group" aria-label="What each layer reports">
        <Layer name="Camera" value={cameraLayer.v} tone={cameraLayer.t} />
        <Layer name="Face detection" value={faceLayer.v} tone={faceLayer.t} />
        <Layer name="Attack assessment" value={padLayer.v} tone={padLayer.t} />
        <Layer name="Decision" value={decLayer.v} tone={decLayer.t} />
      </div>
      <p className={`mt-2 text-sm ${guide.tone === 'warn' && snapshot.trial.active ? 'text-warn' : 'text-slate'}`} aria-live="polite">
        {snapshot.trial.active ? guide.text : trialOn ? 'The trial has finished. The result is shown beside the camera.' : 'Press Start verification when you are in position. Centre your face in the guide.'}
      </p>
      {mode === 'demo' && !compact && (
        <div className="mt-3 flex flex-wrap items-center gap-2">
          {live ? (
            <button className="btn" onClick={cam.stop}><CameraOff size={15} /> Turn preview off</button>
          ) : (
            <button className="btn" onClick={() => void cam.start()} disabled={cam.state.kind === 'requesting'}>
              <CameraIcon size={15} /> {cam.state.kind === 'requesting' ? 'Waiting for permission…' : 'Use my camera for positioning'}
            </button>
          )}
          {cam.devices.length > 1 && (
            <label className="flex items-center gap-2 text-sm text-slate">
              Camera
              <select className="field" value={cam.deviceId} onChange={(e) => { cam.setDeviceId(e.target.value); if (live) void cam.start(e.target.value) }}>
                <option value="">Default</option>
                {cam.devices.map((d) => <option key={d.id} value={d.id}>{d.label}</option>)}
              </select>
            </label>
          )}
          <span className="text-xs text-faint">Positioning only: the picture is not analysed, stored or sent anywhere, and a browser camera has none of the trust properties of a certified capture device.</span>
        </div>
      )}
      {mode === 'browser' && !compact && (
        <div className="mt-3 flex flex-wrap items-center gap-3">
          {live && !snapshot.trial.active && <button className="btn" onClick={cam.stop}><CameraOff size={15} /> Turn camera off</button>}
          {cam.devices.length > 1 && !snapshot.trial.active && (
            <label className="flex items-center gap-2 text-sm text-slate">
              Camera
              <select className="field" value={cam.deviceId} onChange={(e) => { cam.setDeviceId(e.target.value); if (live) void cam.start(e.target.value) }}>
                <option value="">Default</option>
                {cam.devices.map((d) => <option key={d.id} value={d.id}>{d.label}</option>)}
              </select>
            </label>
          )}
          <span className="text-xs text-faint">The face models run on this device. Nothing is uploaded or stored. A browser camera is not a certified capture device, so there is no signed capture and the best result is “Passive checks passed”.</span>
        </div>
      )}
      {mode === 'real' && !compact && (
        <p className="mt-2 text-xs text-faint">This is the engine’s own camera feed, so what you see is exactly what is assessed. The camera is chosen when the engine starts (<span className="code">./webcam.sh --camera N</span>).</p>
      )}
    </div>
  )
}

function Notice({ icon, title, body, action, compact }: { icon: React.ReactNode; title: string; body: string; action?: React.ReactNode; compact?: boolean }) {
  return (
    <div className={`mx-auto max-w-sm text-center ${compact ? '' : ''}`} role="status">
      <div className="mx-auto mb-2 w-fit text-slate">{icon}</div>
      <p className="font-semibold">{title}</p>
      <p className="mt-1 text-sm text-slate">{body}</p>
      {action && <div className="mt-3 flex justify-center">{action}</div>}
    </div>
  )
}

/** Rolling stream PAD score. Thresholds come from the engine's policy. Uncalibrated model output, not a probability of identity. */
export function PadTrace({ history, thresholds }: { history: PadPoint[]; thresholds: Thresholds }) {
  const W = 480
  const H = 130
  const pad = { l: 34, r: 8, t: 8, b: 16 }
  const iw = W - pad.l - pad.r
  const ih = H - pad.t - pad.b
  const y = (v: number) => pad.t + (1 - Math.max(0, Math.min(1, v))) * ih
  const x = (i: number, n: number) => pad.l + (n <= 1 ? 0 : (i / (n - 1)) * iw)
  const line = (sel: (p: PadPoint) => number | null) => {
    const pts = history.map((p, i) => ({ v: sel(p), i })).filter((p): p is { v: number; i: number } => p.v != null)
    return pts.map((p, k) => `${k ? 'L' : 'M'}${x(p.i, history.length).toFixed(1)} ${y(p.v).toFixed(1)}`).join('')
  }
  return (
    <figure>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label={history.length ? `Stream PAD score over time, latest ${fmtScore(history[history.length - 1]?.last)}` : 'No stream PAD scores yet'}>
        {[thresholds.streamAttack, thresholds.streamAccept].map((t, i) => (
          <g key={t}>
            <line x1={pad.l} x2={W - pad.r} y1={y(t)} y2={y(t)} stroke={i ? 'var(--color-ok)' : 'var(--color-bad)'} strokeOpacity="0.5" strokeDasharray="4 4" />
            <text x={pad.l - 6} y={y(t) + 4} textAnchor="end" fontSize="10" fill="var(--color-slate)" className="num">{t.toFixed(2)}</text>
          </g>
        ))}
        <text x={pad.l - 6} y={y(1) + 4} textAnchor="end" fontSize="10" fill="var(--color-faint)">1</text>
        <text x={pad.l - 6} y={y(0) + 4} textAnchor="end" fontSize="10" fill="var(--color-faint)">0</text>
        <line x1={pad.l} x2={pad.l} y1={pad.t} y2={H - pad.b} stroke="var(--color-rule)" />
        {history.length > 1 && <path d={line((p) => p.last)} fill="none" stroke="var(--color-slate)" strokeWidth="1" strokeOpacity="0.7" />}
        {history.length > 1 && <path d={line((p) => p.median)} fill="none" stroke="var(--color-signal)" strokeWidth="2" />}
        {history.length === 0 && <text x={W / 2} y={H / 2} textAnchor="middle" fontSize="12" fill="var(--color-slate)">No scores yet. They appear once a usable face is found.</text>}
      </svg>
      <figcaption className="mt-1 flex flex-wrap gap-x-4 text-xs text-slate">
        <span><span className="mr-1 inline-block h-0.5 w-4 bg-signal align-middle" />median of recent frames</span>
        <span><span className="mr-1 inline-block h-px w-4 bg-slate align-middle" />each frame</span>
        <span>dashed lines: attack and accept lines in force</span>
      </figcaption>
    </figure>
  )
}
