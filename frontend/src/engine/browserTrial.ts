// One verification trial that runs entirely in this browser: camera frames -> the ported pipeline -> the ported passive rules.
// The snapshot has the same shape as the Java engine's, so every screen renders it unchanged.
// There is no signed capture here (a browser has no certified capture device): the best outcome is PASSIVE_PASSED, never VERIFIED.
import { cancelledCopy } from '../lib/demo'
import { DEFAULT_THRESHOLDS, idleRaw, toSnapshot, type Raw } from '../lib/derive'
import type { Snapshot, Thresholds } from '../types'
import type { BgrImage } from './image'
import { rgbaToBgr } from './image'
import { FramePipeline, type FrameEvidence } from './pipeline'
import { PassiveSession, medianLower } from './session'

const ANALYSIS_WIDTH = 960 // the Java engine's stream is 960 wide, and its size gate (80 px face height) is in these pixels
const FRAME_INTERVAL_MS = 66 // about 15 fps, as the engine's stream

export const BROWSER_UNAVAILABLE = 'A browser has no certified capture device, so this check cannot run here.'

/** Applies the browser-specific truth to a snapshot: no signed capture exists, so those stages and checks are unavailable, not "passed". */
export function browserSnapshot(raw: Raw, t: Thresholds, framesReceived: number, streaming: boolean): Snapshot {
  const s = toSnapshot(raw, t, framesReceived, streaming)
  s.integrity = s.integrity.map((c) => (c.id === 'streamAuth' ? c : { ...c, state: 'unavailable' as const, detail: BROWSER_UNAVAILABLE }))
  s.stages = s.stages.map((st) =>
    st.id === 'integrity' || st.id === 'capturePad' || st.id === 'subject'
      ? { ...st, state: 'skipped' as const, reasonCode: null, durationMs: null, detail: 'Not available in the browser: there is no signed capture device.' }
      : st.id === 'decision' && raw.state === 'PASSIVE_PASSED'
        ? { ...st, detail: 'Passive checks passed in this browser. No signed capture was possible, so this is not a verification.' }
        : st,
  )
  return s
}

export interface BrowserTrialOptions {
  video: HTMLVideoElement
  pipeline: FramePipeline
  label: string | null
  trialNumber: number
  thresholds?: Thresholds
  onSnapshot: (s: Snapshot) => void
}

const verdictFor = (state: string, reason: string): string => {
  switch (state) {
    case 'PASSIVE_PASSED':
      return 'PASSIVE CHECKS PASSED in this browser (no signed capture, not a verification)'
    case 'RETRY_PENDING':
      return `NOT ACCEPTED - retry: ${reason}`
    case 'REJECTED_ATTACK':
      return `REJECTED: ${reason}`
    case 'ERROR_ENGINE':
      return 'ERROR_ENGINE / ENGINE_ERROR'
    default:
      return 'collecting stream evidence...'
  }
}

export class BrowserTrial {
  private readonly raw: Raw = idleRaw()
  private readonly session: PassiveSession
  private readonly canvas = document.createElement('canvas')
  private readonly ctx: CanvasRenderingContext2D
  private running = false
  private framesReceived = 0
  private streaming = false
  private readonly recentPads: number[] = []
  private readonly spanSum: Record<string, number> = {}
  private spanN = 0
  private lastQualityKey = ''
  private lastStateKey = ''
  private last: Snapshot
  private readonly t0 = performance.now()

  constructor(private readonly o: BrowserTrialOptions) {
    const r = this.raw
    r.trialNumber = o.trialNumber
    r.trialId = `B${o.trialNumber}-${Math.floor(Math.random() * 0xffffff).toString(16).padStart(6, '0')}`
    r.label = o.label
    r.startedAtMs = Date.now()
    r.active = true
    r.state = 'CAPTURING'
    r.reason = 'NONE'
    r.attempt = 1
    r.maxAttempts = 3
    r.verdict = verdictFor('CAPTURING', 'NONE')
    r.events.push({ tMs: 0, type: 'start', text: `Trial started in the browser${o.label ? ` (label: ${o.label})` : ''}` })
    const ctx = this.canvas.getContext('2d', { willReadFrequently: true })
    if (!ctx) throw new Error('This browser cannot read camera frames from a canvas.')
    this.ctx = ctx
    this.session = new PassiveSession(this.t0)
    this.last = this.build()
  }

  get snapshot(): Snapshot {
    return this.last
  }

  start(): void {
    this.running = true
    this.publish()
    void this.loop()
  }

  /** Stops the loop; if the trial was still running, records it as cancelled (never a decision). */
  cancel(): Snapshot {
    const wasActive = this.running && this.raw.active
    this.running = false
    if (!wasActive) return this.last
    const s = cancelledCopy(this.last, Date.now())
    this.raw.active = false
    this.last = s
    this.o.onSnapshot(s)
    return s
  }

  stop(): void {
    this.running = false
  }

  private grab(): BgrImage | null {
    const v = this.o.video
    if (v.readyState < 2 || v.videoWidth === 0 || v.videoHeight === 0) return null
    const w = ANALYSIS_WIDTH
    const h = Math.max(2, Math.round((w * v.videoHeight) / v.videoWidth))
    if (this.canvas.width !== w || this.canvas.height !== h) {
      this.canvas.width = w
      this.canvas.height = h
    }
    this.ctx.drawImage(v, 0, 0, w, h)
    return rgbaToBgr(this.ctx.getImageData(0, 0, w, h).data, w, h)
  }

  private event(type: string, text: string): void {
    if (this.raw.events.length < 300) this.raw.events.push({ tMs: Math.max(0, Math.round(performance.now() - this.t0)), type, text })
  }

  private ingest(ev: FrameEvidence, now: number): void {
    const r = this.raw
    this.framesReceived++
    r.frames++
    if (ev.eligible) r.eligibleFrames++
    else {
      const k = ev.ineligibleReason ?? 'UNKNOWN'
      r.ineligibleCounts[k] = (r.ineligibleCounts[k] ?? 0) + 1
    }
    const q = ev.eligible ? 'OK' : String(ev.ineligibleReason)
    if (q !== this.lastQualityKey) {
      this.lastQualityKey = q
      this.event('frame', ev.eligible ? 'Face usable for assessment' : `Frame not usable: ${q}`)
    }
    this.spanN++
    for (const [k, v] of Object.entries(ev.spansMs)) {
      this.spanSum[k] = (this.spanSum[k] ?? 0) + v
      r.spanMs[k] = this.spanSum[k]! / this.spanN
    }
    r.processingMs = ev.spansMs['total'] ?? null
    r.faceCount = ev.faceCount
    r.eligible = ev.eligible
    r.ineligibleReason = ev.ineligibleReason
    r.width = ev.width || r.width
    r.height = ev.height || r.height
    r.faceBox = ev.faceCount === 1 ? ev.faceBox : null
    if (ev.eligible && ev.pad !== null && Number.isFinite(ev.pad)) {
      r.lastPad = ev.pad
      r.padMin = r.padMin === null ? ev.pad : Math.min(r.padMin, ev.pad)
      r.padMax = r.padMax === null ? ev.pad : Math.max(r.padMax, ev.pad)
      this.recentPads.push(ev.pad)
      if (this.recentPads.length > 45) this.recentPads.shift() // about 3 s at 15 fps, as the passive window
      r.medianPad = medianLower(this.recentPads)
    }
    this.session.onEvidence(ev, now)
  }

  private syncState(): void {
    const r = this.raw
    const s = this.session
    const key = `${s.state}/${s.reason}`
    if (key !== this.lastStateKey) {
      this.lastStateKey = key
      this.event('state', `Engine state: ${s.state}${s.reason === 'NONE' ? '' : ` (${s.reason})`}`)
    }
    r.state = s.state
    r.reason = s.state === 'PASSIVE_PASSED' ? 'PASSIVE_PASSED' : s.reason
    r.attackEvents = s.attackEvents
    r.readyMs = s.readyAtMs
    r.verdict = verdictFor(s.state, r.reason)
  }

  private build(): Snapshot {
    return browserSnapshot(this.raw, this.o.thresholds ?? DEFAULT_THRESHOLDS, this.framesReceived, this.streaming)
  }

  private publish(): void {
    this.syncState()
    this.last = this.build()
    this.o.onSnapshot(this.last)
  }

  private finish(): void {
    this.running = false
    this.raw.active = false
    this.raw.finishedAtMs = Date.now()
    this.syncState()
    this.last = this.build()
    this.o.onSnapshot(this.last)
  }

  private fail(e: unknown): void {
    this.running = false
    const r = this.raw
    r.active = false
    r.finishedAtMs = Date.now()
    r.state = 'ERROR_ENGINE'
    r.reason = 'ENGINE_ERROR'
    r.detail = e instanceof Error ? e.message : 'Unknown error'
    r.verdict = verdictFor('ERROR_ENGINE', 'ENGINE_ERROR')
    this.event('state', 'Engine state: ERROR_ENGINE (the models failed; nothing was accepted)')
    this.last = this.build()
    this.o.onSnapshot(this.last)
  }

  private async loop(): Promise<void> {
    while (this.running) {
      const started = performance.now()
      try {
        const img = this.grab()
        this.streaming = img !== null
        if (img) {
          const ev = await this.o.pipeline.process(img)
          if (!this.running) return
          this.ingest(ev, performance.now())
        }
        this.session.tick(performance.now())
      } catch (e) {
        if (this.running) this.fail(e)
        return
      }
      if (this.session.done) {
        this.finish()
        return
      }
      this.publish()
      const wait = Math.max(8, FRAME_INTERVAL_MS - (performance.now() - started))
      await new Promise((res) => setTimeout(res, wait))
    }
  }
}
