// DEMO MODE ONLY. Deterministic, scripted events so the interface can be shown without a camera or the Java engine.
// Everything produced here is SIMULATED: it is labelled as such in the UI and is never mixed with real trial records.
import { DEFAULT_THRESHOLDS, idleRaw, toSnapshot } from './derive'
import type { Snapshot } from '../types'

export interface DemoScript {
  id: string
  title: string
  summary: string
  durationMs: number
}

type Frame = { faceCount: number; eligible: boolean; reason: string | null }

interface Spec extends DemoScript {
  frame: (t: number) => Frame
  pad: (t: number) => number
  /** time the session becomes ready for capture (ms), if it does */
  readyAt?: number
  returnAt?: number
  binding?: string
  capturePad?: number
  final: { state: string; reason: string; verdict: string; attack?: number; channel?: number; detail?: string }
}

const GOOD: Frame = { faceCount: 1, eligible: true, reason: null }
const wob = (i: number) => Math.sin(i * 1.7) * 0.012

const SPECS: Spec[] = [
  { id: 'verified', title: 'Verified', summary: 'A live face passes every stage.', durationMs: 4200, frame: () => GOOD, pad: () => 0.97, readyAt: 2200, returnAt: 2750, binding: 'OK', capturePad: 0.98,
    final: { state: 'VERIFIED', reason: 'OK', verdict: 'VERIFIED by the engine (stream PAD passed, signed capture bound, capture PAD >= gate)' } },
  { id: 'capture_uncertain', title: 'Retry: capture uncertain', summary: 'The signed capture scores between the lines.', durationMs: 4200, frame: () => GOOD, pad: () => 0.95, readyAt: 2200, returnAt: 2750, binding: 'PAD_UNCERTAIN', capturePad: 0.74,
    final: { state: 'RETRY_PENDING', reason: 'CAPTURE_UNCERTAIN', verdict: 'NOT ACCEPTED - retry: CAPTURE_UNCERTAIN' } },
  { id: 'static_image', title: 'Retry: no facial movement', summary: 'A face is found and scores well, but nothing moves.', durationMs: 7500, frame: () => GOOD, pad: () => 0.99,
    final: { state: 'RETRY_PENDING', reason: 'STATIC_REPLAY_SUSPECT', verdict: 'NOT ACCEPTED - retry: STATIC_REPLAY_SUSPECT' } },
  { id: 'pad_attack', title: 'Rejected: attack-level PAD', summary: 'Frames score as a presentation attack.', durationMs: 3000, frame: () => GOOD, pad: () => 0.05,
    final: { state: 'REJECTED_ATTACK', reason: 'STREAM_PAD_ATTACK', verdict: 'REJECTED: STREAM_PAD_ATTACK', attack: 1 } },
  { id: 'subject_mismatch', title: 'Rejected: different face at capture', summary: 'The signed capture shows another person.', durationMs: 4200, frame: () => GOOD, pad: () => 0.97, readyAt: 2200, returnAt: 2750, binding: 'SUBJECT_MISMATCH', capturePad: 0.96,
    final: { state: 'REJECTED_ATTACK', reason: 'BINDING_INTEGRITY', verdict: 'REJECTED: BINDING_INTEGRITY (SUBJECT_MISMATCH)', attack: 1 } },
  { id: 'channel_replay', title: 'Rejected: replayed device response', summary: 'The device answer was already used.', durationMs: 4200, frame: () => GOOD, pad: () => 0.97, readyAt: 2200, returnAt: 2750, binding: 'REPLAYED_RESPONSE',
    final: { state: 'REJECTED_ATTACK', reason: 'CHANNEL_INTEGRITY', verdict: 'REJECTED: CHANNEL_INTEGRITY (REPLAYED_RESPONSE)', channel: 1 } },
  { id: 'no_face', title: 'Retry: no face', summary: 'Nobody is in view.', durationMs: 6500, frame: () => ({ faceCount: 0, eligible: false, reason: 'NO_FACE' }), pad: () => 0,
    final: { state: 'RETRY_PENDING', reason: 'INSUFFICIENT_EVIDENCE', verdict: 'NOT ACCEPTED - retry: INSUFFICIENT_EVIDENCE' } },
  { id: 'multiple_faces', title: 'Retry: more than one face', summary: 'Two faces share the frame.', durationMs: 6500, frame: () => ({ faceCount: 2, eligible: false, reason: 'MULTIPLE_FACES' }), pad: () => 0,
    final: { state: 'RETRY_PENDING', reason: 'MULTIPLE_FACES', verdict: 'NOT ACCEPTED - retry: MULTIPLE_FACES' } },
  { id: 'too_dark', title: 'Retry: too dark', summary: 'The face is too dark to assess.', durationMs: 6500, frame: () => ({ faceCount: 1, eligible: false, reason: 'TOO_DARK' }), pad: () => 0,
    final: { state: 'RETRY_PENDING', reason: 'INSUFFICIENT_EVIDENCE', verdict: 'NOT ACCEPTED - retry: INSUFFICIENT_EVIDENCE' } },
  { id: 'blurred', title: 'Retry: blurred', summary: 'The face is not sharp enough.', durationMs: 6500, frame: () => ({ faceCount: 1, eligible: false, reason: 'BLUR' }), pad: () => 0,
    final: { state: 'RETRY_PENDING', reason: 'INSUFFICIENT_EVIDENCE', verdict: 'NOT ACCEPTED - retry: INSUFFICIENT_EVIDENCE' } },
  { id: 'engine_error', title: 'Technical error', summary: 'The engine fails closed on an internal error.', durationMs: 2500, frame: () => GOOD, pad: () => 0.9,
    final: { state: 'ERROR_ENGINE', reason: 'ENGINE_ERROR', verdict: 'ERROR_ENGINE / ENGINE_ERROR', detail: 'Simulated engine error' } },
]

export const DEMO_SCRIPTS: DemoScript[] = SPECS.map(({ id, title, summary, durationMs }) => ({ id, title, summary, durationMs }))

const FRAME_MS = 1000 / 15

/** Deterministic: the same script at the same time always gives the same snapshot. */
export function demoSnapshot(scriptId: string, t: number, trialNumber: number, startedAtMs: number, label: string | null): Snapshot {
  const spec = SPECS.find((s) => s.id === scriptId) ?? SPECS[0]!
  const r = idleRaw()
  r.trialNumber = trialNumber
  r.trialId = `DEMO-${trialNumber}`
  r.label = label
  r.startedAtMs = startedAtMs
  r.active = true
  r.state = 'CAPTURING'
  r.reason = 'NONE'
  r.attempt = 1
  r.verdict = 'collecting stream evidence...'
  r.spanMs = { decode: 5.2, detect: 3.1, quality: 0.5, pad: 3.3 }
  r.events = [{ tMs: 0, type: 'start', text: `Trial started (simulated${label ? `, label: ${label}` : ''})` }]

  const n = Math.min(Math.floor(t / FRAME_MS), Math.floor(spec.durationMs / FRAME_MS))
  const pads: number[] = []
  let lastKey = ''
  for (let i = 0; i < n; i++) {
    const ft = i * FRAME_MS
    if (spec.readyAt != null && ft > spec.readyAt) break // after the request only the capture matters for the display
    const f = spec.frame(ft)
    r.frames++
    if (f.eligible) {
      r.eligibleFrames++
      const p = Math.min(0.999, Math.max(0.001, spec.pad(ft) + wob(i)))
      pads.push(p)
      r.padMin = r.padMin == null ? p : Math.min(r.padMin, p)
      r.padMax = r.padMax == null ? p : Math.max(r.padMax, p)
      r.lastPad = p
    } else if (f.reason) {
      r.ineligibleCounts[f.reason] = (r.ineligibleCounts[f.reason] ?? 0) + 1
    }
    r.faceCount = f.faceCount
    r.eligible = f.eligible
    r.ineligibleReason = f.reason
    const key = f.eligible ? 'OK' : String(f.reason)
    if (key !== lastKey) {
      lastKey = key
      r.events.push({ tMs: Math.round(ft), type: 'frame', text: f.eligible ? 'Face usable for assessment' : `Frame not usable: ${f.reason}` })
    }
  }
  if (pads.length) {
    const recent = pads.slice(-45).sort((a, b) => a - b)
    r.medianPad = recent[Math.floor((recent.length - 1) / 2)] ?? null
  }
  if (r.faceCount >= 1) {
    r.faceBox = [r.width * 0.34, r.height * 0.14, r.width * 0.3, r.height * 0.62]
  }
  r.processingMs = 12.4

  if (spec.readyAt != null && t >= spec.readyAt) {
    r.readyMs = spec.readyAt
    r.captureIssued = true
    r.state = 'CAPTURE_IN_FLIGHT'
    r.verdict = 'capturing signed image...'
    r.events.push({ tMs: spec.readyAt, type: 'capture', text: 'Passive checks passed; signed capture requested (simulated)' })
    if (spec.returnAt != null && t >= spec.returnAt) {
      r.captureRoundTripMs = spec.returnAt - spec.readyAt
      r.events.push({ tMs: spec.returnAt, type: 'capture', text: 'Signed capture received from the device (simulated)' })
      r.bindingReason = spec.binding ?? null
      if (spec.capturePad != null) r.capturePad = spec.capturePad
      r.bindMs = 212
    }
  }

  if (t >= spec.durationMs) {
    r.active = false
    r.finishedAtMs = startedAtMs + spec.durationMs
    r.state = spec.final.state
    r.reason = spec.final.reason
    r.verdict = spec.final.verdict
    r.detail = spec.final.detail ?? null
    r.attackEvents = spec.final.attack ?? 0
    r.channelEvents = spec.final.channel ?? 0
    r.events.push({ tMs: spec.durationMs, type: 'state', text: `Engine state: ${spec.final.state} (${spec.final.reason}) — simulated` })
    if (r.captureIssued && r.bindingReason == null) r.bindingReason = spec.binding ?? null
  }
  return toSnapshot(r, DEFAULT_THRESHOLDS, n, t < spec.durationMs)
}

/** A cancelled simulated trial: never a decision. Mirrors LiveTrialController.cancelTrial. */
export function cancelledCopy(s: Snapshot, nowMs: number): Snapshot {
  const startedAt = s.trial.startedAtMs ?? nowMs
  return {
    ...s,
    trial: { ...s.trial, active: false, unfinished: true, finishedAtMs: nowMs },
    decision: { ...s.decision, state: 'CANCELLED', reason: 'CANCELLED', bindingReason: null, verdict: 'Cancelled before a decision', detail: 'The trial was cancelled by the operator.', final: true },
    timing: { ...s.timing, decisionMs: nowMs - startedAt },
    stages: s.stages.map((x) => (x.id === 'decision' ? { ...x, state: 'skipped' as const, reasonCode: 'CANCELLED', detail: 'Cancelled before a decision' } : x.state === 'active' ? { ...x, state: 'skipped' as const } : x)),
    events: [...s.events, { tMs: nowMs - startedAt, type: 'state', text: 'Engine state: CANCELLED (operator) — simulated' }],
  }
}
