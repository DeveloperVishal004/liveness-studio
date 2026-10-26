// DEMO-ONLY port of liveness-core LiveSnapshot (stage and integrity derivation). In real mode the engine sends these
// already derived; this file exists so the simulator produces snapshots of exactly the same shape and rules.
// The tests replay the Java table so the two stay in step.
import type { Check, CheckState, EventEntry, Snapshot, Stage, StageState, Thresholds } from '../types'

export const DEFAULT_THRESHOLDS: Thresholds = {
  streamAccept: 0.8,
  streamAttack: 0.2,
  captureAccept: 0.8,
  captureAttack: 0.2,
  subjectMinCosine: 0.5,
  motionTrigger: 0.4,
  minFaceHeightPx: 80,
  minSharpness: 15,
  minStreamEmbeddings: 3,
  attackMinFrames: 3,
}

export interface Raw {
  trialNumber: number
  trialId: string | null
  label: string | null
  active: boolean
  unfinished: boolean
  startedAtMs: number
  finishedAtMs: number | null
  state: string
  reason: string
  bindingReason: string | null
  verdict: string
  detail: string | null
  faceCount: number
  eligible: boolean
  ineligibleReason: string | null
  faceBox: number[] | null
  width: number
  height: number
  processingMs: number | null
  frames: number
  eligibleFrames: number
  ineligibleCounts: Record<string, number>
  lastPad: number | null
  medianPad: number | null
  padMin: number | null
  padMax: number | null
  captureIssued: boolean
  capturePad: number | null
  bindMs: number | null
  readyMs: number | null
  captureRoundTripMs: number | null
  spanMs: Record<string, number>
  attackEvents: number
  channelEvents: number
  attempt: number
  maxAttempts: number
  events: EventEntry[]
}

const FINISHED = ['VERIFIED', 'RETRY_PENDING', 'REJECTED_ATTACK', 'ERROR_ENGINE', 'ERROR_DEVICE', 'EXPIRED']
export const isFinished = (state: string) => FINISHED.includes(state) || state.startsWith('FAILED')
export const isDecided = (state: string) => isFinished(state) || state === 'CANCELLED'

export const CHECK_IDS = ['response', 'signature', 'chain', 'replay', 'device', 'nonce', 'timestamp', 'biometric', 'faceCount', 'subject']
export const CHECK_LABELS = ['Response format', 'RS256 signature', 'Certificate chain and trust', 'Replay protection', 'Device identity', 'Nonce (transaction ID)', 'Timestamp window', 'Biometric record', 'Face count in capture', 'Stream / capture subject match']

export function failingCheck(binding: string | null): number {
  if (binding == null) return -2
  switch (binding) {
    case 'MALFORMED_RESPONSE': case 'DEVICE_ERROR': return 0
    case 'BAD_SIGNATURE': return 1
    case 'UNTRUSTED_DEVICE': return 2
    case 'REPLAYED_RESPONSE': return 3
    case 'DIGITAL_ID_INVALID': case 'DEVICE_MISMATCH': return 4
    case 'TRANSACTION_ABSENT': case 'TRANSACTION_MISMATCH': return 5
    case 'MALFORMED_CONTENT': case 'CAPTURE_STALE': case 'CAPTURE_FROM_FUTURE': case 'CAPTURE_OUTSIDE_WINDOW': return 6
    case 'BAD_BIO_FORMAT': return 7
    case 'NO_FACE': case 'MULTIPLE_FACES': return 8
    case 'SUBJECT_MISMATCH': return 9
    default: return -1
  }
}

const captureFailed = (r: Raw) => r.detail != null && r.detail.startsWith('RCAPTURE failed')

export function deriveIntegrity(r: Raw): Check[] {
  const n = CHECK_IDS.length
  const st: CheckState[] = Array(n).fill('not_checked')
  const why: string[] = Array(n).fill(r.captureIssued ? 'Waiting for the device response.' : 'No signed capture was requested in this trial.')
  if (captureFailed(r)) {
    st.fill('unavailable')
    why.fill(r.detail ?? '')
  } else if (r.captureIssued && r.bindingReason != null) {
    const f = failingCheck(r.bindingReason)
    for (let i = 0; i < n; i++) {
      if (f >= 0 && i === f) { st[i] = 'failed'; why[i] = 'Failed: ' + r.bindingReason }
      else if (f >= 0 && i > f) { st[i] = 'not_checked'; why[i] = 'Not reached: an earlier check failed.' }
      else { st[i] = 'passed'; why[i] = '' }
    }
    if (f === -1) {
      const br = r.bindingReason
      if (br === 'ENGINE_ERROR') {
        for (let i = 8; i < n; i++) { st[i] = 'unavailable'; why[i] = 'The analysis step failed (engine error).' }
      } else if (br === 'PAD_ATTACK') {
        st[9] = 'not_checked'; why[9] = 'Not reached: capture PAD flagged an attack first.'
      } else if (br === 'INSUFFICIENT_STREAM_EVIDENCE') {
        st[9] = 'not_checked'; why[9] = 'Not enough stream face samples near the capture (needs at least 3).'
      } else {
        const whole = r.state === 'VERIFIED'
        if (r.reason === 'SUBJECT_CHANGED') { st[9] = 'failed'; why[9] = 'A face earlier in the attempt did not match the capture (whole-attempt check).' }
        else if (br === 'OK' && !whole) { st[9] = 'not_checked'; why[9] = `The median match passed; the whole-attempt check was not reached (${r.reason}).` }
        else { st[9] = 'passed'; why[9] = whole ? 'Every frontal face sample in the attempt matched the capture.' : 'The median stream face matched the capture.' }
      }
    } else if (f === 9) {
      why[9] = 'Stream and capture faces differ (median similarity below the line).'
    }
  }
  const out: Check[] = CHECK_IDS.map((id, i) => ({ id, label: CHECK_LABELS[i]!, state: st[i]!, detail: why[i]! }))
  out.push({ id: 'streamAuth', label: 'Signed stream (B1 digest)', state: 'not_applicable', detail: 'SBI 1.0 streams are unsigned. The signed-stream prototype is disabled in this build.' })
  return out
}

const f2 = (v: number | null) => (v == null || !Number.isFinite(v) ? '-' : v.toFixed(2))

function stage(id: string, label: string, model: string | null, state: StageState, ms: number | null, code: string | null, detail: string): Stage {
  return { id, label, model, state, durationMs: ms, reasonCode: code, detail }
}

export function deriveStages(r: Raw, t: Thresholds): Stage[] {
  const out: Stage[] = []
  const idle = r.trialNumber === 0
  const running = r.active
  const done = isDecided(r.state)
  const noFace = r.ineligibleCounts['NO_FACE'] ?? 0
  const multi = r.ineligibleCounts['MULTIPLE_FACES'] ?? 0
  const oneFace = Math.max(0, r.frames - noFace - multi)
  const M = 'MiniFASNet (public, uncalibrated)'
  const QM = 'Size, light, sharpness'

  if (idle || r.frames === 0) out.push(stage('detect', 'Face detection', 'YuNet', running ? 'active' : 'pending', null, null, running ? 'Waiting for camera frames.' : 'Starts when a verification begins.'))
  else if (oneFace === 0) out.push(stage('detect', 'Face detection', 'YuNet', 'attention', r.spanMs['detect'] ?? null, noFace >= multi ? 'NO_FACE' : 'MULTIPLE_FACES', noFace >= multi ? `No face found in ${r.frames} frames.` : 'More than one face in view.'))
  else if (running && r.faceCount > 1) out.push(stage('detect', 'Face detection', 'YuNet', 'attention', r.spanMs['detect'] ?? null, 'MULTIPLE_FACES', 'More than one face in view right now.'))
  else out.push(stage('detect', 'Face detection', 'YuNet', 'passed', r.spanMs['detect'] ?? null, null, `Exactly one face found in ${oneFace} of ${r.frames} frames.`))

  const topIneligible = (): string | null => {
    let best: string | null = null
    let n = 0
    for (const [k, v] of Object.entries(r.ineligibleCounts)) {
      if (k === 'NO_FACE' || k === 'MULTIPLE_FACES') continue
      if (v > n) { n = v; best = k }
    }
    return best
  }
  if (idle || r.frames === 0) out.push(stage('quality', 'Image-quality gates', QM, 'pending', null, null, 'Checks face size, brightness and sharpness.'))
  else if (r.eligibleFrames === 0) { const top = topIneligible(); out.push(stage('quality', 'Image-quality gates', QM, 'attention', r.spanMs['quality'] ?? null, top, top == null ? 'No frame was usable yet.' : `No frame passed the quality gates (${top}).`)) }
  else if (running && !r.eligible && r.faceCount === 1) out.push(stage('quality', 'Image-quality gates', QM, 'attention', r.spanMs['quality'] ?? null, r.ineligibleReason, `Latest frame not usable: ${r.ineligibleReason}.`))
  else out.push(stage('quality', 'Image-quality gates', QM, 'passed', r.spanMs['quality'] ?? null, null, `${r.eligibleFrames} of ${r.frames} frames usable.`))

  const padAttack = r.reason === 'STREAM_PAD_ATTACK'
  if (r.eligibleFrames === 0) out.push(stage('pad', 'Passive presentation-attack check', M, 'pending', null, null, 'Scores each usable frame once a face passes the quality gates.'))
  else if (padAttack) out.push(stage('pad', 'Passive presentation-attack check', M, 'failed', r.spanMs['pad'] ?? null, 'STREAM_PAD_ATTACK', `At least ${t.attackMinFrames} frames scored below ${f2(t.streamAttack)} (median ${f2(r.medianPad)}).`))
  else if (r.medianPad != null && r.medianPad >= t.streamAccept) out.push(stage('pad', 'Passive presentation-attack check', M, 'passed', r.spanMs['pad'] ?? null, null, `Median stream score ${f2(r.medianPad)} (accept at ${f2(t.streamAccept)} or above). An uncalibrated model score, not a probability of identity.`))
  else out.push(stage('pad', 'Passive presentation-attack check', M, 'attention', r.spanMs['pad'] ?? null, done ? 'PASSIVE_UNCERTAIN_NO_CHALLENGE' : null, `Median stream score ${f2(r.medianPad)} is below ${f2(t.streamAccept)}.`))

  const TM = 'Motion across frames'
  if (r.readyMs != null) out.push(stage('temporal', 'Temporal evidence', TM, 'passed', r.readyMs, null, `Facial movement above the trigger was seen and the session became ready after ${r.readyMs} ms.`))
  else if (r.reason === 'STATIC_REPLAY_SUSPECT') out.push(stage('temporal', 'Temporal evidence', TM, 'attention', null, 'STATIC_REPLAY_SUSPECT', 'No facial movement above the trigger. Smiling or speaking helps; blinking alone is too small on many cameras.'))
  else if (r.eligibleFrames === 0 || padAttack) out.push(stage('temporal', 'Temporal evidence', TM, done ? 'skipped' : 'pending', null, null, 'Looks for natural facial movement once usable frames are scored.'))
  else if (running) out.push(stage('temporal', 'Temporal evidence', TM, 'active', null, null, 'Looking for natural facial movement.'))
  else out.push(stage('temporal', 'Temporal evidence', TM, 'attention', null, r.reason, 'Not enough usable evidence before the time limit.'))

  const checks = deriveIntegrity(r)
  const IM = 'RS256, trust chain, nonce, time'
  let firstFail: string | null = null
  let anyPassed = false
  for (const c of checks) {
    if (c.state === 'failed' && c.id !== 'subject') { firstFail = c.id; break }
    if (c.state === 'passed') anyPassed = true
  }
  const fc = checks.find((c) => c.id === 'faceCount')?.state === 'passed'
  const label = (id: string) => CHECK_LABELS[CHECK_IDS.indexOf(id)] ?? id
  if (captureFailed(r)) out.push(stage('integrity', 'Signed capture and device integrity', IM, 'failed', null, 'CAPTURE_UNAVAILABLE', r.detail ?? ''))
  else if (!r.captureIssued) out.push(stage('integrity', 'Signed capture and device integrity', IM, done ? 'skipped' : 'pending', null, null, done ? 'Not reached: the session never became ready for capture.' : 'Runs after the passive checks pass.'))
  else if (r.bindingReason == null) out.push(stage('integrity', 'Signed capture and device integrity', IM, 'active', r.captureRoundTripMs, null, 'Waiting for the signed response and verifying it.'))
  else if (firstFail != null) out.push(stage('integrity', 'Signed capture and device integrity', IM, 'failed', r.bindMs, r.bindingReason, `Check failed: ${label(firstFail)}.`))
  else if (anyPassed && fc) out.push(stage('integrity', 'Signed capture and device integrity', IM, 'passed', r.bindMs, null, 'Signature, chain, replay, device, nonce, time, record and face count all passed. This shows the capture channel is intact, not that the face was live.'))
  else out.push(stage('integrity', 'Signed capture and device integrity', IM, 'attention', r.bindMs, r.bindingReason, 'Verification ended early.'))

  const CM = 'MiniFASNet on the signed image'
  if (!r.captureIssued || captureFailed(r)) out.push(stage('capturePad', 'Signed-capture PAD gate', CM, done ? 'skipped' : 'pending', null, null, 'Scores the signed image itself.'))
  else if (r.capturePad == null) out.push(stage('capturePad', 'Signed-capture PAD gate', CM, r.bindingReason == null ? 'active' : 'skipped', null, null, r.bindingReason == null ? 'Scoring the signed image.' : 'Not reached: an integrity check failed first.'))
  else if (r.capturePad < t.captureAttack) out.push(stage('capturePad', 'Signed-capture PAD gate', CM, 'failed', null, 'PAD_ATTACK', `Capture score ${f2(r.capturePad)} is below the attack line ${f2(t.captureAttack)}.`))
  else if (r.capturePad < t.captureAccept) out.push(stage('capturePad', 'Signed-capture PAD gate', CM, 'attention', null, 'PAD_UNCERTAIN', `Capture score ${f2(r.capturePad)} is between the attack line and the accept gate ${f2(t.captureAccept)}. Retry required.`))
  else out.push(stage('capturePad', 'Signed-capture PAD gate', CM, 'passed', null, null, `Capture score ${f2(r.capturePad)} (accept at ${f2(t.captureAccept)} or above).`))

  const subj = checks[9]!
  const SM = 'SFace'
  const SL = 'Stream / capture subject match'
  if (!r.captureIssued || captureFailed(r)) out.push(stage('subject', SL, SM, done ? 'skipped' : 'pending', null, null, 'Compares the face seen on the stream with the face in the signed capture.'))
  else if (subj.state === 'failed') out.push(stage('subject', SL, SM, 'failed', null, r.reason === 'SUBJECT_CHANGED' ? 'SUBJECT_CHANGED' : 'SUBJECT_MISMATCH', subj.detail))
  else if (subj.state === 'passed') out.push(stage('subject', SL, SM, 'passed', null, null, subj.detail))
  else if (r.bindingReason === 'INSUFFICIENT_STREAM_EVIDENCE') out.push(stage('subject', SL, SM, 'attention', null, 'INSUFFICIENT_STREAM_EVIDENCE', subj.detail))
  else out.push(stage('subject', SL, SM, r.bindingReason == null ? 'pending' : 'skipped', null, null, subj.detail))

  let ds: StageState
  if (idle || (running && !done)) ds = running ? 'active' : 'pending'
  else if (r.state === 'VERIFIED') ds = 'passed'
  else if (r.state === 'RETRY_PENDING') ds = 'attention'
  else if (r.state === 'CANCELLED') ds = 'skipped'
  else ds = 'failed'
  out.push(stage('decision', 'Engine decision', 'Session state machine', ds, null, done ? r.reason : null, idle ? 'No verification has run.' : r.verdict))
  return out
}

export function toSnapshot(r: Raw, t: Thresholds, framesReceived: number, streaming: boolean): Snapshot {
  return {
    trial: { id: r.trialId, number: r.trialNumber, label: r.label, active: r.active, unfinished: r.unfinished, startedAtMs: r.trialNumber === 0 ? null : r.startedAtMs, finishedAtMs: r.finishedAtMs, attempt: r.attempt || null, maxAttempts: r.maxAttempts || null },
    decision: { state: r.state, reason: r.reason, bindingReason: r.bindingReason, verdict: r.verdict, detail: r.detail, final: isDecided(r.state) },
    frame: { width: r.width, height: r.height, faceCount: r.faceCount, eligible: r.eligible, ineligibleReason: r.ineligibleReason, faceBox: r.faceBox, processingMs: r.processingMs, ageMs: null },
    pad: { stream: { last: r.lastPad, median: r.medianPad, min: r.padMin, max: r.padMax, frames: r.frames, eligibleFrames: r.eligibleFrames }, capture: { score: r.capturePad } },
    timing: { readyMs: r.readyMs, captureRoundTripMs: r.captureRoundTripMs, bindMs: r.bindMs, frameSpansMs: r.spanMs, decisionMs: r.finishedAtMs != null && r.startedAtMs ? r.finishedAtMs - r.startedAtMs : null },
    counters: { attackEvents: r.attackEvents, channelEvents: r.channelEvents },
    camera: { framesReceived, lastFrameAgeMs: streaming ? 30 : null, streaming },
    ineligibleCounts: r.ineligibleCounts,
    stages: deriveStages(r, t),
    integrity: deriveIntegrity(r),
    events: r.events,
  }
}

export function idleRaw(): Raw {
  return {
    trialNumber: 0, trialId: null, label: null, active: false, unfinished: false, startedAtMs: 0, finishedAtMs: null,
    state: 'IDLE', reason: '', bindingReason: null, verdict: '', detail: null, faceCount: -1, eligible: false, ineligibleReason: null,
    faceBox: null, width: 960, height: 540, processingMs: null, frames: 0, eligibleFrames: 0, ineligibleCounts: {}, lastPad: null,
    medianPad: null, padMin: null, padMax: null, captureIssued: false, capturePad: null, bindMs: null, readyMs: null,
    captureRoundTripMs: null, spanMs: {}, attackEvents: 0, channelEvents: 0, attempt: 0, maxAttempts: 3, events: [],
  }
}
