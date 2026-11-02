// Port of the PASSIVE part of liveness-core LivenessSession (collecting evidence, attack count, motion check, median PAD).
// There is no capture phase here: a browser has no certified capture device, so the best outcome is PASSIVE_PASSED,
// which is explicitly NOT a verification.
import { assess, MOTION_DEFAULTS, photoResidual, type MotionRecord } from './motion'
import type { FrameEvidence } from './pipeline'

export interface PassivePolicy {
  streamAccept: number
  streamAttack: number
  attackMinFrames: number
  passiveWindowMs: number
  passiveMinFrames: number
  passiveMinSpanMs: number
  staticWindowMs: number
  collectTimeoutMs: number
  motionThreshold: number
  motionMinPairs: number
  motionMinVarying: number
}

/** The engine's SessionPolicy defaults. Provisional and uncalibrated. */
export const PASSIVE_DEFAULTS: PassivePolicy = {
  streamAccept: 0.8,
  streamAttack: 0.2,
  attackMinFrames: 3,
  passiveWindowMs: 3000,
  passiveMinFrames: 8,
  passiveMinSpanMs: 1000,
  staticWindowMs: 5000,
  collectTimeoutMs: 10_000,
  motionThreshold: MOTION_DEFAULTS.photoThreshold,
  motionMinPairs: MOTION_DEFAULTS.minPairs,
  motionMinVarying: MOTION_DEFAULTS.minVaryingPairs,
}

export type PassiveState = 'CAPTURING' | 'PASSIVE_PASSED' | 'RETRY_PENDING' | 'REJECTED_ATTACK'
export type PassiveReason = 'NONE' | 'OK' | 'INSUFFICIENT_EVIDENCE' | 'STATIC_REPLAY_SUSPECT' | 'PASSIVE_UNCERTAIN_NO_CHALLENGE' | 'MULTIPLE_FACES' | 'STREAM_PAD_ATTACK'

interface Rec extends MotionRecord {
  tMs: number
  faceCount: number
  eligible: boolean
  pad: number | null
}

/** Lower median, the conservative choice used by the engine. */
export function medianLower(v: number[]): number {
  const s = v.slice().sort((a, b) => a - b)
  return s[Math.floor((s.length - 1) / 2)]!
}

export class PassiveSession {
  state: PassiveState = 'CAPTURING'
  reason: PassiveReason = 'NONE'
  attackEvents = 0
  readyAtMs: number | null = null
  invalidEvidence = 0
  private attackFrames = 0
  private shortfall: PassiveReason = 'INSUFFICIENT_EVIDENCE'
  private records: Rec[] = []
  private lastUsable: Rec | null = null

  constructor(private readonly startedAtMs: number, private readonly policy: PassivePolicy = PASSIVE_DEFAULTS) {}

  get done(): boolean {
    return this.state !== 'CAPTURING'
  }

  onEvidence(ev: FrameEvidence, nowMs: number): void {
    if (this.done) return
    if (this.timedOut(nowMs)) return
    // invalid model output is never evidence
    if (ev.eligible && (ev.pad === null || !Number.isFinite(ev.pad) || ev.pad < 0 || ev.pad > 1 || ev.alignedGrey === null)) {
      this.invalidEvidence++
      return
    }
    const rec: Rec = { tMs: nowMs, faceCount: ev.faceCount, eligible: ev.eligible, pad: ev.pad, alignedGrey: ev.eligible ? ev.alignedGrey : null, photoToPrev: Number.NaN }
    if (rec.alignedGrey !== null && ev.landmarks !== null) {
      if (this.lastUsable?.alignedGrey) rec.photoToPrev = photoResidual(this.lastUsable.alignedGrey, rec.alignedGrey)
      this.lastUsable = rec
    }
    this.records.push(rec)
    const keepFrom = nowMs - Math.max(this.policy.staticWindowMs, this.policy.passiveWindowMs) - 1000
    while (this.records.length > 0 && this.records[0]!.tMs < keepFrom) this.records.shift()
    if (ev.eligible && ev.pad! < this.policy.streamAttack) this.attackFrames++
    this.evaluate(nowMs)
  }

  /** Call regularly (even with no frames) so the time limit is enforced. */
  tick(nowMs: number): void {
    if (!this.done) this.timedOut(nowMs)
  }

  private timedOut(nowMs: number): boolean {
    if (nowMs - this.startedAtMs > this.policy.collectTimeoutMs) {
      this.state = 'RETRY_PENDING'
      this.reason = this.shortfall
      return true
    }
    return false
  }

  private evaluate(nowMs: number): void {
    const p = this.policy
    if (this.attackFrames >= p.attackMinFrames) {
      this.state = 'REJECTED_ATTACK'
      this.reason = 'STREAM_PAD_ATTACK'
      this.attackEvents = 1
      return
    }
    const win = this.records.filter((r) => r.tMs >= nowMs - p.passiveWindowMs)
    const el: Rec[] = []
    for (const r of win) {
      if (r.faceCount > 1) {
        this.shortfall = 'MULTIPLE_FACES'
        return
      }
      if (r.eligible) el.push(r)
    }
    if (el.length < p.passiveMinFrames || el[el.length - 1]!.tMs - el[0]!.tMs < p.passiveMinSpanMs) {
      this.shortfall = 'INSUFFICIENT_EVIDENCE'
      return
    }
    const recent = this.records.filter((r) => r.eligible && r.tMs >= nowMs - p.staticWindowMs)
    const motion = assess(recent, { photoThreshold: p.motionThreshold, minPairs: p.motionMinPairs, minVaryingPairs: p.motionMinVarying })
    if (motion.verdict !== 'VARYING') {
      this.shortfall = 'STATIC_REPLAY_SUSPECT'
      return
    }
    if (medianLower(el.map((r) => r.pad!)) < p.streamAccept) {
      this.shortfall = 'PASSIVE_UNCERTAIN_NO_CHALLENGE'
      return
    }
    this.state = 'PASSIVE_PASSED'
    this.reason = 'OK'
    this.readyAtMs = nowMs - this.startedAtMs
  }
}
