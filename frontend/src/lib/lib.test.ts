import { describe, expect, it, beforeEach } from 'vitest'
import { ApiError, parseSnapshot } from './api'
import { filterRecords, percentile, summarize, groupOf } from './analytics'
import { DEMO_SCRIPTS, demoSnapshot } from './demo'
import { CHECK_IDS, DEFAULT_THRESHOLDS, deriveIntegrity, deriveStages, idleRaw, type Raw } from './derive'
import { csvCell, toCsv, toJson } from './exporters'
import { explainReason, frameGuidance } from './copy'
import { OUTCOME_LABEL, outcomeKind, sessionPhase } from './outcome'
import { matchedExpectation, SCENARIOS } from './scenarios'
import { recordFromSnapshot, upsertRecord, loadRecords, clearRecords, mergeRecords } from './trials'
import type { Snapshot, TrialRecord } from '../types'

// minimal localStorage for the node test environment
class MemStore {
  private m = new Map<string, string>()
  getItem(k: string) { return this.m.get(k) ?? null }
  setItem(k: string, v: string) { this.m.set(k, v) }
  removeItem(k: string) { this.m.delete(k) }
}
beforeEach(() => { (globalThis as unknown as { localStorage: MemStore }).localStorage = new MemStore() })

function raw(over: Partial<Raw> = {}): Raw {
  return { ...idleRaw(), trialNumber: 1, trialId: 'T1', active: false, state: 'RETRY_PENDING', reason: 'BINDING_REJECTED', captureIssued: true,
    frames: 60, eligibleFrames: 55, faceCount: 1, eligible: true, medianPad: 0.97, lastPad: 0.97, startedAtMs: 1000, finishedAtMs: 5000, verdict: 'v', ...over }
}

describe('outcome mapping', () => {
  const snap = (state: string, final: boolean, n = 1): Snapshot => ({ ...demoSnapshot('verified', 0, n, 0, null), decision: { state, reason: 'X', bindingReason: null, verdict: '', detail: null, final } })
  it('only the engine final VERIFIED state is verified', () => {
    for (const state of ['CAPTURING', 'READY_FOR_CAPTURE', 'CAPTURE_IN_FLIGHT', 'RETRY_PENDING', 'REJECTED_ATTACK', 'FAILED_POLICY', 'ERROR_ENGINE', 'EXPIRED', 'CANCELLED', 'IDLE', 'SOMETHING']) {
      expect(outcomeKind(snap(state, true))).not.toBe('verified')
      expect(outcomeKind(snap(state, false))).not.toBe('verified')
    }
    expect(outcomeKind(snap('VERIFIED', true))).toBe('verified')
    expect(outcomeKind(snap('VERIFIED', false))).toBe('running') // not final yet: never shown as a result
  })
  it('a perfect score, detected face and bound capture are not a verdict', () => {
    const s = demoSnapshot('verified', 2000, 1, 0, null) // ready, capture in flight, pad 0.97
    expect(s.pad.stream.median).toBeGreaterThan(0.9)
    expect(s.frame.eligible).toBe(true)
    expect(outcomeKind(s)).toBe('running')
    expect(s.stages[7]!.state).toBe('active')
  })
  it('classifies the other states', () => {
    expect(outcomeKind(null)).toBe('idle')
    expect(outcomeKind(snap('RETRY_PENDING', true))).toBe('retry')
    expect(outcomeKind(snap('REJECTED_ATTACK', true))).toBe('rejected')
    expect(outcomeKind(snap('FAILED_MAX_RETRIES', true))).toBe('rejected')
    expect(outcomeKind(snap('ERROR_ENGINE', true))).toBe('error')
    expect(outcomeKind(snap('CANCELLED', true))).toBe('cancelled')
    expect(OUTCOME_LABEL.error).toBe('Technical error')
  })
  it('session phases map real engine states', () => {
    expect(sessionPhase(null)).toBe('Not started')
    expect(sessionPhase(demoSnapshot('verified', 0, 1, 0, null))).toBe('Initializing')
    expect(sessionPhase(demoSnapshot('verified', 1000, 1, 0, null))).toBe('Assessing evidence')
    expect(sessionPhase(demoSnapshot('no_face', 1000, 1, 0, null))).toBe('Waiting for a suitable face')
    expect(sessionPhase(demoSnapshot('verified', 2500, 1, 0, null))).toBe('Validating capture')
    expect(sessionPhase(demoSnapshot('verified', 9999, 1, 0, null))).toBe('Verified')
    expect(sessionPhase(demoSnapshot('engine_error', 9999, 1, 0, null))).toBe('Technical error')
  })
})

describe('integrity derivation (same table as the Java tests)', () => {
  const p = 'passed', f = 'failed', n = 'not_checked'
  const table: [string, string[]][] = [
    ['MALFORMED_RESPONSE', [f, n, n, n, n, n, n, n, n, n]],
    ['BAD_SIGNATURE', [p, f, n, n, n, n, n, n, n, n]],
    ['UNTRUSTED_DEVICE', [p, p, f, n, n, n, n, n, n, n]],
    ['REPLAYED_RESPONSE', [p, p, p, f, n, n, n, n, n, n]],
    ['DEVICE_MISMATCH', [p, p, p, p, f, n, n, n, n, n]],
    ['TRANSACTION_MISMATCH', [p, p, p, p, p, f, n, n, n, n]],
    ['CAPTURE_OUTSIDE_WINDOW', [p, p, p, p, p, p, f, n, n, n]],
    ['BAD_BIO_FORMAT', [p, p, p, p, p, p, p, f, n, n]],
    ['NO_FACE', [p, p, p, p, p, p, p, p, f, n]],
    ['MULTIPLE_FACES', [p, p, p, p, p, p, p, p, f, n]],
    ['PAD_ATTACK', [p, p, p, p, p, p, p, p, p, n]],
    ['INSUFFICIENT_STREAM_EVIDENCE', [p, p, p, p, p, p, p, p, p, n]],
    ['SUBJECT_MISMATCH', [p, p, p, p, p, p, p, p, p, f]],
    ['PAD_UNCERTAIN', [p, p, p, p, p, p, p, p, p, p]],
  ]
  it.each(table)('%s', (reason, expected) => {
    const got = deriveIntegrity(raw({ bindingReason: reason })).map((c) => c.state)
    expected.forEach((e, i) => expect(got[i], `${reason} / ${CHECK_IDS[i]}`).toBe(e))
    expect(got[10]).toBe('not_applicable')
  })
  it('nothing passes without a capture or after a non-pass', () => {
    for (const c of deriveIntegrity(raw({ captureIssued: false, state: 'RETRY_PENDING', reason: 'STATIC_REPLAY_SUSPECT' }))) expect(c.state).not.toBe('passed')
    for (const reason of ['', 'SOMETHING_NEW', 'ENGINE_ERROR', 'OK']) {
      let seen = false
      for (const c of deriveIntegrity(raw({ bindingReason: reason })).slice(0, 10)) {
        if (c.state === 'passed') expect(seen).toBe(false)
        else seen = true
      }
    }
  })
  it('an unavailable capture marks every check unavailable', () => {
    const c = deriveIntegrity(raw({ detail: 'RCAPTURE failed: device unplugged' })).slice(0, 10)
    expect(c.every((x) => x.state === 'unavailable')).toBe(true)
  })
  it('the decision stage is passed only for VERIFIED', () => {
    for (const state of ['CAPTURING', 'RETRY_PENDING', 'REJECTED_ATTACK', 'ERROR_ENGINE', 'EXPIRED', 'CANCELLED', 'VERIFIED']) {
      const d = deriveStages(raw({ state, bindingReason: 'OK', capturePad: 1, readyMs: 900, active: state === 'CAPTURING' }), DEFAULT_THRESHOLDS)[7]!
      expect(d.state === 'passed').toBe(state === 'VERIFIED')
    }
  })
  it('thresholds come from the policy object', () => {
    const t = { ...DEFAULT_THRESHOLDS, streamAccept: 0.9 }
    expect(deriveStages(raw({ medianPad: 0.85, captureIssued: false, active: true, state: 'CAPTURING', bindingReason: null }), t)[2]!.state).toBe('attention')
    expect(deriveStages(raw({ medianPad: 0.85, captureIssued: false, active: true, state: 'CAPTURING', bindingReason: null }), DEFAULT_THRESHOLDS)[2]!.state).toBe('passed')
  })
})

describe('demo simulator', () => {
  it('is deterministic', () => {
    for (const s of DEMO_SCRIPTS) expect(demoSnapshot(s.id, 1234, 3, 99, 'x')).toEqual(demoSnapshot(s.id, 1234, 3, 99, 'x'))
  })
  it('every script ends in its documented outcome and keeps every stage in a valid state', () => {
    const expected: Record<string, string> = { verified: 'VERIFIED', capture_uncertain: 'RETRY_PENDING', static_image: 'RETRY_PENDING', pad_attack: 'REJECTED_ATTACK',
      subject_mismatch: 'REJECTED_ATTACK', channel_replay: 'REJECTED_ATTACK', no_face: 'RETRY_PENDING', multiple_faces: 'RETRY_PENDING', too_dark: 'RETRY_PENDING', blurred: 'RETRY_PENDING', engine_error: 'ERROR_ENGINE' }
    for (const s of DEMO_SCRIPTS) {
      const end = demoSnapshot(s.id, s.durationMs + 50, 1, 0, null)
      expect(end.decision.state, s.id).toBe(expected[s.id])
      expect(end.decision.final).toBe(true)
      expect(() => parseSnapshot(JSON.parse(JSON.stringify(end)))).not.toThrow()
      expect(end.stages).toHaveLength(8)
      expect(end.integrity).toHaveLength(11)
    }
  })
  it('only the verified script verifies', () => {
    const verified = DEMO_SCRIPTS.filter((s) => demoSnapshot(s.id, s.durationMs + 50, 1, 0, null).decision.state === 'VERIFIED')
    expect(verified.map((s) => s.id)).toEqual(['verified'])
  })
  it('simulated events are marked as simulated', () => {
    const e = demoSnapshot('verified', 5000, 1, 0, null).events.map((x) => x.text).join('\n')
    expect(e).toMatch(/simulated/i)
  })
})

describe('parseSnapshot guards the engine response', () => {
  const good = demoSnapshot('verified', 0, 1, 0, null)
  it('accepts the real shape', () => expect(parseSnapshot(JSON.parse(JSON.stringify(good)))).toBeTruthy())
  it.each([null, 5, 'x', [], {}, { trial: {} }])('rejects %j', (v) => {
    expect(() => parseSnapshot(v)).toThrow(ApiError)
  })
  it('rejects a bad stage state or missing arrays', () => {
    const bad = JSON.parse(JSON.stringify(good))
    bad.stages[0].state = 'glowing'
    expect(() => parseSnapshot(bad)).toThrow(/unexpected/)
    const bad2 = JSON.parse(JSON.stringify(good))
    delete bad2.integrity
    expect(() => parseSnapshot(bad2)).toThrow(ApiError)
  })
})

function rec(over: Partial<TrialRecord> = {}): TrialRecord {
  const s = demoSnapshot('verified', 9999, 1, 1000, 'genuine_live')
  return { ...recordFromSnapshot(s, 'demo')!, ...over }
}

describe('analytics', () => {
  it('has no data yet for an empty set and fabricates nothing', () => {
    const s = summarize([])
    expect(s.total).toBe(0)
    expect(s.genuine.n).toBe(0)
    expect(s.decisionMs.median).toBeNull()
    expect(s.decisionMs.p95).toBeNull()
    expect(s.preliminary).toBe(true)
  })
  it('separates labels from outcomes and computes rates only over labelled, decided trials', () => {
    const rs = [
      rec({ id: 'a', label: 'genuine_live', state: 'VERIFIED', reason: 'OK' }),
      rec({ id: 'b', label: 'genuine_live', state: 'RETRY_PENDING', reason: 'STATIC_REPLAY_SUSPECT' }),
      rec({ id: 'c', label: 'screen_replay', state: 'REJECTED_ATTACK', reason: 'STREAM_PAD_ATTACK' }),
      rec({ id: 'd', label: 'printed_photo', state: 'VERIFIED', reason: 'OK' }),
      rec({ id: 'e', label: null, state: 'VERIFIED', reason: 'OK' }),
      rec({ id: 'f', label: 'genuine_live', state: 'CANCELLED', reason: 'CANCELLED', unfinished: true }),
    ]
    const s = summarize(rs)
    expect(s.total).toBe(6)
    expect(s.decided).toBe(5)
    expect(s.counts.cancelled).toBe(1)
    expect(s.genuine).toEqual({ n: 2, accepted: 1 })
    expect(s.attack).toEqual({ n: 2, accepted: 1 })
    expect(s.unlabelled).toBe(1)
    expect(s.counts.verified).toBe(3)
    expect(s.byReason.find((r) => r.reason === 'OK')?.n).toBe(3)
  })
  it('percentiles use nearest rank and P95 needs enough observations', () => {
    expect(percentile([], 50)).toBeNull()
    expect(percentile([5], 95)).toBe(5)
    expect(percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 50)).toBe(5)
    expect(percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 95)).toBe(10)
    expect(percentile([3, Number.NaN, 1], 50)).toBe(1)
    const few = summarize(Array.from({ length: 19 }, (_, i) => rec({ id: 'x' + i, decisionMs: 1000 + i })))
    expect(few.decisionMs.p95).toBeNull()
    const many = summarize(Array.from({ length: 20 }, (_, i) => rec({ id: 'x' + i, decisionMs: 1000 + i })))
    expect(many.decisionMs.p95).toBe(1018)
  })
  it('filters by scenario, outcome and text', () => {
    const rs = [rec({ id: 'a', label: 'genuine_live' }), rec({ id: 'b', label: 'printed_photo', state: 'RETRY_PENDING', reason: 'STATIC_REPLAY_SUSPECT' }), rec({ id: 'c', label: null })]
    expect(filterRecords(rs, { scenario: 'all', outcome: 'all', text: '' })).toHaveLength(3)
    expect(filterRecords(rs, { scenario: 'printed_photo', outcome: 'all', text: '' }).map((r) => r.id)).toEqual(['b'])
    expect(filterRecords(rs, { scenario: 'unlabelled', outcome: 'all', text: '' }).map((r) => r.id)).toEqual(['c'])
    expect(filterRecords(rs, { scenario: 'all', outcome: 'retry', text: '' }).map((r) => r.id)).toEqual(['b'])
    expect(filterRecords(rs, { scenario: 'all', outcome: 'all', text: 'static' }).map((r) => r.id)).toEqual(['b'])
  })
  it('an abandoned trial is never counted as a decision', () => {
    expect(groupOf({ state: 'CAPTURING', unfinished: true })).toBe('cancelled')
  })
})

describe('expectation is separate from the decision', () => {
  it('compares label expectation with the observed state', () => {
    expect(matchedExpectation('genuine_live', 'VERIFIED')).toBe(true)
    expect(matchedExpectation('genuine_live', 'RETRY_PENDING')).toBe(false)
    expect(matchedExpectation('printed_photo', 'VERIFIED')).toBe(false)
    expect(matchedExpectation('printed_photo', 'REJECTED_ATTACK')).toBe(true)
    expect(matchedExpectation(null, 'VERIFIED')).toBeNull()
    expect(matchedExpectation('genuine_live', 'CANCELLED')).toBeNull()
    expect(SCENARIOS.filter((s) => s.expectVerified).map((s) => s.id)).toEqual(['genuine_live'])
  })
})

describe('export', () => {
  it('guards spreadsheet formulas and quotes properly', () => {
    expect(csvCell('=HYPERLINK("x")')).toBe(`"'=HYPERLINK(""x"")"`)
    expect(csvCell('+1')).toBe("'+1")
    expect(csvCell('a,b')).toBe('"a,b"')
    expect(csvCell(-3)).toBe('-3')
    expect(csvCell(Number.NaN)).toBe('')
    expect(csvCell(null)).toBe('')
  })
  it('writes one header and one row per trial, with no frames, events or embeddings by default', () => {
    const csv = toCsv([rec({ id: 'a' }), rec({ id: 'b' })]).trim().split('\n')
    expect(csv).toHaveLength(3)
    expect(csv[0]).toContain('reason_code')
    expect(csv[0]).not.toMatch(/(^|,)events?(,|$)|frame_data|embedding|image/)
    const j = JSON.parse(toJson([rec({ id: 'a' })]))
    expect(j.count).toBe(1)
    expect(j.trials[0].events).toBeUndefined()
    expect(JSON.parse(toJson([rec({ id: 'a' })], { includeEvents: true })).trials[0].events.length).toBeGreaterThan(0)
    expect(JSON.stringify(j.trials)).not.toMatch(/embedding/i)
  })
})

describe('trial storage', () => {
  it('keeps real and demo records apart and never mixes them', () => {
    upsertRecord('demo', rec({ id: 'd1' }))
    upsertRecord('real', { ...rec({ id: 'r1' }), source: 'real' })
    expect(loadRecords('demo').map((r) => r.id)).toEqual(['d1'])
    expect(loadRecords('real').map((r) => r.id)).toEqual(['r1'])
    clearRecords('demo')
    expect(loadRecords('demo')).toEqual([])
    expect(loadRecords('real')).toHaveLength(1)
  })
  it('upserts by id and merges history without duplicates', () => {
    upsertRecord('demo', rec({ id: 'd1', state: 'RETRY_PENDING' }))
    upsertRecord('demo', rec({ id: 'd1', state: 'VERIFIED' }))
    expect(loadRecords('demo')).toHaveLength(1)
    expect(mergeRecords('demo', [rec({ id: 'd1' }), rec({ id: 'd2', startedAtMs: 5 })])).toHaveLength(2)
  })
  it('survives corrupt storage', () => {
    localStorage.setItem('liveness-studio.trials.v1.real', '{not json')
    expect(loadRecords('real')).toEqual([])
    localStorage.setItem('liveness-studio.trials.v1.real', '{"a":1}')
    expect(loadRecords('real')).toEqual([])
  })
  it('records only finished or abandoned trials', () => {
    expect(recordFromSnapshot(demoSnapshot('verified', 500, 1, 0, null), 'demo')).toBeNull()
    expect(recordFromSnapshot(demoSnapshot('verified', 9999, 1, 0, null), 'demo')).not.toBeNull()
    expect(recordFromSnapshot({ ...demoSnapshot('verified', 0, 0, 0, null), trial: { ...demoSnapshot('verified', 0, 0, 0, null).trial, number: 0 } }, 'demo')).toBeNull()
  })
})

describe('copy', () => {
  it('explains known codes and is honest about unknown ones', () => {
    expect(explainReason('STATIC_REPLAY_SUSPECT').next).toMatch(/smile or speak/i)
    const u = explainReason('SOMETHING_NEW')
    expect(u.title).toBe('Unrecognised reason code')
    expect(u.why).toContain('SOMETHING_NEW')
    expect(explainReason(null).title).toBe('No result yet')
  })
  it('gives frame guidance from engine signals only', () => {
    expect(frameGuidance(-1, null, false).tone).toBe('idle')
    expect(frameGuidance(0, 'NO_FACE', false).text).toMatch(/no face/i)
    expect(frameGuidance(2, 'MULTIPLE_FACES', false).text).toMatch(/more than one/i)
    expect(frameGuidance(1, 'FACE_TOO_SMALL', false).text).toMatch(/closer/i)
    expect(frameGuidance(1, 'TOO_DARK', false).text).toMatch(/dark/i)
    expect(frameGuidance(1, 'TOO_BRIGHT', false).text).toMatch(/glare|bright/i)
    expect(frameGuidance(1, 'BLUR', false).text).toMatch(/blur/i)
    expect(frameGuidance(1, null, true).tone).toBe('ok')
  })
})

describe('status ladder only marks phases the engine reached', () => {
  it('a still-image retry never claims signed capture was reached', async () => {
    const { ladderReached } = await import('./outcome')
    const r = ladderReached(demoSnapshot('static_image', 9000, 1, 0, null))
    expect(r).toEqual([true, true, true, false, false])
    expect(ladderReached(demoSnapshot('no_face', 9000, 1, 0, null))).toEqual([true, true, false, false, false])
    expect(ladderReached(demoSnapshot('verified', 9000, 1, 0, null))).toEqual([true, true, true, true, true])
    expect(ladderReached(null)).toEqual([false, false, false, false, false])
  })
  it('a cancelled simulated trial is never a decision', async () => {
    const { cancelledCopy } = await import('./demo')
    const c = cancelledCopy(demoSnapshot('verified', 1000, 1, 100, 'genuine_live'), 1100)
    expect(c.decision.state).toBe('CANCELLED')
    expect(outcomeKind(c)).toBe('cancelled')
    expect(c.trial.unfinished).toBe(true)
    expect(c.stages[7]!.state).toBe('skipped')
    expect(c.stages.every((x) => x.state !== 'active')).toBe(true)
  })
})
