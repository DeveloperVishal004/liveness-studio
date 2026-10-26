import type { Mode, Snapshot, TrialRecord } from '../types'

const MAX_RECORDS = 500
const key = (source: Mode) => `liveness-studio.trials.v1.${source}`

/** A finished or abandoned trial as a compact record. No frames, no embeddings, nothing personal. */
export function recordFromSnapshot(s: Snapshot, source: Mode): TrialRecord | null {
  if (s.trial.number === 0 || !s.trial.id || s.trial.active) return null
  if (!s.decision.final && !s.trial.unfinished) return null
  const spans = s.timing.frameSpansMs
  return {
    id: s.trial.id,
    source,
    label: s.trial.label,
    startedAtMs: s.trial.startedAtMs ?? 0,
    finishedAtMs: s.trial.finishedAtMs,
    state: s.decision.state,
    reason: s.decision.reason,
    bindingReason: s.decision.bindingReason,
    verdict: s.decision.verdict,
    unfinished: s.trial.unfinished,
    decisionMs: s.timing.decisionMs,
    streamPad: { ...s.pad.stream },
    capturePad: s.pad.capture.score,
    frameProcessingMs: typeof spans['total'] === 'number' ? spans['total'] : s.frame.processingMs,
    frameSpansMs: { ...spans },
    readyMs: s.timing.readyMs,
    captureRoundTripMs: s.timing.captureRoundTripMs,
    bindMs: s.timing.bindMs,
    attackEvents: s.counters.attackEvents,
    channelEvents: s.counters.channelEvents,
    ineligibleCounts: { ...s.ineligibleCounts },
    integrity: s.integrity.map((c) => ({ id: c.id, state: c.state })),
    stages: s.stages.map((x) => ({ id: x.id, state: x.state, reasonCode: x.reasonCode, durationMs: x.durationMs })),
    events: s.events.map((e) => ({ ...e })),
  }
}

export function loadRecords(source: Mode): TrialRecord[] {
  try {
    const raw = localStorage.getItem(key(source))
    if (!raw) return []
    const v: unknown = JSON.parse(raw)
    if (!Array.isArray(v)) return []
    return v.filter((r): r is TrialRecord => typeof r === 'object' && r !== null && typeof (r as TrialRecord).id === 'string' && (r as TrialRecord).source === source)
  } catch {
    return []
  }
}

function save(source: Mode, records: TrialRecord[]): void {
  try {
    localStorage.setItem(key(source), JSON.stringify(records.slice(-MAX_RECORDS)))
  } catch {
    /* storage unavailable or full: the live session still works, only persistence is skipped */
  }
}

/** Insert or replace by id; returns the new list (oldest first). */
export function upsertRecord(source: Mode, rec: TrialRecord): TrialRecord[] {
  const list = loadRecords(source)
  const i = list.findIndex((r) => r.id === rec.id)
  if (i >= 0) list[i] = rec
  else list.push(rec)
  list.sort((a, b) => a.startedAtMs - b.startedAtMs)
  save(source, list)
  return list.slice(-MAX_RECORDS)
}

export function mergeRecords(source: Mode, recs: TrialRecord[]): TrialRecord[] {
  let list = loadRecords(source)
  for (const rec of recs) {
    const i = list.findIndex((r) => r.id === rec.id)
    if (i >= 0) list[i] = rec
    else list.push(rec)
  }
  list.sort((a, b) => a.startedAtMs - b.startedAtMs)
  list = list.slice(-MAX_RECORDS)
  save(source, list)
  return list
}

export function clearRecords(source: Mode): void {
  try {
    localStorage.removeItem(key(source))
  } catch {
    /* nothing to clear */
  }
}
