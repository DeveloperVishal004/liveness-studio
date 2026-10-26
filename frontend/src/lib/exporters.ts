import { groupOf } from './analytics'
import type { TrialRecord } from '../types'

const COLUMNS = [
  'trial_id', 'source', 'scenario_label', 'started_at', 'time_to_decision_ms', 'outcome', 'engine_state', 'reason_code',
  'binding_reason', 'stream_pad_median', 'stream_pad_min', 'stream_pad_max', 'capture_pad', 'frames', 'usable_frames',
  'frame_processing_ms', 'time_to_ready_ms', 'capture_round_trip_ms', 'verify_ms', 'attack_events', 'channel_events', 'unfinished',
] as const

/** Spreadsheet formula injection guard: a cell starting with = + - @ would be executed by Excel/Sheets. */
export function csvCell(v: unknown): string {
  if (v == null) return ''
  let s = typeof v === 'number' ? (Number.isFinite(v) ? String(v) : '') : String(v)
  if (/^[=+\-@\t\r]/.test(s) && typeof v !== 'number') s = "'" + s
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

function row(r: TrialRecord): unknown[] {
  return [
    r.id, r.source, r.label, r.startedAtMs ? new Date(r.startedAtMs).toISOString() : '', r.decisionMs, groupOf(r), r.state, r.reason,
    r.bindingReason, r.streamPad.median, r.streamPad.min, r.streamPad.max, r.capturePad, r.streamPad.frames, r.streamPad.eligibleFrames,
    r.frameProcessingMs, r.readyMs, r.captureRoundTripMs, r.bindMs, r.attackEvents, r.channelEvents, r.unfinished,
  ]
}

export function toCsv(records: TrialRecord[]): string {
  return [COLUMNS.join(','), ...records.map((r) => row(r).map(csvCell).join(','))].join('\n') + '\n'
}

export interface JsonExportOptions {
  /** Event timelines are free text from the engine; off by default. */
  includeEvents?: boolean
}

export function toJson(records: TrialRecord[], opts: JsonExportOptions = {}): string {
  const out = records.map((r) => {
    const { events, ...rest } = r
    return opts.includeEvents ? { ...rest, events } : rest
  })
  return JSON.stringify(
    {
      exportedAt: new Date().toISOString(),
      note: 'Individual trials, not an accuracy measurement. No camera frames, face embeddings or personal data are included.',
      count: out.length,
      trials: out,
    },
    null,
    2,
  )
}

export function download(filename: string, mime: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: mime }))
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
