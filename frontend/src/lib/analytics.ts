import { SCENARIOS, scenarioOf } from './scenarios'
import type { TrialRecord } from '../types'

export type OutcomeGroup = 'verified' | 'passive' | 'retry' | 'rejected' | 'error' | 'cancelled' // a subset of OutcomeKind: same names

export function groupOf(r: Pick<TrialRecord, 'state' | 'unfinished'>): OutcomeGroup {
  if (r.state === 'CANCELLED') return 'cancelled'
  if (r.state === 'VERIFIED') return 'verified'
  if (r.state === 'PASSIVE_PASSED') return 'passive'
  if (r.state === 'RETRY_PENDING') return 'retry'
  if (r.state === 'REJECTED_ATTACK' || r.state.startsWith('FAILED')) return 'rejected'
  if (r.unfinished) return 'cancelled' // abandoned mid-way: not a decision
  return 'error'
}

export function percentile(values: number[], p: number): number | null {
  const v = values.filter((x) => Number.isFinite(x)).sort((a, b) => a - b)
  if (v.length === 0) return null
  const rank = Math.ceil((p / 100) * v.length)
  return v[Math.min(v.length - 1, Math.max(0, rank - 1))] ?? null
}

export interface Rate {
  n: number
  accepted: number
}

export interface Row {
  key: string
  label: string
  n: number
  verified: number
  passive: number
  retry: number
  rejected: number
  error: number
}

export interface Summary {
  total: number
  decided: number
  counts: Record<OutcomeGroup, number>
  unlabelled: number
  genuine: Rate
  attack: Rate
  condition: Rate
  retryRate: { n: number; retried: number }
  decisionMs: { n: number; median: number | null; p95: number | null }
  frameMs: { n: number; median: number | null }
  byScenario: Row[]
  byReason: { reason: string; n: number }[]
  /** Fewer than this many decided trials: show every figure as preliminary. */
  preliminary: boolean
}

export const MIN_FOR_P95 = 20
export const PRELIMINARY_BELOW = 30

export function summarize(records: TrialRecord[]): Summary {
  const counts: Record<OutcomeGroup, number> = { verified: 0, passive: 0, retry: 0, rejected: 0, error: 0, cancelled: 0 }
  const genuine: Rate = { n: 0, accepted: 0 }
  const attack: Rate = { n: 0, accepted: 0 }
  const condition: Rate = { n: 0, accepted: 0 }
  const decisionMs: number[] = []
  const frameMs: number[] = []
  const reasons = new Map<string, number>()
  const scen = new Map<string, Row>()
  let unlabelled = 0
  let decided = 0

  for (const r of records) {
    const g = groupOf(r)
    counts[g]++
    if (g === 'cancelled') continue
    decided++
    if (r.decisionMs != null) decisionMs.push(r.decisionMs)
    if (r.frameProcessingMs != null) frameMs.push(r.frameProcessingMs)
    const code = r.state === 'VERIFIED' ? 'OK' : r.reason
    reasons.set(code, (reasons.get(code) ?? 0) + 1)
    const sc = scenarioOf(r.label)
    if (!sc) {
      unlabelled++
      continue
    }
    const rate = sc.kind === 'genuine' ? genuine : sc.kind === 'attack' ? attack : condition
    rate.n++
    if (g === 'verified' || g === 'passive') rate.accepted++
    const row = scen.get(sc.id) ?? { key: sc.id, label: sc.title, n: 0, verified: 0, passive: 0, retry: 0, rejected: 0, error: 0 }
    row.n++
    row[g]++
    scen.set(sc.id, row)
  }

  return {
    total: records.length,
    decided,
    counts,
    unlabelled,
    genuine,
    attack,
    condition,
    retryRate: { n: decided, retried: counts.retry },
    decisionMs: { n: decisionMs.length, median: percentile(decisionMs, 50), p95: decisionMs.length >= MIN_FOR_P95 ? percentile(decisionMs, 95) : null },
    frameMs: { n: frameMs.length, median: percentile(frameMs, 50) },
    byScenario: SCENARIOS.map((s) => scen.get(s.id)).filter((x): x is Row => !!x),
    byReason: [...reasons.entries()].map(([reason, n]) => ({ reason, n })).sort((a, b) => b.n - a.n),
    preliminary: decided < PRELIMINARY_BELOW,
  }
}

export interface Filter {
  scenario: string // 'all' | scenario id | 'unlabelled'
  outcome: string // 'all' | OutcomeGroup
  text: string
}

export function filterRecords(records: TrialRecord[], f: Filter): TrialRecord[] {
  const q = f.text.trim().toLowerCase()
  return records.filter((r) => {
    if (f.scenario === 'unlabelled' ? r.label != null && scenarioOf(r.label) : f.scenario !== 'all' && r.label !== f.scenario) return false
    if (f.outcome !== 'all' && groupOf(r) !== f.outcome) return false
    if (q && !`${r.id} ${r.reason} ${r.bindingReason ?? ''} ${r.label ?? ''} ${r.verdict}`.toLowerCase().includes(q)) return false
    return true
  })
}
