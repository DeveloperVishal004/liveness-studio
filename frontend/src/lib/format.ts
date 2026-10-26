export function fmtScore(v: number | null | undefined): string {
  return v == null || !Number.isFinite(v) ? '—' : v.toFixed(2)
}
export function fmtMs(v: number | null | undefined): string {
  if (v == null || !Number.isFinite(v)) return '—'
  return v >= 1000 ? `${(v / 1000).toFixed(1)} s` : `${Math.round(v)} ms`
}
export function fmtPct(n: number, d: number): string {
  return d === 0 ? '—' : `${Math.round((100 * n) / d)}%`
}
export function fmtTime(ms: number | null | undefined): string {
  return ms == null ? '—' : new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}
export function fmtDateTime(ms: number | null | undefined): string {
  return ms == null ? '—' : new Date(ms).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })
}
