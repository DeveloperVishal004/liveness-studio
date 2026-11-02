import { Download, Trash2 } from 'lucide-react'
import { useMemo, useState } from 'react'
import { ConfirmDialog, Code, EmptyState, OutcomePill, Panel, Stat, Term } from '../components/ui'
import { filterRecords, groupOf, summarize, MIN_FOR_P95, PRELIMINARY_BELOW, type Filter, type Row } from '../lib/analytics'
import { download, toCsv, toJson } from '../lib/exporters'
import { fmtDateTime, fmtMs, fmtPct, fmtScore } from '../lib/format'
import { navigate } from '../router'
import { SCENARIOS, scenarioOf } from '../lib/scenarios'
import { useEngine } from '../state/engine'

function OutcomeBar({ counts }: { counts: { verified: number; passive: number; retry: number; rejected: number; error: number } }) {
  const total = counts.verified + counts.passive + counts.retry + counts.rejected + counts.error
  if (total === 0) return null
  const seg = [
    { k: 'Verified', n: counts.verified, c: 'bg-ok' },
    { k: 'Passive checks passed', n: counts.passive, c: 'bg-signal' },
    { k: 'Retry', n: counts.retry, c: 'bg-warn' },
    { k: 'Rejected', n: counts.rejected, c: 'bg-bad' },
    { k: 'Technical error', n: counts.error, c: 'bg-slate' },
  ]
  return (
    <div>
      <div className="flex h-3 overflow-hidden rounded-sm bg-abyss" role="img" aria-label={seg.map((x) => `${x.k} ${x.n}`).join(', ')}>
        {seg.map((x) => x.n > 0 && <div key={x.k} className={x.c} style={{ width: `${(100 * x.n) / total}%` }} title={`${x.k}: ${x.n}`} />)}
      </div>
      <ul className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-sm">
        {seg.map((x) => (
          <li key={x.k} className="flex items-center gap-2"><span className={`h-2.5 w-2.5 rounded-sm ${x.c}`} aria-hidden="true" /><span className="text-slate">{x.k}</span><span className="num font-medium">{x.n}</span></li>
        ))}
      </ul>
    </div>
  )
}

function ScenarioTable({ rows }: { rows: Row[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="text-xs text-slate"><tr><th className="py-2 pr-3 font-medium">Scenario (your label)</th><th className="py-2 pr-3 text-right font-medium">Runs</th><th className="py-2 pr-3 text-right font-medium">Verified</th><th className="py-2 pr-3 text-right font-medium">Retry</th><th className="py-2 pr-3 text-right font-medium">Rejected</th><th className="py-2 text-right font-medium">Error</th></tr></thead>
        <tbody className="divide-y divide-rule num">
          {rows.map((r) => (
            <tr key={r.key}><td className="py-2 pr-3 font-sans">{r.label}</td><td className="py-2 pr-3 text-right">{r.n}</td><td className="py-2 pr-3 text-right text-ok">{r.verified}</td><td className="py-2 pr-3 text-right text-warn">{r.retry}</td><td className="py-2 pr-3 text-right text-bad">{r.rejected}</td><td className="py-2 text-right text-slate">{r.error}</td></tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

const MODE_NOUN = { real: 'real', browser: 'in-browser', demo: 'simulated' } as const
const MODE_PHRASE = { real: 'on the real engine', browser: 'in this browser', demo: 'in demo mode' } as const
const MODE_LONG = { real: 'from the real engine', browser: 'from the models run in this browser (never mixed with the other modes)', demo: 'in demo mode (simulated, never mixed with real trials)' } as const

export default function Analytics() {
  const { records, mode, clearAllRecords } = useEngine()
  const [filter, setFilter] = useState<Filter>({ scenario: 'all', outcome: 'all', text: '' })
  const [confirmClear, setConfirmClear] = useState(false)
  const [includeEvents, setIncludeEvents] = useState(false)
  const sum = useMemo(() => summarize(records), [records])
  const shown = useMemo(() => filterRecords(records, filter).slice().reverse(), [records, filter])
  const maxReason = Math.max(1, ...sum.byReason.map((r) => r.n))
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')

  if (records.length === 0) {
    return (
      <div>
        <h1 className="text-2xl font-semibold">Analytics</h1>
        <p className="mt-1 mb-5 max-w-2xl text-slate">Results from the trials you run, {MODE_PHRASE[mode]}.</p>
        <EmptyState title="No data yet" body={`No ${MODE_NOUN[mode]} trials have been recorded. Run a few on the Verify screen, or stage labelled scenarios in the Evaluation lab, and they appear here.`}
          action={<div className="flex gap-2"><button className="btn btn-primary" onClick={() => navigate('/')}>Go to Verify</button><button className="btn" onClick={() => navigate('/lab')}>Open the lab</button></div>} />
      </div>
    )
  }

  const g = sum.genuine
  const a = sum.attack
  return (
    <div>
      <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">Analytics</h1>
          <p className="mt-1 max-w-2xl text-slate">Results from the trials recorded in this browser, {MODE_LONG[mode]}.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <label className="flex items-center gap-2 text-sm text-slate"><input type="checkbox" checked={includeEvents} onChange={(e) => setIncludeEvents(e.target.checked)} /> Include event timelines in JSON</label>
          <button className="btn" onClick={() => download(`liveness-${mode}-trials-${stamp}.csv`, 'text/csv', toCsv(shown.slice().reverse()))}><Download size={15} /> CSV</button>
          <button className="btn" onClick={() => download(`liveness-${mode}-trials-${stamp}.json`, 'application/json', toJson(shown.slice().reverse(), { includeEvents }))}><Download size={15} /> JSON</button>
          <button className="btn btn-quiet btn-danger" onClick={() => setConfirmClear(true)}><Trash2 size={15} /> Clear</button>
        </div>
      </div>

      {(sum.preliminary || mode === 'demo') && (
        <div role="note" className="mb-5 rounded-md border border-warn/40 bg-warn/10 px-4 py-2.5 text-sm">
          {mode === 'demo' ? <strong className="font-semibold text-warn">Simulated data. </strong> : <strong className="font-semibold text-warn">Preliminary. </strong>}
          {mode === 'demo' ? 'These are scripted outcomes, not measurements. ' : ''}
          {sum.decided < PRELIMINARY_BELOW ? `Only ${sum.decided} decided trial${sum.decided === 1 ? '' : 's'}: with fewer than ${PRELIMINARY_BELOW}, every rate here is an anecdote, not an accuracy figure. ` : ''}
          Labels are what you staged; they are not confirmed detector results.
        </div>
      )}

      <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <Panel title="Outcomes" aside={`${sum.total} attempt${sum.total === 1 ? '' : 's'} · ${sum.counts.cancelled} cancelled`}>
          <OutcomeBar counts={sum.counts} />
          <dl className="mt-5 grid grid-cols-2 gap-4 sm:grid-cols-4">
            <Stat label="Decided" value={sum.decided} hint="cancelled excluded" />
            <Stat label="Retry rate" value={fmtPct(sum.retryRate.retried, sum.retryRate.n)} hint={`${sum.retryRate.retried} of ${sum.retryRate.n}`} />
            <Stat label="Median time to decision" value={fmtMs(sum.decisionMs.median)} hint={`n=${sum.decisionMs.n}`} />
            <Stat label="P95 time to decision" value={sum.decisionMs.p95 == null ? '—' : fmtMs(sum.decisionMs.p95)} hint={sum.decisionMs.p95 == null ? `needs ${MIN_FOR_P95}+ trials` : `n=${sum.decisionMs.n}`} />
          </dl>
        </Panel>
        <Panel title="Acceptance by what you staged" aside="labelled trials only">
          <dl className="grid grid-cols-2 gap-4 sm:grid-cols-3">
            <Stat label="Genuine accepted" value={fmtPct(g.accepted, g.n)} hint={`${g.accepted} of ${g.n} · rejects and retries are false rejects${mode === 'browser' ? ' · accepted = passive checks passed' : ''}`} />
            <Stat label="Attacks accepted" value={fmtPct(a.accepted, a.n)} hint={`${a.accepted} of ${a.n} · photo, replay, subject change`} />
            <Stat label="Condition trials accepted" value={fmtPct(sum.condition.accepted, sum.condition.n)} hint={`${sum.condition.accepted} of ${sum.condition.n} · light, blur, no face, multiple`} />
          </dl>
          <p className="mt-3 text-xs text-slate">{sum.unlabelled} trial{sum.unlabelled === 1 ? ' has' : 's have'} no label and {sum.unlabelled === 1 ? 'is' : 'are'} excluded from these rates. Median frame processing: {fmtMs(sum.frameMs.median)} (<Term tip="Mean per-frame cost of detection, quality, scoring and embedding, averaged per trial.">per-trial mean</Term>).</p>
        </Panel>

        <Panel title="By scenario">
          {sum.byScenario.length === 0 ? <p className="text-sm text-slate">No labelled trials yet. Choose a scenario in the Evaluation lab.</p> : <ScenarioTable rows={sum.byScenario} />}
        </Panel>
        <Panel title="By reason code">
          <ul className="space-y-2">
            {sum.byReason.map((r) => (
              <li key={r.reason} className="grid grid-cols-[minmax(0,13rem)_1fr_2rem] items-center gap-3 text-sm">
                <Code>{r.reason}</Code>
                <div className="h-2 rounded-sm bg-abyss"><div className={`h-2 rounded-sm ${r.reason === 'OK' ? 'bg-ok' : 'bg-signal-dim'}`} style={{ width: `${(100 * r.n) / maxReason}%` }} /></div>
                <span className="num text-right">{r.n}</span>
              </li>
            ))}
          </ul>
        </Panel>
      </div>

      <Panel className="mt-5" title="Trials" aside={`${shown.length} shown of ${records.length}`}>
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <label className="text-sm text-slate">Scenario <select className="field ml-1" value={filter.scenario} onChange={(e) => setFilter({ ...filter, scenario: e.target.value })}>
            <option value="all">All</option>{SCENARIOS.map((s) => <option key={s.id} value={s.id}>{s.title}</option>)}<option value="unlabelled">Unlabelled</option>
          </select></label>
          <label className="text-sm text-slate">Outcome <select className="field ml-1" value={filter.outcome} onChange={(e) => setFilter({ ...filter, outcome: e.target.value })}>
            <option value="all">All</option><option value="verified">Verified</option><option value="retry">Retry</option><option value="rejected">Rejected</option><option value="error">Technical error</option><option value="cancelled">Cancelled</option>
          </select></label>
          <label className="flex items-center gap-2 text-sm text-slate">Search <input className="field w-52" type="search" placeholder="reason, id or label" value={filter.text} onChange={(e) => setFilter({ ...filter, text: e.target.value })} /></label>
          {(filter.scenario !== 'all' || filter.outcome !== 'all' || filter.text) && <button className="btn btn-quiet" onClick={() => setFilter({ scenario: 'all', outcome: 'all', text: '' })}>Reset filters</button>}
        </div>
        {shown.length === 0 ? <p className="py-6 text-center text-sm text-slate">No trials match these filters.</p> : (
          <div className="max-h-[28rem] overflow-auto">
            <table className="w-full text-left text-sm">
              <thead className="sticky top-0 bg-deck text-xs text-slate"><tr><th className="py-2 pr-3 font-medium">When</th><th className="py-2 pr-3 font-medium">Label</th><th className="py-2 pr-3 font-medium">Outcome</th><th className="py-2 pr-3 font-medium">Reason</th><th className="py-2 pr-3 text-right font-medium">Stream</th><th className="py-2 pr-3 text-right font-medium">Capture</th><th className="py-2 text-right font-medium">Time</th></tr></thead>
              <tbody className="divide-y divide-rule num">
                {shown.map((r) => (
                  <tr key={r.id}>
                    <td className="py-2 pr-3 whitespace-nowrap text-slate">{fmtDateTime(r.startedAtMs)}</td>
                    <td className="py-2 pr-3 font-sans">{scenarioOf(r.label)?.title ?? <span className="text-faint">none</span>}</td>
                    <td className="py-2 pr-3 font-sans"><OutcomePill kind={groupOf(r)} /></td>
                    <td className="py-2 pr-3"><Code>{r.state === 'VERIFIED' ? 'OK' : r.reason}</Code></td>
                    <td className="py-2 pr-3 text-right">{fmtScore(r.streamPad.median)}</td>
                    <td className="py-2 pr-3 text-right">{fmtScore(r.capturePad)}</td>
                    <td className="py-2 text-right">{fmtMs(r.decisionMs)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="mt-3 text-xs text-faint">Exports contain the fields above only: no camera frames, face embeddings or personal data. The CSV and JSON follow the current filters.</p>
      </Panel>
      <ConfirmDialog open={confirmClear} title="Clear recorded trials?" body={`This removes all ${records.length} ${MODE_NOUN[mode]} trials stored in this browser. It cannot be undone. Export first if you need them.`} confirmLabel="Clear trials" onCancel={() => setConfirmClear(false)} onConfirm={() => { clearAllRecords(); setConfirmClear(false) }} />
    </div>
  )
}
