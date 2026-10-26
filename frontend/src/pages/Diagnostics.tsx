import { useMemo, useState } from 'react'
import { Code, Panel, Stat, StageGlyph, stageTone, stageWord } from '../components/ui'
import { explainReason } from '../lib/copy'
import { fmtDateTime, fmtMs, fmtScore } from '../lib/format'
import { useEngine } from '../state/engine'
import type { EventEntry, StageState } from '../types'

interface View {
  id: string
  label: string | null
  attempt: string
  startedAtMs: number | null
  finishedAtMs: number | null
  state: string
  reason: string
  bindingReason: string | null
  detail: string | null
  attackEvents: number
  channelEvents: number
  streamPad: { median: number | null; min: number | null; max: number | null; frames: number; eligibleFrames: number }
  capturePad: number | null
  spans: Record<string, number>
  readyMs: number | null
  rtt: number | null
  bindMs: number | null
  decisionMs: number | null
  stages: { id: string; state: StageState; reasonCode: string | null; durationMs: number | null }[]
  events: EventEntry[]
}

export default function Diagnostics() {
  const { snapshot: s, records, thresholds, info, mode, connection, connectionMessage } = useEngine()
  const [sel, setSel] = useState('current')
  const [q, setQ] = useState('')
  const [type, setType] = useState('all')

  const view: View | null = useMemo(() => {
    if (sel === 'current') {
      if (s.trial.number === 0) return null
      return {
        id: s.trial.id ?? '—', label: s.trial.label, attempt: s.trial.attempt ? `${s.trial.attempt}${s.trial.maxAttempts ? ` of ${s.trial.maxAttempts}` : ''}` : '—',
        startedAtMs: s.trial.startedAtMs, finishedAtMs: s.trial.finishedAtMs, state: s.decision.state, reason: s.decision.reason, bindingReason: s.decision.bindingReason, detail: s.decision.detail,
        attackEvents: s.counters.attackEvents, channelEvents: s.counters.channelEvents, streamPad: s.pad.stream, capturePad: s.pad.capture.score, spans: s.timing.frameSpansMs,
        readyMs: s.timing.readyMs, rtt: s.timing.captureRoundTripMs, bindMs: s.timing.bindMs, decisionMs: s.timing.decisionMs,
        stages: s.stages.map((x) => ({ id: x.id, state: x.state, reasonCode: x.reasonCode, durationMs: x.durationMs })), events: s.events,
      }
    }
    const r = records.find((x) => x.id === sel)
    if (!r) return null
    return {
      id: r.id, label: r.label, attempt: '—', startedAtMs: r.startedAtMs, finishedAtMs: r.finishedAtMs, state: r.state, reason: r.reason, bindingReason: r.bindingReason, detail: null,
      attackEvents: r.attackEvents, channelEvents: r.channelEvents, streamPad: r.streamPad, capturePad: r.capturePad, spans: r.frameSpansMs, readyMs: r.readyMs, rtt: r.captureRoundTripMs,
      bindMs: r.bindMs, decisionMs: r.decisionMs, stages: r.stages, events: r.events,
    }
  }, [sel, s, records])

  const events = useMemo(() => {
    if (!view) return []
    const needle = q.trim().toLowerCase()
    return view.events.filter((e) => (type === 'all' || e.type === type) && (!needle || `${e.type} ${e.text}`.toLowerCase().includes(needle)))
  }, [view, q, type])
  const types = useMemo(() => ['all', ...new Set(view?.events.map((e) => e.type) ?? [])], [view])

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">Diagnostics</h1>
          <p className="mt-1 max-w-2xl text-slate">For developers and evaluators: one trial in detail. Raw camera frames and face embeddings are never kept or shown.</p>
        </div>
        <label className="text-sm text-slate">Trial <select className="field ml-1 min-w-52" value={sel} onChange={(e) => setSel(e.target.value)}>
          <option value="current">Latest in this session</option>
          {records.slice().reverse().map((r) => <option key={r.id} value={r.id}>{fmtDateTime(r.startedAtMs)} · {r.state === 'VERIFIED' ? 'OK' : r.reason}</option>)}
        </select></label>
      </div>

      {connection !== 'connected' && mode === 'real' && (
        <p role="alert" className="mb-4 rounded-md border border-warn/40 bg-warn/10 px-4 py-2 text-sm">Engine connection: <Code>{connection}</Code> {connectionMessage}</p>
      )}

      {!view ? (
        <Panel><p className="text-sm text-slate">No trial to inspect yet. Run a verification, then come back.</p></Panel>
      ) : (
        <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_380px]">
          <div className="min-w-0 space-y-5">
            <Panel title="Session">
              <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                <Stat label="Trial id" value={<Code>{view.id}</Code>} />
                <Stat label="Attempt" value={view.attempt} />
                <Stat label="Label" value={view.label ?? 'none'} />
                <Stat label="Started" value={fmtDateTime(view.startedAtMs)} />
                <Stat label="Engine state" value={<Code>{view.state}</Code>} />
                <Stat label="Reason" value={<Code>{view.reason || '—'}</Code>} hint={explainReason(view.reason).title} />
                <Stat label="Binding reason" value={view.bindingReason ? <Code>{view.bindingReason}</Code> : '—'} />
                <Stat label="Suspected attacks · channel events" value={`${view.attackEvents} · ${view.channelEvents}`} />
              </dl>
              {view.detail && <p className="mt-4 rounded-sm border border-rule bg-abyss p-2 text-sm"><span className="text-slate">Engine message: </span><Code>{view.detail}</Code></p>}
            </Panel>
            <Panel title="Scores and timing">
              <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4 num">
                <Stat label="Stream score median" value={fmtScore(view.streamPad.median)} hint={`min ${fmtScore(view.streamPad.min)} · max ${fmtScore(view.streamPad.max)}`} />
                <Stat label="Capture score" value={fmtScore(view.capturePad)} />
                <Stat label="Usable frames" value={`${view.streamPad.eligibleFrames} / ${view.streamPad.frames}`} />
                <Stat label="Time to decision" value={fmtMs(view.decisionMs)} />
                <Stat label="Time to ready" value={fmtMs(view.readyMs)} />
                <Stat label="Device round trip" value={fmtMs(view.rtt)} />
                <Stat label="Capture verification" value={fmtMs(view.bindMs)} />
                <Stat label="Per-frame total" value={fmtMs(view.spans['total'])} />
              </dl>
              {Object.keys(view.spans).length > 0 && (
                <p className="mt-3 text-xs text-slate num">Per-frame stages (mean): {Object.entries(view.spans).filter(([k]) => k !== 'total').map(([k, v]) => `${k.replace('_', ' ')} ${v.toFixed(1)} ms`).join(' · ')}</p>
              )}
            </Panel>
            <Panel title="Events" aside={`${events.length} of ${view.events.length}`}>
              <div className="mb-3 flex flex-wrap gap-2">
                <input className="field w-60" type="search" placeholder="Search events" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search events" />
                <select className="field" value={type} onChange={(e) => setType(e.target.value)} aria-label="Event type">{types.map((t) => <option key={t} value={t}>{t === 'all' ? 'All types' : t}</option>)}</select>
              </div>
              {events.length === 0 ? <p className="py-4 text-center text-sm text-slate">No events match.</p> : (
                <div className="max-h-96 overflow-auto">
                  <table className="w-full text-left text-sm num">
                    <thead className="sticky top-0 bg-deck text-xs text-slate"><tr><th className="py-1.5 pr-3 font-medium">After start</th><th className="py-1.5 pr-3 font-medium">Type</th><th className="py-1.5 font-medium">Event</th></tr></thead>
                    <tbody className="divide-y divide-rule">{events.map((e, i) => <tr key={i}><td className="py-1.5 pr-3 whitespace-nowrap text-slate">{fmtMs(e.tMs)}</td><td className="py-1.5 pr-3"><Code>{e.type}</Code></td><td className="py-1.5 font-sans">{e.text}</td></tr>)}</tbody>
                  </table>
                </div>
              )}
            </Panel>
          </div>
          <div className="min-w-0 space-y-5">
            <Panel title="Stage outcomes">
              <ul className="divide-y divide-rule text-sm">
                {view.stages.map((x) => (
                  <li key={x.id} className="flex items-center gap-2 py-2">
                    <StageGlyph state={x.state} size={16} />
                    <span className="min-w-0 flex-1"><Code>{x.id}</Code></span>
                    <span className={`text-xs ${stageTone(x.state)}`}>{stageWord(x.state)}</span>
                    <span className="w-16 text-right text-xs text-slate num">{x.durationMs != null ? fmtMs(x.durationMs) : ''}</span>
                  </li>
                ))}
              </ul>
            </Panel>
            <Panel title="Policy in force" aside={info ? 'from the engine' : 'defaults'}>
              <dl className="space-y-1.5 text-sm num">
                {([['Stream accept at', thresholds.streamAccept], ['Stream attack below', thresholds.streamAttack], ['Capture accept at', thresholds.captureAccept], ['Capture attack below', thresholds.captureAttack], ['Subject match at least', thresholds.subjectMinCosine], ['Motion trigger', thresholds.motionTrigger], ['Min face height (px)', thresholds.minFaceHeightPx], ['Min stream face samples', thresholds.minStreamEmbeddings], ['Attack frames to reject', thresholds.attackMinFrames]] as const).map(([k, v]) => (
                  <div key={k} className="flex justify-between"><dt className="text-slate">{k}</dt><dd>{v}</dd></div>
                ))}
              </dl>
              <p className="mt-3 text-xs text-faint">All values are provisional and uncalibrated. They are read from the engine; this page cannot change them.</p>
            </Panel>
            {info && (
              <Panel title="Engine">
                <dl className="space-y-2 text-sm"><div><dt className="text-xs text-slate">Device</dt><dd>{info.device}</dd></div><div><dt className="text-xs text-slate">Model</dt><dd>{info.pad}</dd></div><div><dt className="text-xs text-slate">Camera</dt><dd>{info.camera}</dd></div></dl>
              </Panel>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
