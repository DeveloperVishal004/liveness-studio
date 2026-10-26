import { ArrowRight, CircleHelp, Info, Play, RotateCcw, Square } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { CHECK_MEANING, explainReason, STAGE_GLOSSARY } from '../lib/copy'
import { fmtMs, fmtScore } from '../lib/format'
import { ladderIndex, ladderReached, LADDER, outcomeKind, OUTCOME_LABEL, sessionPhase } from '../lib/outcome'
import { useEngine } from '../state/engine'
import type { Check, Snapshot, Stage } from '../types'
import { checkTone, checkWord, CheckGlyph, Code, OUTCOME_TONE, StageGlyph, stageTone, stageWord, Term } from './ui'

function modelLabel(model: string | null) {
  if (!model) return null
  const key = Object.keys(STAGE_GLOSSARY).find((k) => model.startsWith(k))
  return key ? <Term tip={STAGE_GLOSSARY[key]!}>{model}</Term> : model
}

/** The engine's real stages in the engine's real order. Nothing turns green because time passed. */
export function StageList({ stages }: { stages: Stage[] }) {
  return (
    <ol className="divide-y divide-rule" aria-label="Verification pipeline">
      {stages.map((s) => (
        <li key={s.id} className="grid grid-cols-[1.5rem_minmax(0,1fr)] gap-x-3 gap-y-0.5 py-3 sm:grid-cols-[1.5rem_minmax(0,1fr)_auto]">
          <span className={`mt-0.5 grid h-6 w-6 place-items-center rounded-full ${s.state === 'active' ? 'is-active' : ''}`}><StageGlyph state={s.state} /></span>
          <div className="min-w-0">
            <div className="flex flex-wrap items-baseline gap-x-3">
              <h3 className="text-base font-semibold">{s.label}</h3>
              <span className={`text-sm ${stageTone(s.state)}`}>{stageWord(s.state)}</span>
              {s.model && <span className="text-xs text-slate">{modelLabel(s.model)}</span>}
            </div>
            <p className="mt-0.5 text-sm text-slate">{s.detail}</p>
            {s.reasonCode && <p className="mt-1 text-xs text-slate"><Code>{s.reasonCode}</Code> <span className="ml-1">{explainReason(s.reasonCode).title}</span></p>}
          </div>
          <div className="col-start-2 text-xs text-slate sm:col-start-3 sm:text-right num">{s.durationMs != null ? <>{fmtMs(s.durationMs)}<span className="block text-faint">measured</span></> : <span className="text-faint">no timing</span>}</div>
        </li>
      ))}
    </ol>
  )
}

export function IntegrityList({ checks }: { checks: Check[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <caption className="sr-only">Integrity checks on the signed capture</caption>
        <thead className="text-xs text-slate">
          <tr><th className="w-8 py-2 pr-2 font-medium"><span className="sr-only">Result</span></th><th className="py-2 pr-4 font-medium">Check</th><th className="py-2 pr-4 font-medium">Result</th><th className="py-2 font-medium">What it means</th></tr>
        </thead>
        <tbody className="divide-y divide-rule align-top">
          {checks.map((c) => (
            <tr key={c.id}>
              <td className="py-2.5 pr-2"><CheckGlyph state={c.state} /></td>
              <td className="py-2.5 pr-4 font-medium">{c.label}</td>
              <td className={`py-2.5 pr-4 whitespace-nowrap ${checkTone(c.state)}`}>{checkWord(c.state)}</td>
              <td className="py-2.5 text-slate">
                {CHECK_MEANING[c.id]}
                {c.detail && c.state !== 'passed' && <span className="mt-0.5 block text-xs text-paper/80">{c.detail}</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/** The decision, shown only as the engine returned it. */
export function ResultCard({ snapshot }: { snapshot: Snapshot }) {
  const kind = outcomeKind(snapshot)
  const d = snapshot.decision
  if (kind === 'idle') {
    return (
      <div className="rounded-md border border-dashed border-rule-strong p-4 text-slate">
        <p className="font-medium text-paper">No decision yet</p>
        <p className="mt-1 text-sm">The result appears here once the engine finishes a verification. A camera, a face or a high score alone never counts as a result.</p>
      </div>
    )
  }
  if (kind === 'running') {
    return (
      <div className="rounded-md border border-rule p-4" aria-live="polite">
        <p className="font-medium text-signal">{sessionPhase(snapshot)}</p>
        <p className="mt-1 text-sm text-slate">{d.verdict || 'The engine is collecting evidence.'}</p>
      </div>
    )
  }
  const code = kind === 'verified' ? 'OK' : d.reason
  const copy = explainReason(code)
  const border = kind === 'verified' ? 'border-ok/60' : kind === 'retry' || kind === 'cancelled' ? 'border-warn/50' : 'border-bad/60'
  return (
    <div className={`rounded-md border ${border} bg-raised p-4`} role="status" aria-live="polite">
      <div className="flex items-center gap-3">
        <h3 className={`text-xl font-semibold ${OUTCOME_TONE[kind]}`}>{OUTCOME_LABEL[kind]}</h3>
      </div>
      <dl className="mt-3 space-y-2.5 text-sm">
        <div><dt className="text-xs text-slate">Engine decision</dt><dd className="mt-0.5">{d.verdict}</dd></div>
        <div>
          <dt className="text-xs text-slate">Reason</dt>
          <dd className="mt-0.5">
            <span className="font-medium">{copy.title}</span>{' '}
            <Code>{code}</Code>
            {d.bindingReason && d.bindingReason !== 'OK' && <> <Code>{d.bindingReason}</Code></>}
            <p className="mt-1 text-slate">{copy.why}</p>
          </dd>
        </div>
        <div><dt className="text-xs text-slate">What to do next</dt><dd className="mt-0.5 flex items-start gap-2"><ArrowRight size={15} className="mt-1 shrink-0 text-signal" aria-hidden="true" /><span>{copy.next}</span></dd></div>
      </dl>
      <dl className="mt-4 grid grid-cols-3 gap-3 border-t border-rule pt-3 num">
        <div><dt className="text-xs text-slate">Time to decision</dt><dd className="font-semibold">{fmtMs(snapshot.timing.decisionMs)}</dd></div>
        <div><dt className="text-xs text-slate">Stream score</dt><dd className="font-semibold">{fmtScore(snapshot.pad.stream.median)}</dd></div>
        <div><dt className="text-xs text-slate">Capture score</dt><dd className="font-semibold">{fmtScore(snapshot.pad.capture.score)}</dd></div>
      </dl>
      {kind === 'verified' && <p className="mt-3 flex gap-2 text-xs text-slate"><Info size={14} className="mt-0.5 shrink-0" aria-hidden="true" />Verified by the engine for this single attempt, with an uncalibrated model. It is not an accuracy measurement.</p>}
    </div>
  )
}

export function StatusLadder({ snapshot }: { snapshot: Snapshot }) {
  const idx = snapshot.trial.active ? ladderIndex(snapshot) : -2
  const reached = ladderReached(snapshot)
  const kind = outcomeKind(snapshot)
  return (
    <ol className="space-y-1.5" aria-label="Session progress">
      {LADDER.map((label, i) => {
        const on = idx === i
        const done = !on && reached[i] === true
        return (
          <li key={label} className={`flex items-center gap-2.5 text-sm ${on ? 'font-medium text-paper' : done ? 'text-slate' : 'text-faint'}`} aria-current={on ? 'step' : undefined}>
            <span className={`h-2.5 w-2.5 rounded-full border ${on ? 'border-signal bg-signal is-active' : done ? 'border-slate bg-slate' : 'border-faint'}`} aria-hidden="true" />
            {label}
          </li>
        )
      })}
      <li className={`flex items-center gap-2.5 pt-1 text-sm font-medium ${kind === 'idle' || kind === 'running' ? 'text-faint' : OUTCOME_TONE[kind]}`}>
        <span className={`h-2.5 w-2.5 rounded-full ${kind === 'verified' ? 'bg-ok' : kind === 'retry' ? 'bg-warn' : kind === 'rejected' || kind === 'error' ? 'bg-bad' : kind === 'cancelled' ? 'bg-slate' : 'border border-faint'}`} aria-hidden="true" />
        {kind === 'idle' || kind === 'running' ? 'Outcome' : OUTCOME_LABEL[kind]}
      </li>
    </ol>
  )
}

export function RunControls({ label, demoScript, onStarted }: { label: string | null; demoScript?: string; onStarted?: () => void }) {
  const { snapshot, start, cancel, busy, mode, connection } = useEngine()
  // Cancel appears where Start was, so a double-click must not start a trial and cancel it in the same breath.
  const [justStarted, setJustStarted] = useState(false)
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  useEffect(() => () => clearTimeout(timer.current), [])
  const kind = outcomeKind(snapshot)
  const running = snapshot.trial.active
  const real = mode === 'real'
  const ready = !real || (connection === 'connected' && snapshot.camera.streaming)
  const why = !ready ? (connection !== 'connected' ? 'Waiting for the engine.' : 'Waiting for camera frames.') : null
  return (
    <div>
      <div className="flex flex-wrap gap-2">
        {running ? (
          <button className="btn btn-danger" onClick={() => void cancel()} disabled={busy || justStarted}><Square size={15} /> Cancel verification</button>
        ) : (
          <button className="btn btn-primary" onClick={() => {
            setJustStarted(true)
            clearTimeout(timer.current)
            timer.current = setTimeout(() => setJustStarted(false), 900)
            void start(label, demoScript)
            onStarted?.()
          }} disabled={busy || !ready}>
            {kind === 'idle' ? <Play size={15} /> : <RotateCcw size={15} />}
            {kind === 'idle' ? 'Start verification' : 'Run again'}
          </button>
        )}
      </div>
      {why && !running && <p className="mt-2 flex items-center gap-1.5 text-xs text-slate"><CircleHelp size={13} aria-hidden="true" />{why}</p>}
    </div>
  )
}
