import { useState } from 'react'
import { CameraStage } from '../components/Camera'
import { ResultCard, RunControls } from '../components/Pipeline'
import { Code, EmptyState, OutcomePill, Panel, Stat } from '../components/ui'
import { groupOf } from '../lib/analytics'
import { fmtDateTime, fmtMs, fmtScore } from '../lib/format'
import { outcomeKind } from '../lib/outcome'
import { matchedExpectation, SCENARIOS, scenarioOf } from '../lib/scenarios'
import { useEngine } from '../state/engine'

export default function Lab() {
  const { snapshot: s, records, mode } = useEngine()
  const [pick, setPick] = useState(SCENARIOS[0]!.id)
  const sc = SCENARIOS.find((x) => x.id === pick)!
  const kind = outcomeKind(s)
  const finished = kind !== 'idle' && kind !== 'running'
  const scored = scenarioOf(s.trial.label)
  const match = finished ? matchedExpectation(s.trial.label, s.decision.state) : null
  const subject = s.integrity.find((c) => c.id === 'subject')
  const counts = s.integrity.reduce<Record<string, number>>((m, c) => ({ ...m, [c.state]: (m[c.state] ?? 0) + 1 }), {})
  const labelled = records.filter((r) => scenarioOf(r.label)).slice(-8).reverse()

  return (
    <div>
      <div className="mb-4">
        <h1 className="text-2xl font-semibold">Evaluation lab</h1>
        <p className="mt-1 max-w-2xl text-slate">Stage a scenario in front of the camera, run it, and compare what you expected with what the engine decided. The label is your note, not a detection: the engine never sees it.</p>
      </div>
      <div className="grid gap-5 xl:grid-cols-[320px_minmax(0,1fr)]">
        <Panel title="Scenario">
          <fieldset>
            <legend className="sr-only">Scenario to stage</legend>
            <div className="space-y-1.5">
              {SCENARIOS.map((x) => (
                <label key={x.id} className={`block cursor-pointer rounded-sm border px-3 py-2 transition-colors ${pick === x.id ? 'border-signal bg-raised' : 'border-rule hover:border-rule-strong'} ${s.trial.active ? 'pointer-events-none opacity-60' : ''}`}>
                  <input type="radio" name="scenario" className="sr-only" checked={pick === x.id} onChange={() => setPick(x.id)} disabled={s.trial.active} />
                  <span className="block font-medium">{x.title}</span>
                  <span className="block text-xs text-slate">{x.kind === 'genuine' ? 'Genuine' : x.kind === 'attack' ? 'Presentation attack' : 'Capture condition'}</span>
                </label>
              ))}
            </div>
          </fieldset>
          <div className="mt-4 rounded-sm border border-rule bg-abyss p-3 text-sm">
            <p className="font-medium">How to stage it</p>
            <p className="mt-1 text-slate">{sc.howTo}</p>
            <p className="mt-3 font-medium">Expected (your hypothesis)</p>
            <p className="mt-1 text-slate">{sc.expectVerified ? 'The engine verifies this attempt.' : 'The engine does not verify this attempt (a retry or a rejection both count).'}</p>
            {mode === 'demo' && <p className="mt-3 text-xs text-warn">Demo mode: the outcome comes from a fixed script, not from a physical test.</p>}
          </div>
        </Panel>
        <div className="min-w-0 space-y-5">
          <div className="grid gap-5 lg:grid-cols-2">
            <CameraStage compact />
            <Panel title="Run">
              <RunControls label={pick} demoScript={sc.demoScript} />
              <p className="mt-3 text-xs text-slate">Recorded as: <Code>{pick}</Code>. Use one run per physical setup, then change the scenario.</p>
              <div className="mt-4"><ResultCard snapshot={s} /></div>
            </Panel>
          </div>

          <Panel title="Expectation versus the engine" aside={s.trial.number > 0 ? `Trial ${s.trial.number}` : undefined}>
            {!finished ? (
              <p className="text-sm text-slate">Finish a run to compare. The expectation and the engine’s decision are kept apart on purpose.</p>
            ) : (
              <>
                <dl className="grid gap-4 sm:grid-cols-3">
                  <Stat label="Labelled as" value={scored ? scored.title : 'No label'} />
                  <Stat label="Expected" value={scored ? (scored.expectVerified ? 'Verified' : 'Not verified') : '—'} />
                  <Stat label="Engine decided" value={<OutcomePill kind={kind} />} hint={<Code>{s.decision.reason}</Code>} />
                </dl>
                <p className={`mt-3 text-sm font-medium ${match == null ? 'text-slate' : match ? 'text-ok' : 'text-warn'}`}>
                  {match == null ? 'No comparison: the trial was cancelled or has no label.' : match ? 'The decision matched the expectation.' : scored?.expectVerified ? 'Mismatch: the engine did not verify a genuine attempt (a false reject).' : 'Mismatch: the engine verified an attempt that was expected to fail (a false accept).'}
                </p>
                <dl className="mt-4 grid grid-cols-2 gap-4 border-t border-rule pt-4 sm:grid-cols-4 num">
                  <Stat label="Stream score" value={`${fmtScore(s.pad.stream.median)}`} hint={`range ${fmtScore(s.pad.stream.min)}–${fmtScore(s.pad.stream.max)}`} />
                  <Stat label="Capture score" value={fmtScore(s.pad.capture.score)} hint={s.timing.readyMs != null ? undefined : 'no capture taken'} />
                  <Stat label="Subject match" value={subject ? ({ passed: 'Matched', failed: 'Different', not_checked: 'Not checked', unavailable: 'Unavailable', not_applicable: 'n/a' } as const)[subject.state] : '—'} />
                  <Stat label="Integrity checks" value={`${counts['passed'] ?? 0} passed`} hint={`${counts['failed'] ?? 0} failed · ${counts['not_checked'] ?? 0} not checked`} />
                  <Stat label="Frame processing" value={fmtMs(s.timing.frameSpansMs['total'] ?? s.frame.processingMs)} />
                  <Stat label="Time to decision" value={fmtMs(s.timing.decisionMs)} />
                </dl>
              </>
            )}
          </Panel>

          <Panel title="Recent labelled trials" aside={mode === 'demo' ? 'Simulated' : 'Real engine'}>
            {labelled.length === 0 ? (
              <EmptyState title="No labelled trials yet" body="Run a scenario above. Each finished run is saved here and counted in Analytics." />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="text-xs text-slate"><tr><th className="py-2 pr-3 font-medium">When</th><th className="py-2 pr-3 font-medium">Labelled as</th><th className="py-2 pr-3 font-medium">Engine</th><th className="py-2 pr-3 font-medium">Reason</th><th className="py-2 font-medium">Matched</th></tr></thead>
                  <tbody className="divide-y divide-rule">
                    {labelled.map((r) => {
                      const m = matchedExpectation(r.label, r.state)
                      return (
                        <tr key={r.id}>
                          <td className="py-2 pr-3 whitespace-nowrap text-slate num">{fmtDateTime(r.startedAtMs)}</td>
                          <td className="py-2 pr-3">{scenarioOf(r.label)?.title}</td>
                          <td className="py-2 pr-3"><OutcomePill kind={groupOf(r)} /></td>
                          <td className="py-2 pr-3"><Code>{r.state === 'VERIFIED' ? 'OK' : r.reason}</Code></td>
                          <td className={`py-2 ${m == null ? 'text-slate' : m ? 'text-ok' : 'text-warn'}`}>{m == null ? '—' : m ? 'Yes' : 'No'}</td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </div>
      </div>
    </div>
  )
}
