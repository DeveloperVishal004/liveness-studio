import { Info } from 'lucide-react'
import { StageList } from '../components/Pipeline'
import { Panel, Stat } from '../components/ui'
import { fmtMs } from '../lib/format'
import { sessionPhase } from '../lib/outcome'
import { useEngine } from '../state/engine'

export default function PipelinePage() {
  const { snapshot: s, mode } = useEngine()
  return (
    <div>
      <div className="mb-4">
        <h1 className="text-2xl font-semibold">Pipeline</h1>
        <p className="mt-1 max-w-2xl text-slate">The stages the engine runs, in the order it runs them. A stage shows Passed only when the engine actually got through it.</p>
      </div>
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_320px]">
        <Panel title={s.trial.number > 0 ? `Trial ${s.trial.number}: ${sessionPhase(s)}` : 'No verification has run'} aside={mode === 'demo' ? 'Simulated' : undefined}>
          {s.trial.number === 0 && <p className="mb-2 text-sm text-slate">Start a verification on the Verify screen. Stages fill in as the engine works.</p>}
          <StageList stages={s.stages} />
        </Panel>
        <div className="space-y-5">
          <Panel title="Timings">
            <dl className="grid grid-cols-2 gap-4">
              <Stat label="Time to ready" value={fmtMs(s.timing.readyMs)} hint="passive checks done" />
              <Stat label="Device round trip" value={fmtMs(s.timing.captureRoundTripMs)} />
              <Stat label="Capture verification" value={fmtMs(s.timing.bindMs)} hint="all binder checks" />
              <Stat label="Time to decision" value={fmtMs(s.timing.decisionMs)} />
            </dl>
            {Object.keys(s.timing.frameSpansMs).length > 0 && (
              <div className="mt-4 border-t border-rule pt-3">
                <h3 className="text-sm font-semibold">Per-frame cost</h3>
                <ul className="mt-2 space-y-1 text-sm num">
                  {Object.entries(s.timing.frameSpansMs).map(([k, v]) => (
                    <li key={k} className="flex justify-between"><span className="text-slate">{k.replace('_', ' ')}</span><span>{v.toFixed(1)} ms</span></li>
                  ))}
                </ul>
              </div>
            )}
          </Panel>
          <div className="flex gap-2 rounded-md border border-rule p-3 text-xs text-slate">
            <Info size={14} className="mt-0.5 shrink-0" aria-hidden="true" />
            <p>The capture is requested only after the passive stages pass, so those stages never wait for it. Inside the capture check the engine applies the attack line first, then the subject match, then the accept gate. They are shown as separate stages.</p>
          </div>
        </div>
      </div>
    </div>
  )
}
