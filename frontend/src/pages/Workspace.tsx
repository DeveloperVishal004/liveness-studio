import { X } from 'lucide-react'
import { useState } from 'react'
import { CameraStage, PadTrace } from '../components/Camera'
import { ResultCard, RunControls, StatusLadder } from '../components/Pipeline'
import { Panel, Stat } from '../components/ui'
import { DEMO_SCRIPTS } from '../lib/demo'
import { fmtMs, fmtScore } from '../lib/format'
import { sessionPhase } from '../lib/outcome'
import { useEngine } from '../state/engine'

const INTRO_KEY = 'liveness-studio.intro.v1'

function FirstRun() {
  const [open, setOpen] = useState(() => {
    try {
      return localStorage.getItem(INTRO_KEY) !== 'seen'
    } catch {
      return true
    }
  })
  if (!open) return null
  const close = () => {
    try {
      localStorage.setItem(INTRO_KEY, 'seen')
    } catch {
      /* shown again next time */
    }
    setOpen(false)
  }
  return (
    <section aria-label="How this works" className="relative mb-5 rounded-md border border-signal-dim bg-deck p-4 pr-12">
      <h2 className="text-base font-semibold">Before you start</h2>
      <ul className="mt-2 grid gap-x-8 gap-y-1.5 text-sm text-slate md:grid-cols-3">
        <li>Look at the camera and press <strong className="font-medium text-paper">Start verification</strong>. The engine decides; this screen only shows what it reports.</li>
        <li>Smile or speak naturally for a few seconds. Blinking alone is often too small for the camera to register as movement.</li>
        <li>A pass is one trial with an uncalibrated model. It says nothing about accuracy against real attacks.</li>
      </ul>
      <button className="btn btn-quiet absolute right-2 top-2 !min-h-8 !px-2" onClick={close} aria-label="Dismiss introduction"><X size={16} /></button>
    </section>
  )
}

export default function Workspace() {
  const { mode, snapshot, padHistory, thresholds, demoScript, setDemoScript } = useEngine()
  const s = snapshot
  return (
    <div>
      <div className="mb-4">
        <h1 className="text-2xl font-semibold">Verify</h1>
        <p className="mt-1 max-w-2xl text-slate">Run one verification at a time and see exactly what the engine does with it.</p>
      </div>
      <FirstRun />
      {/* DOM order is camera, controls and result, then the chart, so on a narrow screen Start is right under the camera. */}
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_390px]">
        <div className="min-w-0 xl:col-start-1 xl:row-start-1">
          <CameraStage />
        </div>
        <div className="min-w-0 space-y-5 xl:col-start-2 xl:row-span-2 xl:row-start-1">
          <Panel title="Session">
            <div className="flex items-baseline justify-between gap-3">
              <p className="text-lg font-semibold" aria-live="polite">{sessionPhase(s)}</p>
              {s.trial.number > 0 && <p className="text-xs text-slate num">Trial {s.trial.number}{s.trial.attempt ? ` · attempt ${s.trial.attempt}${s.trial.maxAttempts ? ` of ${s.trial.maxAttempts}` : ''}` : ''}</p>}
            </div>
            <div className="mt-3"><StatusLadder snapshot={s} /></div>
            {mode === 'demo' && (
              <label className="mt-4 block text-sm">
                <span className="text-slate">Scripted outcome for the next run</span>
                <select className="field mt-1 w-full" value={demoScript} onChange={(e) => setDemoScript(e.target.value)} disabled={s.trial.active}>
                  {DEMO_SCRIPTS.map((d) => <option key={d.id} value={d.id}>{d.title}</option>)}
                </select>
                <span className="mt-1 block text-xs text-faint">{DEMO_SCRIPTS.find((d) => d.id === demoScript)?.summary}</span>
              </label>
            )}
            <div className="mt-4 border-t border-rule pt-4"><RunControls label={null} /></div>
          </Panel>
          <Panel title="Result"><ResultCard snapshot={s} /></Panel>
          {s.trial.number > 0 && (
            <Panel title="This trial">
              <dl className="grid grid-cols-2 gap-4">
                <Stat label="Usable frames" value={`${s.pad.stream.eligibleFrames} of ${s.pad.stream.frames}`} />
                <Stat label="Frame processing" value={fmtMs(s.timing.frameSpansMs['total'] ?? s.frame.processingMs)} hint="mean per frame" />
                <Stat label="Stream score range" value={s.pad.stream.min != null ? `${fmtScore(s.pad.stream.min)} – ${fmtScore(s.pad.stream.max)}` : '—'} />
                <Stat label="Suspected attacks" value={s.counters.attackEvents} hint={`device-channel events: ${s.counters.channelEvents}`} />
              </dl>
            </Panel>
          )}
        </div>
        <div className="min-w-0 xl:col-start-1 xl:row-start-2">
          <Panel title="Passive attack score over time" aside={`Accept at ${thresholds.streamAccept.toFixed(2)}, attack below ${thresholds.streamAttack.toFixed(2)}`}>
            <PadTrace history={padHistory} thresholds={thresholds} />
            <p className="mt-2 text-xs text-slate">An uncalibrated model score for each usable frame. It is not a probability that the person is genuine or who they are.</p>
          </Panel>
        </div>
      </div>
    </div>
  )
}
