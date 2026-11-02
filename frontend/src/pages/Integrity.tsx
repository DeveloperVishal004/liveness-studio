import { ShieldAlert } from 'lucide-react'
import { IntegrityList } from '../components/Pipeline'
import { Panel } from '../components/ui'
import { useEngine } from '../state/engine'

export default function Integrity() {
  const { snapshot: s, mode } = useEngine()
  const counts = s.integrity.reduce<Record<string, number>>((m, c) => ({ ...m, [c.state]: (m[c.state] ?? 0) + 1 }), {})
  return (
    <div>
      <div className="mb-4">
        <h1 className="text-2xl font-semibold">Security integrity</h1>
        <p className="mt-1 max-w-2xl text-slate">The checks the engine runs on the signed capture, for the latest trial. Only checks that actually ran are marked Passed or Failed.</p>
      </div>
      <div role="note" className="mb-5 flex gap-3 rounded-md border border-warn/40 bg-warn/10 p-4 text-sm">
        <ShieldAlert size={18} className="mt-0.5 shrink-0 text-warn" aria-hidden="true" />
        <p><strong className="font-semibold">A valid signature does not prove the person was live.</strong> It shows the capture came intact from the trusted device, was fresh, and was not replayed. A photo or a screen held up to a genuine, trusted camera is still signed. Telling those apart is the job of the presentation-attack checks, shown on the Pipeline screen.</p>
      </div>
      {mode === 'browser' && (
        <p role="note" className="mb-5 rounded-md border border-signal-dim bg-signal/5 px-4 py-3 text-sm">
          <strong className="font-semibold text-signal">Not available in the browser.</strong> These checks apply to a signed capture from a certified device. A browser camera produces no signature, certificate, nonce or device identity, so every check below is shown as unavailable rather than passed. Run the engine locally (<span className="code">./webcam.sh --ui</span>) to see them run.
        </p>
      )}
      <Panel title={s.trial.number > 0 ? `Trial ${s.trial.number}` : 'No verification has run'} aside={mode === 'demo' ? 'Simulated' : `${counts['passed'] ?? 0} passed · ${counts['failed'] ?? 0} failed · ${counts['not_checked'] ?? 0} not yet checked`}>
        <IntegrityList checks={s.integrity} />
      </Panel>
      <p className="mt-3 max-w-2xl text-xs text-faint">Keys, certificate contents and the raw biometric payload are never shown here, and are not sent to this page.</p>
    </div>
  )
}
