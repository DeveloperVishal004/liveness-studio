import { Activity, BarChart3, FlaskConical, Info, ScanFace, ShieldCheck, Terminal, TriangleAlert, Workflow, X, type LucideIcon } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { navigate, useRoute, type Route } from '../router'
import type { Mode } from '../types'
import { useEngine } from '../state/engine'
import { HOSTED } from '../lib/env'
import { ConfirmDialog } from './ui'

const NAV: { to: Route; label: string; icon: LucideIcon }[] = [
  { to: '/', label: 'Verify', icon: ScanFace },
  { to: '/pipeline', label: 'Pipeline', icon: Workflow },
  { to: '/integrity', label: 'Security integrity', icon: ShieldCheck },
  { to: '/lab', label: 'Evaluation lab', icon: FlaskConical },
  { to: '/analytics', label: 'Analytics', icon: BarChart3 },
  { to: '/diagnostics', label: 'Diagnostics', icon: Terminal },
]

function Brand() {
  return (
    <div className="flex items-center gap-3 px-4 py-4 lg:py-5">
      <svg width="30" height="30" viewBox="0 0 32 32" aria-hidden="true" className="shrink-0">
        <path d="M5 11V6h5M22 6h5v5M27 21v5h-5M10 26H5v-5" stroke="#4fc9da" strokeWidth="2.2" fill="none" strokeLinecap="round" />
        <ellipse cx="16" cy="16" rx="5.2" ry="6.8" stroke="#e6edf7" strokeWidth="1.6" fill="none" />
      </svg>
      <div className="min-w-0">
        <div className="text-lg font-semibold leading-tight">Liveness Studio</div>
        <div className="text-xs leading-snug text-slate">Biometric Verification &amp; Security Lab</div>
      </div>
    </div>
  )
}

const MODE_LABEL: Record<Mode, string> = { real: 'Real engine', browser: 'This browser', demo: 'Demo' }

function ModeSwitch() {
  const { mode, modes, setMode, trialRunning } = useEngine()
  const [pending, setPending] = useState<Mode | null>(null)
  const choose = (m: Mode) => {
    if (m === mode) return
    if (trialRunning) setPending(m)
    else setMode(m)
  }
  return (
    <>
      <div role="radiogroup" aria-label="Data source" className="inline-flex overflow-hidden rounded-sm border border-rule-strong">
        {modes.map((m) => (
          <button
            key={m}
            role="radio"
            aria-checked={mode === m}
            onClick={() => choose(m)}
            className={`min-h-9 px-3 text-sm font-medium transition-colors ${mode === m ? 'bg-signal text-[#04202a]' : 'text-slate hover:text-paper'}`}
          >
            {MODE_LABEL[m]}
          </button>
        ))}
      </div>
      <ConfirmDialog
        open={pending !== null}
        title={`Switch to ${pending ? MODE_LABEL[pending].toLowerCase() : ''}?`}
        body="A verification is running. Switching stops it and records it as unfinished."
        confirmLabel="Switch"
        onCancel={() => setPending(null)}
        onConfirm={() => {
          if (pending) setMode(pending)
          setPending(null)
        }}
      />
    </>
  )
}

function ConnectionChip() {
  const { mode, connection, snapshot, modelStatus, camera } = useEngine()
  if (mode === 'demo') return <span className="text-sm text-slate">Scripted events, no camera or engine</span>
  if (mode === 'browser') {
    const t =
      modelStatus.state === 'loading' ? { text: `Loading models… ${Math.round(modelStatus.fraction * 100)}%`, tone: 'text-slate' }
      : modelStatus.state === 'error' ? { text: 'Models could not start', tone: 'text-bad' }
      : camera.state.kind === 'live' ? { text: 'Camera on · analysed on this device · nothing uploaded', tone: 'text-ok' }
      : { text: modelStatus.state === 'ready' ? 'Models ready · camera off' : 'Runs in this browser · nothing uploaded', tone: 'text-slate' }
    return (
      <span className={`inline-flex items-center gap-2 text-sm ${t.tone}`}>
        <Activity size={14} aria-hidden="true" />
        {t.text}
      </span>
    )
  }
  const map: Record<string, { text: string; tone: string }> = {
    connecting: { text: 'Connecting to the local engine…', tone: 'text-slate' },
    connected: snapshot.camera.streaming ? { text: 'Engine connected · camera streaming', tone: 'text-ok' } : { text: 'Engine connected · no camera frames', tone: 'text-warn' },
    error: { text: 'Engine not answering', tone: 'text-warn' },
    offline: { text: 'Engine offline', tone: 'text-bad' },
    unauthorized: { text: 'Not authorised', tone: 'text-bad' },
    malformed: { text: 'Unexpected engine response', tone: 'text-bad' },
  }
  const c = map[connection] ?? map['connecting']!
  return (
    <span className={`inline-flex items-center gap-2 text-sm ${c.tone}`}>
      <Activity size={14} aria-hidden="true" />
      {c.text}
    </span>
  )
}

function Banner() {
  const { mode, connection, connectionMessage, hasToken } = useEngine()
  if (mode === 'demo') {
    return (
      <div role="note" className="flex items-start gap-3 border-b border-warn/40 bg-warn/10 px-6 py-2.5 text-sm">
        <TriangleAlert size={16} className="mt-0.5 shrink-0 text-warn" aria-hidden="true" />
        <p>
          <strong className="font-semibold text-warn">Demo mode.</strong> Every event on screen is simulated from fixed scripts. Nothing here is a measurement{HOSTED ? '. This preview uses no camera feed and no engine, and sends nothing anywhere.' : ', and demo trials are kept apart from real ones.'}
        </p>
      </div>
    )
  }
  if (mode === 'browser') {
    return (
      <div role="note" className="flex items-start gap-3 border-b border-signal-dim bg-signal/5 px-6 py-2.5 text-sm">
        <Info size={16} className="mt-0.5 shrink-0 text-signal" aria-hidden="true" />
        <p>
          <strong className="font-semibold text-signal">Live in your browser.</strong> The face models run on this device, and no image leaves it. A browser has no certified capture device, so there is no signed capture: the best result is <em>Passive checks passed</em>, never <em>Verified</em>. Research prototype with an uncalibrated model; one trial is an anecdote, not an accuracy figure.
        </p>
      </div>
    )
  }
  if (!hasToken || connection === 'unauthorized') {
    return (
      <div role="alert" className="border-b border-bad/40 bg-bad/10 px-6 py-2.5 text-sm">
        <strong className="font-semibold text-bad">Not connected to the engine.</strong>{' '}
        {connectionMessage ?? 'Start it with ./webcam.sh --ui and open the address it prints, or switch to This browser.'}
      </div>
    )
  }
  if (connection === 'offline' || connection === 'error' || connection === 'malformed') {
    return (
      <div role="alert" className="border-b border-warn/40 bg-warn/10 px-6 py-2.5 text-sm">
        <strong className="font-semibold text-warn">Engine connection problem.</strong> {connectionMessage ?? 'Retrying…'}
      </div>
    )
  }
  return null
}

function Toast() {
  const { notice, dismissNotice } = useEngine()
  if (!notice) return null
  return (
    <div role={notice.kind === 'error' ? 'alert' : 'status'} className={`fixed bottom-5 right-5 z-40 flex max-w-sm items-start gap-3 rounded-md border bg-raised px-4 py-3 text-sm shadow-lg ${notice.kind === 'error' ? 'border-bad/60' : 'border-rule-strong'}`}>
      <p>{notice.text}</p>
      <button className="btn btn-quiet !min-h-6 !px-1" onClick={dismissNotice} aria-label="Dismiss message">
        <X size={14} />
      </button>
    </div>
  )
}

export function Shell({ children }: { children: ReactNode }) {
  const route = useRoute()
  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[236px_minmax(0,1fr)]">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-3 focus:top-3 focus:z-50 focus:rounded-sm focus:bg-signal focus:px-3 focus:py-2 focus:text-[#04202a]">Skip to content</a>
      <aside className="border-b border-rule bg-deck lg:sticky lg:top-0 lg:h-screen lg:border-b-0 lg:border-r">
        <Brand />
        <nav aria-label="Main" className="flex gap-1 overflow-x-auto px-2 pb-2 lg:flex-col lg:overflow-visible lg:px-3">
          {NAV.map(({ to, label, icon: Icon }) => {
            const on = route === to
            return (
              <a
                key={to}
                href={to + window.location.hash}
                aria-current={on ? 'page' : undefined}
                onClick={(e) => {
                  e.preventDefault()
                  navigate(to)
                }}
                className={`flex min-h-10 shrink-0 items-center gap-3 rounded-sm px-3 text-sm font-medium transition-colors ${on ? 'bg-raised text-paper shadow-[inset_2px_0_0_var(--color-signal)]' : 'text-slate hover:bg-raised hover:text-paper'}`}
              >
                <Icon size={17} aria-hidden="true" />
                {label}
              </a>
            )
          })}
        </nav>
        <p className="hidden px-4 py-4 text-xs leading-snug text-faint lg:absolute lg:bottom-0 lg:block">
          Research prototype. Not a certified device, not production-ready, and no accuracy claim.
        </p>
      </aside>
      <div className="min-w-0">
        <header className="flex flex-wrap items-center justify-between gap-3 border-b border-rule px-6 py-3">
          <ConnectionChip />
          <ModeSwitch />
        </header>
        <Banner />
        <main id="main" className="mx-auto max-w-[1400px] px-4 py-5 sm:px-6">
          {children}
        </main>
      </div>
      <Toast />
    </div>
  )
}
