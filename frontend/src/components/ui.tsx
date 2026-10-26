import { AlertTriangle, CheckCircle2, Circle, CircleSlash, Loader2, MinusCircle, XCircle, type LucideIcon } from 'lucide-react'
import { useEffect, useId, useRef, type ReactNode } from 'react'
import type { CheckState, StageState } from '../types'
import type { OutcomeKind } from '../lib/outcome'
import { OUTCOME_LABEL } from '../lib/outcome'

export const TONE: Record<string, string> = {
  ok: 'text-ok',
  warn: 'text-warn',
  bad: 'text-bad',
  signal: 'text-signal',
  muted: 'text-slate',
}

const STAGE_META: Record<StageState, { icon: LucideIcon; tone: string; word: string }> = {
  pending: { icon: Circle, tone: 'text-faint', word: 'Waiting' },
  active: { icon: Loader2, tone: 'text-signal', word: 'Running' },
  passed: { icon: CheckCircle2, tone: 'text-ok', word: 'Passed' },
  attention: { icon: AlertTriangle, tone: 'text-warn', word: 'Needs attention' },
  failed: { icon: XCircle, tone: 'text-bad', word: 'Failed' },
  skipped: { icon: MinusCircle, tone: 'text-faint', word: 'Not reached' },
}

export function StageGlyph({ state, size = 18 }: { state: StageState; size?: number }) {
  const m = STAGE_META[state]
  const Icon = m.icon
  return <Icon size={size} className={`${m.tone} ${state === 'active' ? 'animate-spin' : ''} shrink-0`} aria-hidden="true" />
}
export const stageWord = (s: StageState) => STAGE_META[s].word
export const stageTone = (s: StageState) => STAGE_META[s].tone

const CHECK_META: Record<CheckState, { icon: LucideIcon; tone: string; word: string }> = {
  passed: { icon: CheckCircle2, tone: 'text-ok', word: 'Passed' },
  failed: { icon: XCircle, tone: 'text-bad', word: 'Failed' },
  not_checked: { icon: Circle, tone: 'text-faint', word: 'Not yet checked' },
  unavailable: { icon: CircleSlash, tone: 'text-warn', word: 'Unavailable' },
  not_applicable: { icon: MinusCircle, tone: 'text-faint', word: 'Not applicable' },
}
export function CheckGlyph({ state, size = 18 }: { state: CheckState; size?: number }) {
  const m = CHECK_META[state]
  const Icon = m.icon
  return <Icon size={size} className={`${m.tone} shrink-0`} aria-hidden="true" />
}
export const checkWord = (s: CheckState) => CHECK_META[s].word
export const checkTone = (s: CheckState) => CHECK_META[s].tone

export const OUTCOME_TONE: Record<OutcomeKind, string> = {
  idle: 'text-slate', running: 'text-signal', verified: 'text-ok', retry: 'text-warn', rejected: 'text-bad', error: 'text-bad', cancelled: 'text-slate',
}

export function OutcomePill({ kind }: { kind: OutcomeKind }) {
  const dot = kind === 'verified' ? 'bg-ok' : kind === 'retry' ? 'bg-warn' : kind === 'rejected' || kind === 'error' ? 'bg-bad' : kind === 'running' ? 'bg-signal' : 'bg-faint'
  return (
    <span className={`inline-flex items-center gap-2 text-sm font-medium ${OUTCOME_TONE[kind]}`}>
      <span className={`h-2 w-2 rounded-full ${dot}`} aria-hidden="true" />
      {OUTCOME_LABEL[kind]}
    </span>
  )
}

export function Panel({ title, aside, children, className = '', id }: { title?: ReactNode; aside?: ReactNode; children: ReactNode; className?: string; id?: string }) {
  return (
    <section id={id} className={`panel ${className}`} aria-labelledby={id ? `${id}-t` : undefined}>
      {(title || aside) && (
        <header className="flex items-center justify-between gap-3 border-b border-rule px-4 py-2.5">
          <h2 id={id ? `${id}-t` : undefined} className="text-base font-semibold">{title}</h2>
          {aside && <div className="text-xs text-slate">{aside}</div>}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  )
}

export function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-slate">{label}</dt>
      <dd className="num mt-0.5 text-lg font-semibold leading-tight">{value}</dd>
      {hint && <div className="mt-0.5 text-xs text-slate">{hint}</div>}
    </div>
  )
}

export function Code({ children }: { children: ReactNode }) {
  return <code className="code rounded-sm border border-rule bg-abyss px-1.5 py-0.5 text-paper">{children}</code>
}

/** A technical term with a focusable explanation (works with keyboard and touch, not only hover). */
export function Term({ children, tip }: { children: ReactNode; tip: string }) {
  const id = useId()
  return (
    <span className="group relative inline-block">
      <span tabIndex={0} aria-describedby={id} className="cursor-help border-b border-dotted border-slate">
        {children}
      </span>
      <span
        id={id}
        role="tooltip"
        className="pointer-events-none absolute left-0 top-full z-30 mt-1 hidden w-64 rounded-md border border-rule-strong bg-raised p-2 text-xs font-normal leading-snug text-paper shadow-lg group-focus-within:block group-hover:block"
      >
        {tip}
      </span>
    </span>
  )
}

export function EmptyState({ title, body, action }: { title: string; body: ReactNode; action?: ReactNode }) {
  return (
    <div className="rounded-md border border-dashed border-rule-strong px-6 py-10 text-center">
      <h3 className="text-base font-semibold">{title}</h3>
      <p className="mx-auto mt-1 max-w-md text-slate">{body}</p>
      {action && <div className="mt-4 flex justify-center">{action}</div>}
    </div>
  )
}

export function ConfirmDialog({ open, title, body, confirmLabel, onConfirm, onCancel }: { open: boolean; title: string; body: ReactNode; confirmLabel: string; onConfirm: () => void; onCancel: () => void }) {
  const ref = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    const d = ref.current
    if (!d) return
    if (open && !d.open) d.showModal()
    if (!open && d.open) d.close()
  }, [open])
  return (
    <dialog
      ref={ref}
      onCancel={(e) => {
        e.preventDefault()
        onCancel()
      }}
      className="m-auto w-[min(92vw,26rem)] rounded-md border border-rule-strong bg-deck p-0 text-paper backdrop:bg-black/60"
    >
      <div className="p-5">
        <h2 className="text-lg font-semibold">{title}</h2>
        <div className="mt-2 text-slate">{body}</div>
        <div className="mt-5 flex justify-end gap-2">
          <button className="btn btn-quiet" onClick={onCancel} autoFocus>Keep as is</button>
          <button className="btn btn-danger" onClick={onConfirm}>{confirmLabel}</button>
        </div>
      </div>
    </dialog>
  )
}
