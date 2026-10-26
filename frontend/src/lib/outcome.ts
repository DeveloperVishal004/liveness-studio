import type { Snapshot } from '../types'

export type OutcomeKind = 'idle' | 'running' | 'verified' | 'retry' | 'rejected' | 'error' | 'cancelled'

/**
 * The ONE place a decision is classified. "verified" requires the engine's own final VERIFIED state: a running camera,
 * a detected face, a high PAD score or a completed animation can never produce it.
 */
export function outcomeKind(s: Snapshot | null): OutcomeKind {
  if (!s || s.trial.number === 0) return 'idle'
  const { state, final } = s.decision
  if (state === 'CANCELLED') return 'cancelled'
  if (!final) return 'running'
  switch (state) {
    case 'VERIFIED':
      return 'verified'
    case 'RETRY_PENDING':
      return 'retry'
    case 'REJECTED_ATTACK':
    case 'FAILED_POLICY':
    case 'FAILED_MAX_RETRIES':
      return 'rejected'
    default:
      return 'error'
  }
}

export const OUTCOME_LABEL: Record<OutcomeKind, string> = {
  idle: 'Not started',
  running: 'In progress',
  verified: 'Verified',
  retry: 'Retry required',
  rejected: 'Rejected',
  error: 'Technical error',
  cancelled: 'Cancelled',
}

/** Human-readable session status, mapped from the engine's real states (none is invented). */
export function sessionPhase(s: Snapshot | null): string {
  if (!s || s.trial.number === 0) return 'Not started'
  const { state } = s.decision
  switch (state) {
    case 'CAPTURING':
      if (s.pad.stream.frames === 0) return 'Initializing'
      if (s.pad.stream.eligibleFrames === 0) return 'Waiting for a suitable face'
      return 'Assessing evidence'
    case 'READY_FOR_CAPTURE':
      return 'Ready for signed capture'
    case 'CAPTURE_IN_FLIGHT':
      return 'Validating capture'
    case 'VERIFIED':
      return 'Verified'
    case 'RETRY_PENDING':
      return 'Retry required'
    case 'REJECTED_ATTACK':
    case 'FAILED_POLICY':
    case 'FAILED_MAX_RETRIES':
      return 'Rejected'
    case 'CANCELLED':
      return 'Cancelled'
    case 'EXPIRED':
      return 'Session expired'
    case 'ERROR_ENGINE':
    case 'ERROR_DEVICE':
      return 'Technical error'
    case 'CREATED':
      return 'Initializing'
    default:
      return state
  }
}

/** Ordered phases for the status ladder; `index` is where the current state sits. */
export const LADDER = ['Initializing', 'Waiting for a suitable face', 'Assessing evidence', 'Ready for signed capture', 'Validating capture'] as const

/** Which phases the engine actually reached. After a finished trial a phase is never marked done unless it happened. */
export function ladderReached(s: Snapshot | null): boolean[] {
  if (!s || s.trial.number === 0) return LADDER.map(() => false)
  return [
    true,
    s.pad.stream.frames > 0,
    s.pad.stream.eligibleFrames > 0,
    s.timing.readyMs != null,
    s.timing.captureRoundTripMs != null || s.decision.bindingReason != null,
  ]
}

export function ladderIndex(s: Snapshot | null): number {
  const p = sessionPhase(s)
  const i = (LADDER as readonly string[]).indexOf(p)
  if (i >= 0) return i
  if (!s || s.trial.number === 0) return -1
  return LADDER.length // finished
}
