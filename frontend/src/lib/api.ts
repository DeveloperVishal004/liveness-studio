import type { EngineInfo, Snapshot, StageState, CheckState } from '../types'

export type ApiErrorKind = 'network' | 'unauthorized' | 'malformed' | 'http' | 'timeout'

export class ApiError extends Error {
  readonly kind: ApiErrorKind
  readonly status?: number
  constructor(kind: ApiErrorKind, message: string, status?: number) {
    super(message)
    this.kind = kind
    this.status = status
  }
}

const TOKEN_KEY = 'liveness-studio.token'

/** The launcher puts the per-run token in the URL fragment (#t=...), so it is never sent to any server or logged. */
export function readToken(): string | null {
  try {
    const t = new URLSearchParams(window.location.hash.replace(/^#/, '')).get('t')
    if (t) {
      sessionStorage.setItem(TOKEN_KEY, t)
      return t
    }
    return sessionStorage.getItem(TOKEN_KEY)
  } catch {
    return null
  }
}

const STAGE_STATES: StageState[] = ['pending', 'active', 'passed', 'attention', 'failed', 'skipped']
const CHECK_STATES: CheckState[] = ['passed', 'failed', 'not_checked', 'unavailable', 'not_applicable']

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** Refuse anything that is not the engine's snapshot shape: a malformed answer must never be rendered as a result. */
export function parseSnapshot(raw: unknown): Snapshot {
  const bad = (why: string): never => {
    throw new ApiError('malformed', `The engine sent an unexpected response (${why}).`)
  }
  if (!isObj(raw)) return bad('not an object')
  const { trial, decision, frame, pad, timing, counters, camera, stages, integrity, events } = raw
  if (!isObj(trial) || typeof trial.number !== 'number' || typeof trial.active !== 'boolean') return bad('trial')
  if (!isObj(decision) || typeof decision.state !== 'string' || typeof decision.reason !== 'string' || typeof decision.final !== 'boolean') return bad('decision')
  if (!isObj(frame) || typeof frame.faceCount !== 'number') return bad('frame')
  if (!isObj(pad) || !isObj(pad.stream) || !isObj(pad.capture)) return bad('pad')
  if (!isObj(timing) || !isObj(counters) || !isObj(camera)) return bad('timing')
  if (!Array.isArray(stages) || stages.length === 0) return bad('stages')
  for (const s of stages) {
    if (!isObj(s) || typeof s.id !== 'string' || !STAGE_STATES.includes(s.state as StageState)) return bad('stage')
  }
  if (!Array.isArray(integrity)) return bad('integrity')
  for (const c of integrity) {
    if (!isObj(c) || typeof c.id !== 'string' || !CHECK_STATES.includes(c.state as CheckState)) return bad('check')
  }
  if (!Array.isArray(events)) return bad('events')
  return raw as unknown as Snapshot
}

export function parseInfo(raw: unknown): EngineInfo {
  if (!isObj(raw) || !isObj(raw.thresholds) || typeof raw.disclosure !== 'string') {
    throw new ApiError('malformed', 'The engine sent an unexpected /info response.')
  }
  return raw as unknown as EngineInfo
}

interface RequestOpts {
  method?: 'GET' | 'POST'
  body?: unknown
  signal?: AbortSignal
  timeoutMs?: number
}

export async function request(path: string, opts: RequestOpts = {}): Promise<unknown> {
  const token = readToken()
  if (!token) throw new ApiError('unauthorized', 'No access token. Open the address printed by ./webcam.sh --ui.')
  const ctl = new AbortController()
  const timer = setTimeout(() => ctl.abort('timeout'), opts.timeoutMs ?? 4000)
  opts.signal?.addEventListener('abort', () => ctl.abort('cancelled'), { once: true })
  try {
    const res = await fetch(path, {
      method: opts.method ?? 'GET',
      headers: { 'X-Token': token, ...(opts.body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      signal: ctl.signal,
      cache: 'no-store',
    })
    if (res.status === 401) throw new ApiError('unauthorized', 'The engine refused the access token.', 401)
    if (!res.ok) {
      let message = `The engine answered ${res.status}.`
      try {
        const j: unknown = await res.json()
        if (isObj(j) && typeof j.message === 'string') message = j.message
      } catch {
        /* keep the status text */
      }
      throw new ApiError('http', message, res.status)
    }
    if (res.status === 204) return null
    try {
      return await res.json()
    } catch {
      throw new ApiError('malformed', 'The engine sent a response that is not JSON.')
    }
  } catch (e) {
    if (e instanceof ApiError) throw e
    if (ctl.signal.aborted && ctl.signal.reason === 'timeout') throw new ApiError('timeout', 'The engine did not answer in time.')
    if (ctl.signal.aborted) throw new ApiError('network', 'Request cancelled.')
    throw new ApiError('network', 'Cannot reach the local engine. Is ./webcam.sh --ui running?')
  } finally {
    clearTimeout(timer)
  }
}

export const api = {
  status: async (signal?: AbortSignal) => parseSnapshot(await request('/api/status', { signal })),
  info: async () => parseInfo(await request('/api/info')),
  history: async (): Promise<Snapshot[]> => {
    const raw = await request('/api/history', { timeoutMs: 8000 })
    if (!Array.isArray(raw)) throw new ApiError('malformed', 'The engine sent an unexpected history response.')
    return raw.map(parseSnapshot)
  },
  startTrial: async (label: string | null) => {
    await request('/api/trial', { method: 'POST', body: { label } })
  },
  cancel: async () => {
    await request('/api/cancel', { method: 'POST', body: {} })
  },
  quit: async () => {
    await request('/api/quit', { method: 'POST', body: {} })
  },
}

/** The engine's own camera frames (what is assessed is exactly what is shown). */
export function previewUrl(): string | null {
  const t = readToken()
  return t ? `/api/stream.mjpg?t=${encodeURIComponent(t)}` : null
}
