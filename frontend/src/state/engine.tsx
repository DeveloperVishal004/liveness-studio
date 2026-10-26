import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { api, ApiError, readToken } from '../lib/api'
import { DEMO_ONLY } from '../lib/env'
import { cancelledCopy, demoSnapshot } from '../lib/demo'
import { DEFAULT_THRESHOLDS, idleRaw, toSnapshot } from '../lib/derive'
import { clearRecords, loadRecords, mergeRecords, recordFromSnapshot, upsertRecord } from '../lib/trials'
import type { Connection, EngineInfo, Mode, Snapshot, Thresholds, TrialRecord } from '../types'

export interface PadPoint {
  t: number
  last: number | null
  median: number | null
}

export interface Notice {
  kind: 'info' | 'error'
  text: string
}

interface EngineContext {
  mode: Mode
  setMode: (m: Mode) => void
  hasToken: boolean
  snapshot: Snapshot
  connection: Connection
  connectionMessage: string | null
  info: EngineInfo | null
  thresholds: Thresholds
  records: TrialRecord[]
  padHistory: PadPoint[]
  busy: boolean
  notice: Notice | null
  dismissNotice: () => void
  demoScript: string
  setDemoScript: (id: string) => void
  start: (label: string | null, demoScript?: string) => Promise<void>
  cancel: () => Promise<void>
  clearAllRecords: () => void
  trialRunning: boolean
}

const Ctx = createContext<EngineContext | null>(null)

const MODE_KEY = 'liveness-studio.mode'
const idleSnapshot = (): Snapshot => toSnapshot(idleRaw(), DEFAULT_THRESHOLDS, 0, false)

function initialMode(): Mode {
  if (DEMO_ONLY) return 'demo'
  const token = readToken()
  try {
    const stored = localStorage.getItem(MODE_KEY)
    if (stored === 'demo') return 'demo'
    if (stored === 'real' && token) return 'real'
  } catch {
    /* default below */
  }
  return token ? 'real' : 'demo'
}

export function EngineProvider({ children }: { children: ReactNode }) {
  const [mode, setModeState] = useState<Mode>(initialMode)
  const hasToken = useMemo(() => readToken() !== null, [])
  const [snapshot, setSnapshot] = useState<Snapshot>(idleSnapshot)
  const [connection, setConnection] = useState<Connection>(mode === 'real' ? 'connecting' : 'connected')
  const [connectionMessage, setConnectionMessage] = useState<string | null>(null)
  const [info, setInfo] = useState<EngineInfo | null>(null)
  const [records, setRecords] = useState<TrialRecord[]>(() => loadRecords(initialMode()))
  const [padHistory, setPadHistory] = useState<PadPoint[]>([])
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [demoScript, setDemoScript] = useState('verified')
  const demoRun = useRef<{ script: string; startedAt: number; number: number; label: string | null } | null>(null)
  const demoFrozen = useRef<Snapshot | null>(null)
  const demoCounter = useRef(records.filter((r) => r.source === 'demo').length)
  const recorded = useRef(new Set<string>())
  const lastTrialId = useRef<string | null>(null)
  const thresholds = info?.thresholds ?? DEFAULT_THRESHOLDS

  const setMode = useCallback((m: Mode) => {
    if (DEMO_ONLY && m === 'real') return // the hosted build can never talk to an engine
    try {
      localStorage.setItem(MODE_KEY, m)
    } catch {
      /* not persisted */
    }
    demoRun.current = null
    demoFrozen.current = null
    setSnapshot(idleSnapshot())
    setPadHistory([])
    setRecords(loadRecords(m))
    setConnection(m === 'real' ? 'connecting' : 'connected')
    setConnectionMessage(null)
    setModeState(m)
  }, [])

  const say = useCallback((n: Notice) => {
    setNotice(n)
  }, [])

  useEffect(() => {
    if (!notice) return
    const id = setTimeout(() => setNotice(null), notice.kind === 'error' ? 8000 : 4000)
    return () => clearTimeout(id)
  }, [notice])

  // ---- REAL mode: poll the local engine -------------------------------------------------------------------------------
  useEffect(() => {
    if (mode !== 'real') return
    if (!hasToken) {
      setConnection('unauthorized')
      setConnectionMessage('No access token. Start the engine with ./webcam.sh --ui and open the address it prints.')
      return
    }
    let stopped = false
    let failures = 0
    let timer: ReturnType<typeof setTimeout> | undefined
    const ac = new AbortController()
    let first = true

    const tick = async () => {
      if (stopped) return
      try {
        const s = await api.status(ac.signal)
        if (stopped) return
        setSnapshot(s)
        setConnection('connected')
        setConnectionMessage(null)
        failures = 0
        if (first) {
          first = false
          api.info().then((i) => !stopped && setInfo(i)).catch(() => undefined)
          api.history().then((h) => {
            if (stopped) return
            const recs = h.map((x) => recordFromSnapshot(x, 'real')).filter((x): x is TrialRecord => x !== null)
            if (recs.length) setRecords(mergeRecords('real', recs))
          }).catch(() => undefined)
        }
      } catch (e) {
        if (stopped) return
        failures++
        if (e instanceof ApiError && e.kind === 'unauthorized') {
          setConnection('unauthorized')
          setConnectionMessage(e.message)
          return // retrying cannot fix a refused token: stop instead of filling the console with 401s
        } else if (e instanceof ApiError && e.kind === 'malformed') {
          setConnection('malformed')
          setConnectionMessage(e.message)
        } else if (failures >= 3) {
          setConnection(failures >= 8 ? 'offline' : 'error')
          setConnectionMessage(e instanceof Error ? e.message : 'The engine is not answering.')
        }
      }
      timer = setTimeout(tick, failures === 0 ? 120 : Math.min(3000, 300 * 2 ** Math.min(failures, 4)))
    }
    tick()
    return () => {
      stopped = true
      ac.abort()
      if (timer) clearTimeout(timer)
    }
  }, [mode, hasToken])

  // ---- DEMO mode: deterministic scripted events ------------------------------------------------------------------------
  useEffect(() => {
    if (mode !== 'demo') return
    const id = setInterval(() => {
      if (demoFrozen.current) {
        setSnapshot(demoFrozen.current)
        return
      }
      const run = demoRun.current
      if (!run) return
      const next = demoSnapshot(run.script, Date.now() - run.startedAt, run.number, run.startedAt, run.label)
      if (next.decision.final) {
        demoFrozen.current = next // a finished trial is frozen: no more updates, and it can only be recorded once
        demoRun.current = null
      }
      setSnapshot(next)
    }, 100)
    return () => clearInterval(id)
  }, [mode])

  // ---- PAD trace + recording --------------------------------------------------------------------------------------------
  useEffect(() => {
    const id = snapshot.trial.id
    if (id !== lastTrialId.current) {
      lastTrialId.current = id
      setPadHistory([])
    }
    if (snapshot.trial.active && snapshot.pad.stream.last != null) {
      setPadHistory((h) => [...h.slice(-239), { t: Date.now(), last: snapshot.pad.stream.last, median: snapshot.pad.stream.median }])
    }
    const rec = recordFromSnapshot(snapshot, mode)
    if (rec) {
      const key = `${mode}:${rec.id}:${rec.state}:${rec.unfinished}`
      if (!recorded.current.has(key)) {
        recorded.current.add(key)
        setRecords(upsertRecord(mode, rec))
      }
    }
  }, [snapshot, mode])

  const start = useCallback(
    async (label: string | null, script?: string) => {
      if (busy) return
      setBusy(true)
      try {
        if (mode === 'real') {
          await api.startTrial(label)
        } else {
          demoFrozen.current = null
          demoCounter.current += 1
          demoRun.current = { script: script ?? demoScript, startedAt: Date.now(), number: demoCounter.current, label }
          setSnapshot(demoSnapshot(demoRun.current.script, 0, demoRun.current.number, demoRun.current.startedAt, label))
        }
      } catch (e) {
        say({ kind: 'error', text: e instanceof Error ? e.message : 'Could not start the trial.' })
      } finally {
        setBusy(false)
      }
    },
    [busy, mode, demoScript, say],
  )

  const cancel = useCallback(async () => {
    if (busy) return
    setBusy(true)
    try {
      if (mode === 'real') {
        await api.cancel()
      } else if (demoRun.current) {
        const run = demoRun.current
        const now = Date.now()
        const frozen = cancelledCopy(demoSnapshot(run.script, now - run.startedAt, run.number, run.startedAt, run.label), now)
        demoFrozen.current = frozen
        demoRun.current = null
        setSnapshot(frozen)
      }
    } catch (e) {
      say({ kind: 'error', text: e instanceof Error ? e.message : 'Could not cancel the trial.' })
    } finally {
      setBusy(false)
    }
  }, [busy, mode, say])

  const clearAllRecords = useCallback(() => {
    clearRecords(mode)
    setRecords([]) // `recorded` is kept: the trial still on screen must not be re-recorded after Clear
  }, [mode])

  const value: EngineContext = {
    mode, setMode, hasToken, snapshot, connection, connectionMessage, info, thresholds, records, padHistory, busy,
    notice, dismissNotice: () => setNotice(null), demoScript, setDemoScript, start, cancel, clearAllRecords,
    trialRunning: snapshot.trial.active,
  }
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useEngine(): EngineContext {
  const c = useContext(Ctx)
  if (!c) throw new Error('useEngine must be used inside EngineProvider')
  return c
}
