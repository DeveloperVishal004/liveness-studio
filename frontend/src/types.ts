// Mirrors the JSON of the local engine API (liveness-core LiveSnapshot). The UI renders these values; it never
// computes a decision of its own.

export type StageState = 'pending' | 'active' | 'passed' | 'attention' | 'failed' | 'skipped'
export type CheckState = 'passed' | 'failed' | 'not_checked' | 'unavailable' | 'not_applicable'

export interface Stage {
  id: string
  label: string
  model: string | null
  state: StageState
  durationMs: number | null
  reasonCode: string | null
  detail: string
}

export interface Check {
  id: string
  label: string
  state: CheckState
  detail: string
}

export interface EventEntry {
  tMs: number
  type: string
  text: string
}

export interface Snapshot {
  trial: {
    id: string | null
    number: number
    label: string | null
    active: boolean
    unfinished: boolean
    startedAtMs: number | null
    finishedAtMs: number | null
    attempt: number | null
    maxAttempts: number | null
  }
  decision: {
    state: string
    reason: string
    bindingReason: string | null
    verdict: string
    detail: string | null
    final: boolean
  }
  frame: {
    width: number
    height: number
    faceCount: number
    eligible: boolean
    ineligibleReason: string | null
    faceBox: number[] | null
    processingMs: number | null
    ageMs: number | null
  }
  pad: {
    stream: {
      last: number | null
      median: number | null
      min: number | null
      max: number | null
      frames: number
      eligibleFrames: number
    }
    capture: { score: number | null }
  }
  timing: {
    readyMs: number | null
    captureRoundTripMs: number | null
    bindMs: number | null
    frameSpansMs: Record<string, number>
    decisionMs: number | null
  }
  counters: { attackEvents: number; channelEvents: number }
  camera: { framesReceived: number; lastFrameAgeMs: number | null; streaming: boolean }
  ineligibleCounts: Record<string, number>
  stages: Stage[]
  integrity: Check[]
  events: EventEntry[]
}

export interface Thresholds {
  streamAccept: number
  streamAttack: number
  captureAccept: number
  captureAttack: number
  subjectMinCosine: number
  motionTrigger: number
  minFaceHeightPx: number
  minSharpness: number
  minStreamEmbeddings: number
  attackMinFrames: number
}

export interface EngineInfo {
  mode: string
  camera: string
  device: string
  pad: string
  disclosure: string
  thresholds: Thresholds
}

/** real = the local Java engine; browser = the models running in this browser; demo = scripted and simulated */
export type Mode = 'real' | 'browser' | 'demo'
export type Connection = 'connecting' | 'connected' | 'error' | 'unauthorized' | 'malformed' | 'offline'

/** What was staged in front of the camera. An experiment note, never a claim about what the detector found. */
export type ScenarioId =
  | 'genuine_live'
  | 'printed_photo'
  | 'screen_replay'
  | 'poor_lighting'
  | 'blurred_face'
  | 'no_face'
  | 'multiple_faces'
  | 'subject_change'

/** One finished (or abandoned) trial, kept locally. Contains no frames, embeddings or personal data. */
export interface TrialRecord {
  id: string
  source: Mode
  label: string | null
  startedAtMs: number
  finishedAtMs: number | null
  state: string
  reason: string
  bindingReason: string | null
  verdict: string
  unfinished: boolean
  decisionMs: number | null
  streamPad: { last: number | null; median: number | null; min: number | null; max: number | null; frames: number; eligibleFrames: number }
  capturePad: number | null
  frameProcessingMs: number | null
  frameSpansMs: Record<string, number>
  readyMs: number | null
  captureRoundTripMs: number | null
  bindMs: number | null
  attackEvents: number
  channelEvents: number
  ineligibleCounts: Record<string, number>
  integrity: { id: string; state: CheckState }[]
  stages: { id: string; state: StageState; reasonCode: string | null; durationMs: number | null }[]
  events: EventEntry[]
}
