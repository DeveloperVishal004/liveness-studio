import type { ScenarioId } from '../types'

export type ScenarioKind = 'genuine' | 'attack' | 'condition'

export interface Scenario {
  id: ScenarioId
  title: string
  kind: ScenarioKind
  /** What the operator physically sets up. */
  howTo: string
  /** What the experiment expects. The engine decides independently; the two are compared afterwards. */
  expectVerified: boolean
  /** Which scripted outcome stands in for this scenario in DEMO mode only. */
  demoScript: string
}

export const SCENARIOS: Scenario[] = [
  { id: 'genuine_live', title: 'Genuine live person', kind: 'genuine', howTo: 'One person looks at the camera, in even light, and smiles or speaks naturally.', expectVerified: true, demoScript: 'verified' },
  { id: 'printed_photo', title: 'Printed photograph', kind: 'attack', howTo: 'Hold a printed photo of a face in front of the camera. Nobody else in view.', expectVerified: false, demoScript: 'static_image' },
  { id: 'screen_replay', title: 'Screen-video replay', kind: 'attack', howTo: 'Play a face video on a phone or second screen and hold it in front of the camera. Keep your own face out of view.', expectVerified: false, demoScript: 'pad_attack' },
  { id: 'poor_lighting', title: 'Poor lighting', kind: 'condition', howTo: 'Dim the room or sit with a bright window behind you.', expectVerified: false, demoScript: 'too_dark' },
  { id: 'blurred_face', title: 'Blurred face', kind: 'condition', howTo: 'Move quickly or smear the lens slightly so the face is not sharp.', expectVerified: false, demoScript: 'blurred' },
  { id: 'no_face', title: 'No face', kind: 'condition', howTo: 'Point the camera at the room with nobody in view.', expectVerified: false, demoScript: 'no_face' },
  { id: 'multiple_faces', title: 'Multiple faces', kind: 'condition', howTo: 'Two people sit in front of the camera together.', expectVerified: false, demoScript: 'multiple_faces' },
  { id: 'subject_change', title: 'Subject change', kind: 'attack', howTo: 'Start as one person, then let a different person take their place during the attempt.', expectVerified: false, demoScript: 'subject_mismatch' },
]

export function scenarioOf(label: string | null): Scenario | undefined {
  return SCENARIOS.find((s) => s.id === label)
}

/** A positive outcome: the engine verified, or (browser build only) the passive checks passed. Neither is an accuracy claim. */
export function isPositive(state: string): boolean {
  return state === 'VERIFIED' || state === 'PASSIVE_PASSED'
}

/** Did the engine's decision agree with what the experiment expected? Kept separate from the decision itself. */
export function matchedExpectation(label: string | null, state: string): boolean | null {
  const sc = scenarioOf(label)
  if (!sc) return null
  if (state === 'CANCELLED') return null
  return sc.expectVerified === isPositive(state)
}
