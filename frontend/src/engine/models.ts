// Loads the three models into ONNX Runtime Web (WebAssembly, single thread) and checks each file against the SHA-256 the Java
// engine's manifest pins. Everything is fetched from the same origin; nothing leaves the device.
import * as ort from 'onnxruntime-web/wasm'
import type { Runner } from './yunet'

export interface ModelSpec {
  id: 'yunet' | 'pad27' | 'pad40'
  label: string
  url: string
  sha256: string
}

/** Hashes copied from models/onnx/manifest.json (the same pins the Java loader enforces). */
export const MODELS: ModelSpec[] = [
  { id: 'yunet', label: 'Face detector (YuNet)', url: '/models/yunet_2023mar_dynamic.onnx', sha256: 'd6b78655ac8d2e5d3186ba1a8a933c5a33aae3a21614996b87489606e2469a71' },
  { id: 'pad27', label: 'Attack check, wide context (MiniFASNetV2)', url: '/models/minifasnet_minifasnetv2_s2.7.onnx', sha256: '3b6b220dedea9e9ffec5bfd3f85aca6a64dd5ba68b11d7cfefa4af842a9e2511' },
  { id: 'pad40', label: 'Attack check, tight context (MiniFASNetV1SE)', url: '/models/minifasnet_minifasnetv1se_s4.0.onnx', sha256: '21f7d4e0ca7ccd5e36b6824256d8787bff12d220ff0e602ff7b5c858edbce4d4' },
]

export class ModelLoadError extends Error {}

/** Size of the unpacked runtime, so progress can be shown as a true percentage while the (compressed) download streams in. */
export const WASM_URL = '/ort/ort-wasm-simd-threaded.wasm'
export const WASM_BYTES = 14_848_852

/** Streams a file once so the browser caches it and reports real progress; the runtime then finds it already downloaded. */
export async function warmUp(url: string, expectedBytes: number, onFraction: (f: number) => void): Promise<void> {
  let res: Response
  try {
    res = await fetch(url, { cache: 'force-cache' })
  } catch {
    throw new ModelLoadError('Could not download the runtime. Check your connection and try again.')
  }
  if (!res.ok || !res.body) throw new ModelLoadError(`Could not download the runtime (${res.status}).`)
  const reader = res.body.getReader()
  let got = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    got += value.byteLength
    onFraction(Math.min(1, got / expectedBytes))
  }
}

export async function sha256Hex(buf: ArrayBuffer): Promise<string> {
  const subtle = globalThis.crypto?.subtle
  if (!subtle) throw new ModelLoadError('This page is not a secure context (use https or localhost), so the model files cannot be verified.')
  const d = new Uint8Array(await subtle.digest('SHA-256', buf))
  return Array.from(d, (b) => b.toString(16).padStart(2, '0')).join('')
}

function wrap(session: ort.InferenceSession): Runner {
  return {
    async run(feeds) {
      const inputs: Record<string, ort.Tensor> = {}
      for (const [name, t] of Object.entries(feeds)) inputs[name] = new ort.Tensor('float32', t.data, t.dims)
      const res = await session.run(inputs)
      const out: Record<string, { data: Float32Array; dims: number[] }> = {}
      for (const name of Object.keys(res)) {
        const t = res[name]!
        out[name] = { data: t.data as Float32Array, dims: [...t.dims] }
      }
      return out
    },
  }
}

export interface LoadedModels {
  detector: Runner
  pads: { scale: number; runner: Runner }[]
  dispose: () => Promise<void>
}

export type Progress = (label: string, fraction: number) => void

let cached: Promise<LoadedModels> | null = null

/** Loads once per page. A failed load is not cached, so the user can retry. */
export function loadModels(onProgress?: Progress, spec: ModelSpec[] = MODELS): Promise<LoadedModels> {
  if (cached) return cached
  const p = doLoad(onProgress, spec)
  cached = p
  p.catch(() => {
    if (cached === p) cached = null
  })
  return p
}

async function doLoad(onProgress: Progress | undefined, spec: ModelSpec[]): Promise<LoadedModels> {
  ort.env.wasm.numThreads = 1 // single thread: no SharedArrayBuffer or cross-origin isolation needed
  ort.env.wasm.wasmPaths = '/ort/'
  ort.env.logLevel = 'error' // the dynamic-shape YuNet export triggers harmless shape warnings that would otherwise flood the console
  const sessions = new Map<string, ort.InferenceSession>()
  await warmUp(WASM_URL, WASM_BYTES, (f) => onProgress?.(`Downloading the runtime, ${Math.round(f * 100)}%`, f * 0.8))
  for (let i = 0; i < spec.length; i++) {
    const m = spec[i]!
    onProgress?.(m.label, 0.8 + (i / spec.length) * 0.2)
    let res: Response
    try {
      res = await fetch(m.url, { cache: 'force-cache' })
    } catch {
      throw new ModelLoadError(`Could not download ${m.label}. Check your connection and try again.`)
    }
    if (!res.ok) throw new ModelLoadError(`Could not download ${m.label} (${res.status}).`)
    const buf = await res.arrayBuffer()
    const got = await sha256Hex(buf)
    if (got !== m.sha256) throw new ModelLoadError(`${m.label} does not match its pinned hash, so it was not used.`)
    try {
      sessions.set(m.id, await ort.InferenceSession.create(new Uint8Array(buf), { executionProviders: ['wasm'], graphOptimizationLevel: 'all', logSeverityLevel: 3 }))
    } catch (e) {
      throw new ModelLoadError(`The model runtime could not start (${e instanceof Error ? e.message : 'unknown error'}).`)
    }
  }
  onProgress?.('Ready', 1)
  return {
    detector: wrap(sessions.get('yunet')!),
    pads: [
      { scale: 2.7, runner: wrap(sessions.get('pad27')!) },
      { scale: 4.0, runner: wrap(sessions.get('pad40')!) },
    ],
    dispose: async () => {
      for (const s of sessions.values()) await s.release()
      sessions.clear()
      cached = null
    },
  }
}
