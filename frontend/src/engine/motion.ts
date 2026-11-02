// Port of liveness-core StaticReplayDetector: landmark-aligned crops registered by affine Lucas-Kanade; the statistic is the
// maximum 8x8-block mean absolute residual. A window is VARYING when enough consecutive pairs exceed the threshold.

export type MotionVerdict = 'VARYING' | 'STATIC_SUSPECT' | 'INSUFFICIENT_FRAMES'

export interface Assessment {
  verdict: MotionVerdict
  pairs: number
  varyingPairs: number
  maxPhoto: number
}

export function zscore(v: Float32Array): Float64Array | null {
  let m = 0
  for (const x of v) m += x
  m /= v.length
  let variance = 0
  for (const x of v) variance += (x - m) * (x - m)
  const sd = Math.sqrt(variance / v.length)
  if (sd < 1e-6) return null
  const z = new Float64Array(v.length)
  for (let i = 0; i < v.length; i++) z[i] = (v[i]! - m) / sd
  return z
}

const at = (b: Float64Array, n: number, x: number, y: number): number => {
  x = x < 0 ? 0 : x >= n ? n - 1 : x
  y = y < 0 ? 0 : y >= n ? n - 1 : y
  return b[y * n + x]!
}

/** Bilinear resampling of b at the affine-warped coordinates (edge clamp). */
export function warp(b: Float64Array, n: number, p: number[]): Float64Array {
  const out = new Float64Array(n * n)
  for (let y = 0; y < n; y++) {
    for (let x = 0; x < n; x++) {
      const sx = (1 + p[0]!) * x + p[2]! * y + p[4]!
      const sy = p[1]! * x + (1 + p[3]!) * y + p[5]!
      const x0 = Math.floor(sx), y0 = Math.floor(sy)
      const wx = sx - x0, wy = sy - y0
      const v00 = at(b, n, x0, y0), v01 = at(b, n, x0 + 1, y0), v10 = at(b, n, x0, y0 + 1), v11 = at(b, n, x0 + 1, y0 + 1)
      out[y * n + x] = (v00 * (1 - wx) + v01 * wx) * (1 - wy) + (v10 * (1 - wx) + v11 * wx) * wy
    }
  }
  return out
}

/** Gaussian elimination with partial pivoting; null if singular. */
export function solve(m: number[][], y: number[]): number[] | null {
  const k = y.length
  const a = m.map((row, r) => [...row, y[r]!])
  for (let c = 0; c < k; c++) {
    let piv = c
    for (let r = c + 1; r < k; r++) if (Math.abs(a[r]![c]!) > Math.abs(a[piv]![c]!)) piv = r
    if (Math.abs(a[piv]![c]!) < 1e-12) return null
    const t = a[c]!
    a[c] = a[piv]!
    a[piv] = t
    for (let r = 0; r < k; r++) {
      if (r !== c) {
        const f = a[r]![c]! / a[c]![c]!
        for (let q = c; q <= k; q++) a[r]![q]! -= f * a[c]![q]!
      }
    }
  }
  return a.map((row, r) => row[k]! / row[r]!)
}

/** Affine params p (x' = (1+p0)x + p2 y + p4, y' = p1 x + (1+p3) y + p5) registering b onto a. */
export function register(a: Float64Array, b: Float64Array, n: number): number[] {
  const p = [0, 0, 0, 0, 0, 0]
  const border = 4
  for (let it = 0; it < 30; it++) {
    const bw = warp(b, n, p)
    const h = Array.from({ length: 6 }, () => new Array<number>(6).fill(0))
    const g = new Array<number>(6).fill(0)
    for (let y = border; y < n - border; y++) {
      for (let x = border; x < n - border; x++) {
        const i = y * n + x
        const gx = (bw[i + 1]! - bw[i - 1]!) / 2
        const gy = (bw[i + n]! - bw[i - n]!) / 2
        const j = [gx * x, gy * x, gx * y, gy * y, gx, gy]
        const e = a[i]! - bw[i]!
        for (let r = 0; r < 6; r++) {
          g[r]! += j[r]! * e
          for (let c = 0; c < 6; c++) h[r]![c]! += j[r]! * j[c]!
        }
      }
    }
    const dp = solve(h, g)
    if (dp === null) break
    let step = 0
    for (let k = 0; k < 6; k++) {
      p[k]! += dp[k]!
      step += Math.abs(dp[k]!)
    }
    if (step < 1e-4) break
  }
  return p
}

/** Maximum 8x8-block mean |residual| between two aligned crops after registration. +Infinity when a crop cannot be standardised (documented residual risk). */
export function photoResidual(a: Float32Array, b: Float32Array): number {
  const za = zscore(a)
  const zb = zscore(b)
  if (za === null || zb === null || za.length !== zb.length) return Number.POSITIVE_INFINITY
  const n = Math.round(Math.sqrt(za.length))
  if (n * n !== za.length) return Number.POSITIVE_INFINITY
  const p = register(za, zb, n)
  const bw = warp(zb, n, p)
  const border = 6
  const block = 8
  let best = 0
  for (let by = border; by + block <= n - border; by += block / 2) {
    for (let bx = border; bx + block <= n - border; bx += block / 2) {
      let s = 0
      for (let y = by; y < by + block; y++) for (let x = bx; x < bx + block; x++) s += Math.abs(za[y * n + x]! - bw[y * n + x]!)
      best = Math.max(best, s / (block * block))
    }
  }
  return best
}

export interface MotionRecord {
  alignedGrey: Float32Array | null
  /** residual versus the previous usable record, filled when the record is appended */
  photoToPrev: number
}

export const MOTION_DEFAULTS = { photoThreshold: 0.4, minPairs: 10, minVaryingPairs: 1 }

/** records: time-ordered, only those with an aligned crop are used. photoToPrev must already be set for each usable record but the first. */
export function assess(records: MotionRecord[], cfg = MOTION_DEFAULTS): Assessment {
  let pairs = 0
  let varying = 0
  let maxP = 0
  let prev: MotionRecord | null = null
  for (const r of records) {
    if (r.alignedGrey === null) continue
    if (prev !== null) {
      pairs++
      maxP = Math.max(maxP, r.photoToPrev)
      if (r.photoToPrev > cfg.photoThreshold) varying++
    }
    prev = r
  }
  if (pairs < cfg.minPairs) return { verdict: 'INSUFFICIENT_FRAMES', pairs, varyingPairs: varying, maxPhoto: maxP }
  return { verdict: varying >= cfg.minVaryingPairs ? 'VARYING' : 'STATIC_SUSPECT', pairs, varyingPairs: varying, maxPhoto: maxP }
}
