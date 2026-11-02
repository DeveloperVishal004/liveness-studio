// Port of liveness-core MiniFasPad: crop geometry, 80x80 BGR input, softmax P(real), fusion across scales.
import { cropResizeToChw, type BgrImage } from './image'
import type { Face, Runner } from './yunet'

export const PAD_SIZE = 80

export class PadOutputError extends Error {}

/** Upstream CropImage._get_new_box: integer bbox, box scaled about its centre, shifted into the frame. Returns inclusive [l,t,r,b]. */
export function cropBox(srcW: number, srcH: number, f: Pick<Face, 'x' | 'y' | 'w' | 'h'>, scale: number): [number, number, number, number] {
  const x = Math.trunc(f.x)
  const y = Math.trunc(f.y)
  const bw = Math.trunc(f.w)
  const bh = Math.trunc(f.h)
  if (!(bw > 0) || !(bh > 0)) throw new Error('empty face box')
  const s = Math.min((srcH - 1) / bh, Math.min((srcW - 1) / bw, scale))
  const nw = bw * s
  const nh = bh * s
  const cx = bw / 2 + x
  const cy = bh / 2 + y
  let l = cx - nw / 2
  let t = cy - nh / 2
  let r = cx + nw / 2
  let b = cy + nh / 2
  if (l < 0) { r -= l; l = 0 }
  if (t < 0) { b -= t; t = 0 }
  if (r > srcW - 1) { l -= r - srcW + 1; r = srcW - 1 }
  if (b > srcH - 1) { t -= b - srcH + 1; b = srcH - 1 }
  return [Math.trunc(l), Math.trunc(t), Math.trunc(r), Math.trunc(b)]
}

/** Softmax over the 3 logits, returning P(class 1 = real). Anything that is not a finite 3-way output is an error, never a score. */
export function realProbability(logits: Float32Array, dims: number[]): number {
  if (logits.length !== 3 || (dims.length > 0 && dims.reduce((a, b) => a * b, 1) !== 3)) throw new PadOutputError('unexpected PAD output shape')
  const l0 = logits[0]!, l1 = logits[1]!, l2 = logits[2]!
  const max = Math.max(l0, l1, l2)
  if (!Number.isFinite(max)) throw new PadOutputError('non-finite PAD logits')
  const e0 = Math.exp(l0 - max), e1 = Math.exp(l1 - max), e2 = Math.exp(l2 - max)
  const p = e1 / (e0 + e1 + e2)
  if (!(p >= 0 && p <= 1)) throw new PadOutputError('PAD probability out of range')
  return p
}

/** P(real) per context scale (the scale is widened from float32 as the Java code does). */
export async function scoreFace(runners: { scale: number; runner: Runner }[], img: BgrImage, face: Face): Promise<number[]> {
  const out: number[] = []
  const buf = new Float32Array(3 * PAD_SIZE * PAD_SIZE)
  for (const { scale, runner } of runners) {
    const [l, t, r, b] = cropBox(img.width, img.height, face, Math.fround(scale))
    cropResizeToChw(img, l, t, r + 1, b + 1, PAD_SIZE, PAD_SIZE, buf, 0)
    const res = await runner.run({ input: { data: buf, dims: [1, 3, PAD_SIZE, PAD_SIZE] } })
    const first = Object.values(res)[0]
    if (!first) throw new PadOutputError('no PAD output')
    out.push(realProbability(first.data, first.dims))
  }
  return out
}

/** Mean of P(real) across scales. An empty list is NaN, which no gate accepts. */
export function fuse(perScale: number[]): number {
  if (perScale.length === 0) return Number.NaN
  return perScale.reduce((a, b) => a + b, 0) / perScale.length
}
