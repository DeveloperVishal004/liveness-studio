// Port of liveness-core YuNetDetector: frame downscale, 32-padding, output decoding and NMS.
import { resizeBilinear, type BgrImage } from './image'

export interface Face {
  x: number
  y: number
  w: number
  h: number
  /** 5 landmarks: right eye, left eye, nose, right mouth corner, left mouth corner */
  landmarks: number[][]
  score: number
}

/** A model runner: the real one wraps ONNX Runtime Web; tests pass a fake. Inputs/outputs are flat float arrays. */
export interface Runner {
  run(feeds: Record<string, { data: Float32Array; dims: number[] }>): Promise<Record<string, { data: Float32Array; dims: number[] }>>
}

const STRIDES = [8, 16, 32]
const f32 = Math.fround
const clamp01 = (v: number) => (v < 0 ? 0 : v > 1 ? 1 : v)

export function iou(a: Face, b: Face): number {
  const ix = Math.max(0, Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x))
  const iy = Math.max(0, Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y))
  const inter = ix * iy
  const union = a.w * a.h + b.w * b.h - inter
  return union > 0 ? inter / union : 0
}

export function nms(faces: Face[], thr: number): Face[] {
  const sorted = faces.slice().sort((a, b) => b.score - a.score)
  const keep: Face[] = []
  outer: for (const f of sorted) {
    for (const k of keep) if (iou(f, k) > thr) continue outer
    keep.push(f)
  }
  return keep
}

/** Builds the padded planar BGR input (zero padded to a multiple of 32) exactly as the Java detector does. */
export function yunetInput(frame: BgrImage, detWidth: number): { input: Float32Array; pw: number; ph: number; scale: number } {
  const scale = frame.width > detWidth ? f32(detWidth / frame.width) : 1
  let img = frame
  if (scale !== 1) img = resizeBilinear(frame, Math.floor(f32(frame.width * scale) + 0.5), Math.floor(f32(frame.height * scale) + 0.5))
  const pw = Math.floor((img.width + 31) / 32) * 32
  const ph = Math.floor((img.height + 31) / 32) * 32
  const plane = pw * ph
  const input = new Float32Array(plane * 3)
  const d = img.data
  for (let y = 0; y < img.height; y++) {
    let si = y * img.width * 3
    let di = y * pw
    for (let x = 0; x < img.width; x++, si += 3, di++) {
      input[di] = d[si]!
      input[di + plane] = d[si + 1]!
      input[di + 2 * plane] = d[si + 2]!
    }
  }
  return { input, pw, ph, scale }
}

export function decodeYunet(out: Record<string, { data: Float32Array }>, pw: number, scale: number, scoreThr: number, nmsThr: number): Face[] {
  const faces: Face[] = []
  for (const s of STRIDES) {
    const cls = out[`cls_${s}`]?.data
    const obj = out[`obj_${s}`]?.data
    const bbox = out[`bbox_${s}`]?.data
    const kps = out[`kps_${s}`]?.data
    if (!cls || !obj || !bbox || !kps) throw new Error(`missing YuNet output for stride ${s}`)
    const n = cls.length
    if (obj.length !== n || bbox.length !== 4 * n || kps.length !== 10 * n) throw new Error('unexpected YuNet output shapes') // never guess on bad output
    const cols = pw / s
    for (let i = 0; i < n; i++) {
      const score = Math.sqrt(clamp01(cls[i]!) * clamp01(obj[i]!))
      if (!(score >= scoreThr)) continue
      const r = Math.floor(i / cols)
      const col = i % cols
      const cx = (col + bbox[4 * i]!) * s
      const cy = (r + bbox[4 * i + 1]!) * s
      const w = Math.exp(bbox[4 * i + 2]!) * s
      const h = Math.exp(bbox[4 * i + 3]!) * s
      const lm: number[][] = []
      for (let k = 0; k < 5; k++) lm.push([((kps[10 * i + 2 * k]! + col) * s) / scale, ((kps[10 * i + 2 * k + 1]! + r) * s) / scale])
      faces.push({ x: (cx - w / 2) / scale, y: (cy - h / 2) / scale, w: w / scale, h: h / scale, landmarks: lm, score })
    }
  }
  return nms(faces, nmsThr)
}

export async function detectFaces(runner: Runner, frame: BgrImage, detWidth = 320, scoreThr = 0.6, nmsThr = 0.3): Promise<Face[]> {
  const { input, pw, ph, scale } = yunetInput(frame, detWidth)
  const out = await runner.run({ input: { data: input, dims: [1, 3, ph, pw] } })
  return decodeYunet(out, pw, scale, scoreThr, nmsThr)
}
