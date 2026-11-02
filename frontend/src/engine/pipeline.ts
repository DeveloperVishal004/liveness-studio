// Port of liveness-core FramePipeline.process: frozen-frame check, detection, quality gates, PAD, landmark-aligned grey crop.
import { laplacianVariance, meanGrey, similarityTransform, warpAffineToChw, type BgrImage } from './image'
import { fuse, scoreFace } from './pad'
import { detectFaces, type Runner } from './yunet'

export interface PipelineConfig {
  detWidth: number
  scoreThreshold: number
  nmsThreshold: number
  minFaceHeightPx: number
  minMeanGrey: number
  maxMeanGrey: number
  minSharpness: number
}

/** The engine's defaults (FramePipeline.Config and Phase0Models). Provisional and uncalibrated. */
export const PIPELINE_DEFAULTS: PipelineConfig = {
  detWidth: 320,
  scoreThreshold: 0.6,
  nmsThreshold: 0.3,
  minFaceHeightPx: 80,
  minMeanGrey: 40,
  maxMeanGrey: 220,
  minSharpness: 15,
}

export interface FrameEvidence {
  faceCount: number
  eligible: boolean
  ineligibleReason: string | null
  faceHeightPx: number
  meanGrey: number
  sharpness: number
  /** fused P(real); null unless the frame was eligible */
  pad: number | null
  perScale: number[]
  landmarks: number[][] | null
  /** x, y, w, h in analysis-frame pixels */
  faceBox: number[] | null
  yawProxy: number
  /** 64x64 landmark-aligned grey crop for the motion check (eligible frames only) */
  alignedGrey: Float32Array | null
  spansMs: Record<string, number>
  width: number
  height: number
}

const ALIGN = 64
const SFACE_TEMPLATE = [[38.2946, 51.6963], [73.5318, 51.5014], [56.0252, 71.7366], [41.5493, 92.3655], [70.7299, 92.2041]]
const K = Math.fround(ALIGN / 112)
export const TEMPLATE48: number[][] = SFACE_TEMPLATE.map(([x, y]) => [Math.fround(Math.fround(x!) * K), Math.fround(Math.fround(y!) * K)])

export class FramePipeline {
  private last: Uint8Array | null = null

  constructor(
    private readonly detector: Runner,
    private readonly pads: { scale: number; runner: Runner }[],
    private readonly cfg: PipelineConfig = PIPELINE_DEFAULTS,
    private readonly clock: () => number = () => performance.now(),
  ) {}

  /** A byte-identical repeat of the previous frame is a stalled sensor or a looped injection: never evidence. */
  private isFrozen(img: BgrImage): boolean {
    const prev = this.last
    this.last = img.data
    if (prev === null || prev.length !== img.data.length) return false
    for (let i = 0; i < prev.length; i += 7) if (prev[i] !== img.data[i]) return false // cheap strided pass first
    for (let i = 0; i < prev.length; i++) if (prev[i] !== img.data[i]) return false
    return true
  }

  async process(img: BgrImage): Promise<FrameEvidence> {
    const spans: Record<string, number> = {}
    const t0 = this.clock()
    const base = { pad: null, perScale: [] as number[], landmarks: null, faceBox: null, yawProxy: Number.NaN, alignedGrey: null, width: img.width, height: img.height }
    if (this.isFrozen(img)) {
      spans['total'] = this.clock() - t0
      return { ...base, faceCount: -1, eligible: false, ineligibleReason: 'FROZEN_FRAME', faceHeightPx: 0, meanGrey: 0, sharpness: 0, spansMs: spans, width: 0, height: 0 }
    }
    const faces = await detectFaces(this.detector, img, this.cfg.detWidth, this.cfg.scoreThreshold, this.cfg.nmsThreshold)
    const t1 = this.clock()
    spans['detect'] = t1 - t0
    if (faces.length !== 1) {
      spans['total'] = t1 - t0
      return { ...base, faceCount: faces.length, eligible: false, ineligibleReason: faces.length === 0 ? 'NO_FACE' : 'MULTIPLE_FACES', faceHeightPx: 0, meanGrey: 0, sharpness: 0, spansMs: spans }
    }
    const f = faces[0]!
    const x0 = Math.trunc(f.x), y0 = Math.trunc(f.y), x1 = Math.trunc(f.x + f.w), y1 = Math.trunc(f.y + f.h)
    const grey = meanGrey(img, x0, y0, x1, y1)
    const sharp = laplacianVariance(img, x0, y0, x1, y1)
    const t2 = this.clock()
    spans['quality'] = t2 - t1
    let why: string | null = null
    if (f.h < this.cfg.minFaceHeightPx) why = 'FACE_TOO_SMALL'
    else if (grey < this.cfg.minMeanGrey) why = 'TOO_DARK'
    else if (grey > this.cfg.maxMeanGrey) why = 'TOO_BRIGHT'
    else if (sharp < this.cfg.minSharpness) why = 'BLUR'
    const lm = f.landmarks.map((p) => [p[0]!, p[1]!])
    const iod = Math.hypot(lm[1]![0]! - lm[0]![0]!, lm[1]![1]! - lm[0]![1]!)
    const yaw = iod > 1e-3 ? (lm[2]![0]! - (lm[0]![0]! + lm[1]![0]!) / 2) / iod : Number.NaN
    const common = { faceCount: 1, faceHeightPx: f.h, meanGrey: grey, sharpness: sharp, landmarks: lm, faceBox: [f.x, f.y, f.w, f.h], yawProxy: yaw, width: img.width, height: img.height }
    if (why !== null) {
      spans['total'] = t2 - t0
      return { ...common, eligible: false, ineligibleReason: why, pad: null, perScale: [], alignedGrey: null, spansMs: spans }
    }
    const perScale = await scoreFace(this.pads, img, f)
    const pad = fuse(perScale)
    const t3 = this.clock()
    spans['pad'] = t3 - t2

    // landmark-aligned grey crop for the motion check
    const m = similarityTransform(lm, TEMPLATE48)
    const buf = new Float32Array(3 * ALIGN * ALIGN)
    warpAffineToChw(img, m, ALIGN, ALIGN, buf)
    const plane = ALIGN * ALIGN
    const g = new Float32Array(plane)
    for (let i = 0; i < plane; i++) g[i] = Math.fround(Math.fround(0.114 * buf[i]!) + Math.fround(0.587 * buf[i + plane]!) + Math.fround(0.299 * buf[i + 2 * plane]!))
    spans['motion_signature'] = this.clock() - t3
    spans['total'] = this.clock() - t0
    return { ...common, eligible: true, ineligibleReason: null, pad, perScale, alignedGrey: g, spansMs: spans }
  }
}
