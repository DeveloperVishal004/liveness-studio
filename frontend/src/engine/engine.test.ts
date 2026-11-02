import { describe, expect, it } from 'vitest'
import { clampInt, cropResizeToChw, laplacianVariance, meanGrey, resizeBilinear, rgbaToBgr, rint, similarityTransform, warpAffineToChw, type BgrImage } from './image'
import { assess, photoResidual, zscore } from './motion'
import { cropBox, fuse, PadOutputError, realProbability } from './pad'
import { FramePipeline, TEMPLATE48 } from './pipeline'
import { medianLower, PassiveSession, PASSIVE_DEFAULTS } from './session'
import { decodeYunet, nms, yunetInput, type Face, type Runner } from './yunet'
import type { FrameEvidence } from './pipeline'

// ---- helpers --------------------------------------------------------------------------------------------------------
function seeded(seed: number) {
  let s = seed >>> 0
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0
    return s / 2 ** 32
  }
}
function texture(seed: number, n = 64): Float32Array {
  const r = seeded(seed)
  const t = new Float32Array(n * n)
  for (let i = 0; i < t.length; i++) t[i] = (r() + r() + r() - 1.5) * 40 + 128
  return t
}
function solid(w: number, h: number, v: number): BgrImage {
  return { width: w, height: h, data: new Uint8Array(w * h * 3).fill(v) }
}
function noisy(w: number, h: number, seed: number, mean = 128, amp = 60): BgrImage {
  const r = seeded(seed)
  const d = new Uint8Array(w * h * 3)
  for (let i = 0; i < d.length; i++) d[i] = Math.max(0, Math.min(255, mean + (r() - 0.5) * amp))
  return { width: w, height: h, data: d }
}

describe('image ops', () => {
  it('rint rounds half to even like Java', () => {
    expect([0.5, 1.5, 2.5, 3.5, 2.4, 2.6, 254.5, 255.5].map(rint)).toEqual([0, 2, 2, 4, 2, 3, 254, 256])
    expect(clampInt(5, 0, 3)).toBe(3)
  })
  it('converts RGBA to BGR', () => {
    const bgr = rgbaToBgr(new Uint8ClampedArray([10, 20, 30, 255, 40, 50, 60, 255]), 2, 1)
    expect(Array.from(bgr.data)).toEqual([30, 20, 10, 60, 50, 40])
  })
  it('crop-resize to the same size is the identity, in planar BGR order', () => {
    const img = noisy(8, 6, 1)
    const out = new Float32Array(8 * 6 * 3)
    cropResizeToChw(img, 0, 0, 8, 6, 8, 6, out, 0)
    for (let i = 0; i < 8 * 6; i++) {
      expect(out[i]).toBe(img.data[i * 3]) // plane 0 = B
      expect(out[i + 48]).toBe(img.data[i * 3 + 1])
      expect(out[i + 96]).toBe(img.data[i * 3 + 2])
    }
  })
  it('clamps absurd crop windows instead of reading outside the image', () => {
    const img = noisy(10, 10, 2)
    const out = new Float32Array(3 * 4 * 4)
    expect(() => cropResizeToChw(img, -50, -50, 500, 500, 4, 4, out, 0)).not.toThrow()
    expect(() => cropResizeToChw(img, 9, 9, 3, 3, 4, 4, out, 0)).not.toThrow()
    expect(out.every(Number.isFinite)).toBe(true)
  })
  it('resizes a constant image to the same constant', () => {
    const r = resizeBilinear(solid(100, 60, 77), 40, 24)
    expect(r.width).toBe(40)
    expect(new Set(r.data)).toEqual(new Set([77]))
  })
  it('similarity transform recovers identity, scale and shift', () => {
    const pts = [[10, 10], [50, 12], [30, 30], [14, 50], [46, 52]]
    const id = similarityTransform(pts, pts)
    expect(id.map((v) => +v.toFixed(6))).toEqual([1, -0, 0, 0, 1, 0].map((v) => +v.toFixed(6)))
    const moved = pts.map(([x, y]) => [2 * x! + 5, 2 * y! - 3])
    const m = similarityTransform(pts, moved)
    expect(m[0]).toBeCloseTo(2, 6)
    expect(m[2]).toBeCloseTo(5, 6)
    expect(m[5]).toBeCloseTo(-3, 6)
    expect(() => similarityTransform([[1, 1], [1, 1]], [[0, 0], [1, 1]])).toThrow(/degenerate/)
  })
  it('an identity warp reproduces the image and a singular warp is refused', () => {
    const img = noisy(16, 16, 3)
    const out = new Float32Array(3 * 16 * 16)
    warpAffineToChw(img, [1, 0, 0, 0, 1, 0], 16, 16, out)
    for (let i = 0; i < 256; i++) expect(out[i]).toBe(img.data[i * 3])
    expect(() => warpAffineToChw(img, [0, 0, 0, 0, 0, 0], 16, 16, out)).toThrow(/singular/)
  })
  it('quality measures: flat = no sharpness, noise = sharp, grey weights are BGR', () => {
    expect(laplacianVariance(solid(40, 40, 100), 5, 5, 35, 35)).toBe(0)
    expect(laplacianVariance(noisy(40, 40, 4), 5, 5, 35, 35)).toBeGreaterThan(15)
    const px: BgrImage = { width: 2, height: 2, data: new Uint8Array([100, 0, 0, 100, 0, 0, 100, 0, 0, 100, 0, 0]) } // pure blue
    expect(meanGrey(px, 0, 0, 2, 2)).toBeCloseTo(11.4, 6)
    expect(() => laplacianVariance(solid(3, 3, 1), -9, -9, 99, 99)).not.toThrow()
  })
})

// ---- YuNet decoding -----------------------------------------------------------------------------------------------------
type Det = { cx: number; cy: number; w: number; h: number; score?: number }
/** A fake detector that "finds" faces given in detection-space pixels (stride-8 cells). */
function fakeDetector(dets: Det[] | (() => Det[])): Runner {
  return {
    async run(feeds) {
      const dims = feeds['input']!.dims
      const ph = dims[2]!, pw = dims[3]!
      const out: Record<string, { data: Float32Array; dims: number[] }> = {}
      for (const s of [8, 16, 32]) {
        const n = (ph / s) * (pw / s)
        out[`cls_${s}`] = { data: new Float32Array(n), dims: [1, n, 1] }
        out[`obj_${s}`] = { data: new Float32Array(n), dims: [1, n, 1] }
        out[`bbox_${s}`] = { data: new Float32Array(4 * n), dims: [1, n, 4] }
        out[`kps_${s}`] = { data: new Float32Array(10 * n), dims: [1, n, 10] }
      }
      for (const d of typeof dets === 'function' ? dets() : dets) {
        const s = 8
        const cols = pw / s
        const col = Math.floor(d.cx / s), r = Math.floor(d.cy / s)
        const i = r * cols + col
        const sc = d.score ?? 0.95
        out['cls_8']!.data[i] = sc
        out['obj_8']!.data[i] = sc
        const bb = out['bbox_8']!.data
        bb[4 * i] = d.cx / s - col
        bb[4 * i + 1] = d.cy / s - r
        bb[4 * i + 2] = Math.log(d.w / s)
        bb[4 * i + 3] = Math.log(d.h / s)
        const lm = [[d.cx - d.w * 0.25, d.cy - d.h * 0.15], [d.cx + d.w * 0.25, d.cy - d.h * 0.15], [d.cx, d.cy + d.h * 0.05], [d.cx - d.w * 0.2, d.cy + d.h * 0.25], [d.cx + d.w * 0.2, d.cy + d.h * 0.25]]
        for (let k = 0; k < 5; k++) {
          out['kps_8']!.data[10 * i + 2 * k] = lm[k]![0]! / s - col
          out['kps_8']!.data[10 * i + 2 * k + 1] = lm[k]![1]! / s - r
        }
      }
      return out
    },
  }
}
function padRunner(p: number): Runner {
  const logit1 = Math.log((2 * p) / (1 - p))
  return { async run() { return { logits: { data: Float32Array.from([0, logit1, 0]), dims: [1, 3] } } } }
}

describe('YuNet port', () => {
  it('pads to a multiple of 32 after downscaling to the detection width, in planar BGR', () => {
    const { input, pw, ph, scale } = yunetInput(solid(960, 540, 9), 320)
    expect([pw, ph]).toEqual([320, 192])
    expect(scale).toBeCloseTo(1 / 3, 6)
    expect(input.length).toBe(320 * 192 * 3)
    expect(input[0]).toBe(9)
    expect(input[320 * 180]).toBe(0) // zero padding below the 180 image rows
    expect(yunetInput(solid(200, 100, 1), 320).scale).toBe(1) // never upscaled
  })
  it('decodes a cell back to frame coordinates and keeps landmarks inside the box', async () => {
    const det = fakeDetector([{ cx: 160, cy: 96, w: 64, h: 80 }])
    const { input, pw, ph, scale } = yunetInput(solid(960, 540, 5), 320)
    const out = await det.run({ input: { data: input, dims: [1, 3, ph, pw] } })
    const faces = decodeYunet(out, pw, scale, 0.6, 0.3)
    expect(faces).toHaveLength(1)
    const f = faces[0]!
    expect(f.x).toBeCloseTo((160 - 32) / scale, 3)
    expect(f.h).toBeCloseTo(80 / scale, 3)
    for (const [x, y] of f.landmarks) {
      expect(x).toBeGreaterThan(f.x)
      expect(x).toBeLessThan(f.x + f.w)
      expect(y).toBeGreaterThan(f.y)
      expect(y).toBeLessThan(f.y + f.h)
    }
  })
  it('applies the score threshold and NMS', () => {
    const mk = (x: number, s: number): Face => ({ x, y: 0, w: 100, h: 100, landmarks: [], score: s })
    expect(nms([mk(0, 0.9), mk(5, 0.8), mk(300, 0.7)], 0.3).map((f) => f.score)).toEqual([0.9, 0.7])
  })
  it('refuses malformed model output instead of guessing', () => {
    expect(() => decodeYunet({}, 320, 1, 0.6, 0.3)).toThrow(/missing/)
    const bad = { cls_8: { data: new Float32Array(4) }, obj_8: { data: new Float32Array(3) }, bbox_8: { data: new Float32Array(16) }, kps_8: { data: new Float32Array(40) },
      cls_16: { data: new Float32Array(1) }, obj_16: { data: new Float32Array(1) }, bbox_16: { data: new Float32Array(4) }, kps_16: { data: new Float32Array(10) },
      cls_32: { data: new Float32Array(1) }, obj_32: { data: new Float32Array(1) }, bbox_32: { data: new Float32Array(4) }, kps_32: { data: new Float32Array(10) } }
    expect(() => decodeYunet(bad, 320, 1, 0.6, 0.3)).toThrow(/unexpected YuNet/)
  })
})

// ---- PAD -----------------------------------------------------------------------------------------------------------------
describe('PAD port', () => {
  const p = (a: number, b: number, c: number) => realProbability(Float32Array.from([a, b, c]), [1, 3])
  it('softmax is stable for extreme logits', () => {
    expect(p(0, 0, 0)).toBeCloseTo(1 / 3, 6)
    expect(p(1e30, 0, 0)).toBe(0)
    expect(p(-1e30, 1e30, -1e30)).toBe(1)
    expect(p(0, 1000, 0)).toBeCloseTo(1, 6)
    expect(p(7, 7, -1e30)).toBeCloseTo(0.5, 6)
  })
  it('non-finite or mis-shaped output is an error, never a score', () => {
    for (const bad of [[NaN, 0, 0], [0, Infinity, 0], [-Infinity, -Infinity, -Infinity]]) expect(() => p(bad[0]!, bad[1]!, bad[2]!)).toThrow(PadOutputError)
    expect(() => realProbability(Float32Array.from([1, 2]), [1, 2])).toThrow(PadOutputError)
    expect(() => realProbability(Float32Array.from([1, 2, 3, 4]), [1, 4])).toThrow(PadOutputError)
  })
  it('fusion is the mean and an empty list is NaN, which no gate accepts', () => {
    expect(fuse([1, 0])).toBe(0.5)
    expect(fuse([0.9])).toBe(0.9)
    const e = fuse([])
    expect(Number.isNaN(e)).toBe(true)
    expect(e >= 0.8 || e < 0.2).toBe(false)
  })
  it('the crop box never leaves the image and an empty box is refused', () => {
    const r = seeded(9)
    for (let i = 0; i < 20000; i++) {
      const W = 2 + Math.floor(r() * 3000), H = 2 + Math.floor(r() * 3000)
      const f = { x: (r() - 0.5) * 20000, y: (r() - 0.5) * 20000, w: 1 + r() * 9000, h: 1 + r() * 9000 }
      const [l, t, rr, b] = cropBox(W, H, f, r() < 0.5 ? Math.fround(2.7) : 4)
      expect(l >= 0 && t >= 0 && rr <= W - 1 && b <= H - 1 && l <= rr && t <= b, JSON.stringify({ W, H, f, box: [l, t, rr, b] })).toBe(true)
    }
    expect(() => cropBox(640, 480, { x: 1, y: 1, w: 0, h: 5 }, 2.7)).toThrow(/empty/)
    expect(() => cropBox(640, 480, { x: 1, y: 1, w: 0.9, h: 5 }, 2.7)).toThrow(/empty/)
  })
})

// ---- motion check ---------------------------------------------------------------------------------------------------------
describe('motion check port', () => {
  it('identical crops leave no residual, different crops exceed the trigger', () => {
    const a = texture(1)
    expect(photoResidual(a, a.slice())).toBeLessThan(0.01)
    expect(photoResidual(a, texture(2))).toBeGreaterThan(0.4)
    const scaled = a.map((v) => v * 3 + 40)
    expect(photoResidual(a, scaled)).toBeLessThan(0.4) // brightness/contrast are standardised away
  })
  it('degenerate crops: constant or mis-sized count as motion (documented residual risk), NaN never does', () => {
    const flat = new Float32Array(4096).fill(0.5)
    expect(zscore(flat)).toBeNull()
    expect(photoResidual(flat, flat.slice())).toBe(Infinity)
    expect(photoResidual(texture(1), new Float32Array(63 * 63))).toBe(Infinity)
    const nan = texture(1)
    nan[10] = NaN
    expect(photoResidual(texture(1), nan) > 0.4).toBe(false)
  })
  it('assess needs 10 pairs, and one varying pair is enough', () => {
    const rec = (i: number, varying: boolean) => ({ alignedGrey: texture(i), photoToPrev: varying ? 1 : 0.05 })
    const stat = Array.from({ length: 11 }, () => rec(1, false))
    expect(assess(stat.slice(0, 10)).verdict).toBe('INSUFFICIENT_FRAMES') // 9 pairs
    expect(assess(stat).verdict).toBe('STATIC_SUSPECT')
    const one = stat.slice()
    one[5] = rec(2, true)
    expect(assess(one).verdict).toBe('VARYING')
    expect(assess([]).verdict).toBe('INSUFFICIENT_FRAMES')
    expect(assess(stat.map((r) => ({ alignedGrey: null, photoToPrev: r.photoToPrev }))).pairs).toBe(0)
  })
})

// ---- pipeline with fake models ------------------------------------------------------------------------------------------------
const CENTER_FACE: Det = { cx: 160, cy: 96, w: 64, h: 90 } // 270 px tall after the 1/3 downscale back-projection

describe('frame pipeline (fake models)', () => {
  const pads = (p: number) => [{ scale: 2.7, runner: padRunner(p) }, { scale: 4, runner: padRunner(p) }]
  it('a usable face is eligible with a fused score, landmarks and an aligned crop', async () => {
    const pipe = new FramePipeline(fakeDetector([CENTER_FACE]), pads(0.9))
    const ev = await pipe.process(noisy(960, 540, 1))
    expect(ev.eligible).toBe(true)
    expect(ev.faceCount).toBe(1)
    expect(ev.pad).toBeCloseTo(0.9, 5)
    expect(ev.alignedGrey).toHaveLength(64 * 64)
    expect(ev.landmarks).toHaveLength(5)
    expect(ev.spansMs['pad']).toBeGreaterThanOrEqual(0)
  })
  it('names the first failing quality gate and never scores an unusable frame', async () => {
    const small = new FramePipeline(fakeDetector([{ ...CENTER_FACE, h: 20 }]), pads(0.99))
    const e1 = await small.process(noisy(960, 540, 2))
    expect([e1.eligible, e1.ineligibleReason, e1.pad]).toEqual([false, 'FACE_TOO_SMALL', null])
    const dark = new FramePipeline(fakeDetector([CENTER_FACE]), pads(0.99))
    expect((await dark.process(noisy(960, 540, 3, 10, 10))).ineligibleReason).toBe('TOO_DARK')
    const bright = new FramePipeline(fakeDetector([CENTER_FACE]), pads(0.99))
    expect((await bright.process(noisy(960, 540, 3, 245, 10))).ineligibleReason).toBe('TOO_BRIGHT')
    const blur = new FramePipeline(fakeDetector([CENTER_FACE]), pads(0.99))
    expect((await blur.process(solid(960, 540, 120))).ineligibleReason).toBe('BLUR')
  })
  it('reports no face, several faces, and a frozen frame', async () => {
    expect((await new FramePipeline(fakeDetector([]), pads(0.9)).process(noisy(960, 540, 4))).ineligibleReason).toBe('NO_FACE')
    const two = new FramePipeline(fakeDetector([CENTER_FACE, { cx: 60, cy: 96, w: 40, h: 60 }]), pads(0.9))
    const e = await two.process(noisy(960, 540, 5))
    expect([e.faceCount, e.ineligibleReason]).toEqual([2, 'MULTIPLE_FACES'])
    const pipe = new FramePipeline(fakeDetector([CENTER_FACE]), pads(0.9))
    const img = noisy(960, 540, 6)
    await pipe.process(img)
    const again = await pipe.process({ ...img, data: img.data.slice() })
    expect([again.eligible, again.ineligibleReason, again.faceCount]).toEqual([false, 'FROZEN_FRAME', -1])
    expect((await pipe.process(noisy(960, 540, 7))).eligible).toBe(true) // a new frame is fine again
  })
  it('a model failure surfaces as an error, not as a passing score', async () => {
    const broken: Runner = { async run() { return { logits: { data: Float32Array.from([NaN, 0, 0]), dims: [1, 3] } } } }
    const pipe = new FramePipeline(fakeDetector([CENTER_FACE]), [{ scale: 2.7, runner: broken }])
    await expect(pipe.process(noisy(960, 540, 8))).rejects.toThrow(PadOutputError)
  })
  it('the alignment template is the SFace template scaled to 64', () => {
    expect(TEMPLATE48[0]![0]).toBeCloseTo(38.2946 * (64 / 112), 4)
    expect(TEMPLATE48).toHaveLength(5)
  })
})

// ---- passive session rules (mirrors SessionBoundaryTest on the Java side) ------------------------------------------------------
function ev(pad: number | null, over: Partial<FrameEvidence> = {}, motionSeed?: number): FrameEvidence {
  const eligible = over.eligible ?? pad !== null
  return {
    faceCount: 1, eligible, ineligibleReason: eligible ? null : 'FACE_TOO_SMALL', faceHeightPx: 200, meanGrey: 120, sharpness: 50, pad, perScale: [], landmarks: [[1, 1], [2, 1], [1.5, 2], [1, 3], [2, 3]],
    faceBox: [0, 0, 1, 1], yawProxy: 0, alignedGrey: eligible ? texture(motionSeed ?? 1) : null, spansMs: {}, width: 960, height: 540, ...over,
  }
}
const FRAME = 67
/** Feeds `n` frames; `varying` gives each frame a different texture (motion), otherwise the same texture (still). */
function feed(s: PassiveSession, t: { now: number }, n: number, pad: number, varying = true, extra: Partial<FrameEvidence> = {}) {
  for (let i = 0; i < n; i++) {
    t.now += FRAME
    s.onEvidence(ev(pad, extra, varying ? Math.floor(t.now) : 1), t.now)
  }
}

describe('passive session rules', () => {
  const start = () => ({ s: new PassiveSession(0), t: { now: 0 } })
  it('passes only with enough varying, confident frames; and that is PASSIVE_PASSED, never VERIFIED', () => {
    const { s, t } = start()
    feed(s, t, 40, 0.95)
    expect([s.state, s.reason]).toEqual(['PASSIVE_PASSED', 'OK'])
    expect(s.readyAtMs).toBeGreaterThan(0)
    expect(s.state).not.toBe('VERIFIED')
  })
  it('a still image never passes however high the score: it ends as STATIC_REPLAY_SUSPECT', () => {
    const { s, t } = start()
    feed(s, t, 120, 0.999, false)
    s.tick(11_000)
    expect([s.state, s.reason]).toEqual(['RETRY_PENDING', 'STATIC_REPLAY_SUSPECT'])
  })
  it('two attack frames are tolerated and the third rejects, even when separated by good frames', () => {
    const { s, t } = start()
    feed(s, t, 2, 0.1)
    expect(s.state).toBe('CAPTURING')
    feed(s, t, 4, 0.95)
    expect(s.state).toBe('CAPTURING')
    feed(s, t, 1, 0.1)
    expect([s.state, s.reason, s.attackEvents]).toEqual(['REJECTED_ATTACK', 'STREAM_PAD_ATTACK', 1])
  })
  it('exactly 0.20 is not an attack frame; one ulp below is', () => {
    const a = start()
    feed(a.s, a.t, 60, 0.2)
    expect(a.s.state).toBe('CAPTURING')
    a.s.tick(11_000)
    expect([a.s.state, a.s.reason]).toEqual(['RETRY_PENDING', 'PASSIVE_UNCERTAIN_NO_CHALLENGE'])
    const b = start()
    feed(b.s, b.t, 3, 0.2 - Number.EPSILON)
    expect(b.s.state).toBe('REJECTED_ATTACK')
  })
  it('the median gate is exactly 0.80', () => {
    const a = start()
    feed(a.s, a.t, 40, 0.8)
    expect(a.s.state).toBe('PASSIVE_PASSED')
    const b = start()
    feed(b.s, b.t, 40, 0.8 - 1e-9)
    expect(b.s.state).toBe('CAPTURING')
    expect(medianLower([0.1, 0.9, 0.8, 0.85])).toBe(0.8)
  })
  it('a minority of low frames cannot move the median under the gate', () => {
    const { s, t } = start()
    feed(s, t, 2, 0.1)
    feed(s, t, 40, 0.95)
    expect(s.state).toBe('PASSIVE_PASSED')
    expect(s.attackEvents).toBe(0)
  })
  it('needs at least 8 eligible frames spanning one second', () => {
    const { s, t } = start()
    feed(s, t, 7, 0.95)
    expect(s.state).toBe('CAPTURING')
    const q = start()
    feed(q.s, q.t, 11, 0.95) // 11 frames at 67 ms = 0.67 s span
    expect(q.s.state).toBe('CAPTURING')
  })
  it('ineligible frames never count, even with a score attached', () => {
    const { s, t } = start()
    for (let i = 0; i < 100; i++) {
      t.now += FRAME
      s.onEvidence(ev(i % 2 ? 1 : 0, { eligible: false, ineligibleReason: 'FACE_TOO_SMALL' }), t.now)
    }
    expect(s.state).toBe('CAPTURING')
    expect(s.attackEvents).toBe(0)
  })
  it('invalid scores are discarded and counted, and never make the session ready or reject it', () => {
    for (const bad of [NaN, Infinity, -0.1, 1.0001]) {
      const { s, t } = start()
      for (let i = 0; i < 40; i++) {
        t.now += FRAME
        s.onEvidence(ev(bad, { eligible: true }), t.now)
      }
      expect([s.state, s.invalidEvidence, s.attackEvents]).toEqual(['CAPTURING', 40, 0])
    }
  })
  it('more than one face in the window blocks readiness and the time limit reports why', () => {
    const { s, t } = start()
    feed(s, t, 40, 0.95, true, { faceCount: 2, eligible: false, ineligibleReason: 'MULTIPLE_FACES' })
    s.tick(10_500)
    expect([s.state, s.reason]).toEqual(['RETRY_PENDING', 'MULTIPLE_FACES'])
  })
  it('no usable face at all ends as INSUFFICIENT_EVIDENCE at the time limit', () => {
    const { s } = start()
    s.tick(5000)
    expect(s.state).toBe('CAPTURING')
    s.tick(10_001)
    expect([s.state, s.reason]).toEqual(['RETRY_PENDING', 'INSUFFICIENT_EVIDENCE'])
  })
  it('a finished session ignores everything afterwards', () => {
    const { s, t } = start()
    feed(s, t, 3, 0.1)
    expect(s.state).toBe('REJECTED_ATTACK')
    feed(s, t, 60, 0.99)
    expect(s.state).toBe('REJECTED_ATTACK')
    expect(PASSIVE_DEFAULTS.streamAccept).toBe(0.8)
  })
})

// ---- browser snapshots: no signed capture, so never VERIFIED ---------------------------------------------------------------------
import { browserSnapshot } from './browserTrial'
import { idleRaw, DEFAULT_THRESHOLDS } from '../lib/derive'
import { outcomeKind } from '../lib/outcome'
import { groupOf, summarize } from '../lib/analytics'
import { isPositive, matchedExpectation } from '../lib/scenarios'
import { explainReason } from '../lib/copy'

function browserRaw(state: string, reason: string, over: Record<string, unknown> = {}) {
  return { ...idleRaw(), trialNumber: 1, trialId: 'B1-x', active: false, state, reason, frames: 40, eligibleFrames: 38, faceCount: 1, eligible: true, medianPad: 0.9, lastPad: 0.9, readyMs: state === 'PASSIVE_PASSED' ? 1500 : null, startedAtMs: 1000, finishedAtMs: 4000, verdict: 'v', ...over }
}

describe('browser snapshots', () => {
  it('a passive pass is its own outcome and is never classified as verified', () => {
    const s = browserSnapshot(browserRaw('PASSIVE_PASSED', 'PASSIVE_PASSED'), DEFAULT_THRESHOLDS, 40, true)
    expect(outcomeKind(s)).toBe('passive')
    expect(s.decision.final).toBe(true)
    expect(s.stages[7]!.state).toBe('passed')
    expect(s.stages[7]!.detail).toMatch(/not a verification/i)
    expect(groupOf({ state: 'PASSIVE_PASSED', unfinished: false })).toBe('passive')
  })
  it('every signed-capture stage and check is unavailable, never passed', () => {
    const s = browserSnapshot(browserRaw('PASSIVE_PASSED', 'PASSIVE_PASSED'), DEFAULT_THRESHOLDS, 40, true)
    for (const id of ['integrity', 'capturePad', 'subject']) {
      const st = s.stages.find((x) => x.id === id)!
      expect(st.state).toBe('skipped')
      expect(st.detail).toMatch(/not available in the browser/i)
    }
    for (const c of s.integrity) expect(['unavailable', 'not_applicable']).toContain(c.state)
    expect(s.integrity.some((c) => c.state === 'passed')).toBe(false)
  })
  it('retry and rejection keep the engine meaning in the browser', () => {
    expect(outcomeKind(browserSnapshot(browserRaw('RETRY_PENDING', 'STATIC_REPLAY_SUSPECT', { active: false }), DEFAULT_THRESHOLDS, 1, false))).toBe('retry')
    expect(outcomeKind(browserSnapshot(browserRaw('REJECTED_ATTACK', 'STREAM_PAD_ATTACK', { attackEvents: 1 }), DEFAULT_THRESHOLDS, 1, false))).toBe('rejected')
    expect(outcomeKind(browserSnapshot(browserRaw('ERROR_ENGINE', 'ENGINE_ERROR'), DEFAULT_THRESHOLDS, 1, false))).toBe('error')
  })
  it('no state other than the engine VERIFIED is ever verified, including the browser pass', () => {
    for (const state of ['PASSIVE_PASSED', 'CAPTURING', 'RETRY_PENDING', 'REJECTED_ATTACK', 'ERROR_ENGINE', 'CANCELLED', 'EXPIRED']) {
      expect(outcomeKind(browserSnapshot(browserRaw(state, 'X', { active: state === 'CAPTURING' }), DEFAULT_THRESHOLDS, 1, true))).not.toBe('verified')
    }
  })
  it('a passive pass counts as a positive outcome for expectations and acceptance rates', () => {
    expect(isPositive('VERIFIED') && isPositive('PASSIVE_PASSED')).toBe(true)
    expect(isPositive('RETRY_PENDING') || isPositive('CANCELLED')).toBe(false)
    expect(matchedExpectation('genuine_live', 'PASSIVE_PASSED')).toBe(true)
    expect(matchedExpectation('printed_photo', 'PASSIVE_PASSED')).toBe(false) // a photo that passed is a false accept
    const rec = (id: string, label: string, state: string) => ({ id, source: 'browser' as const, label, startedAtMs: 1, finishedAtMs: 2, state, reason: state, bindingReason: null, verdict: '', unfinished: false, decisionMs: 1, streamPad: { last: 1, median: 1, min: 1, max: 1, frames: 1, eligibleFrames: 1 }, capturePad: null, frameProcessingMs: 1, frameSpansMs: {}, readyMs: null, captureRoundTripMs: null, bindMs: null, attackEvents: 0, channelEvents: 0, ineligibleCounts: {}, integrity: [], stages: [], events: [] })
    const s = summarize([rec('a', 'genuine_live', 'PASSIVE_PASSED'), rec('b', 'printed_photo', 'PASSIVE_PASSED'), rec('c', 'printed_photo', 'RETRY_PENDING')])
    expect(s.counts.passive).toBe(2)
    expect(s.counts.verified).toBe(0)
    expect(s.genuine).toEqual({ n: 1, accepted: 1 })
    expect(s.attack).toEqual({ n: 2, accepted: 1 })
  })
  it('explains the passive result without calling it a verification', () => {
    const c = explainReason('PASSIVE_PASSED')
    expect(c.why).toMatch(/NOT a verification/)
    expect(c.next).toMatch(/signed capture/)
  })
})
