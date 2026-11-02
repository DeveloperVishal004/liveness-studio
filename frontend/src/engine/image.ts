// Port of liveness-core ImageOps (BGR byte images, OpenCV-style bilinear, similarity alignment, quality measures).
// Pure functions: no DOM, no model. Kept numerically close to the Java code so scores can be compared against it.

export interface BgrImage {
  width: number
  height: number
  /** interleaved B,G,R bytes, row-major */
  data: Uint8Array
}

/** Round half to even, like Java Math.rint (cv2 stores the rounded value as uint8). */
export function rint(v: number): number {
  const f = Math.floor(v)
  const d = v - f
  if (d < 0.5) return f
  if (d > 0.5) return f + 1
  return f % 2 === 0 ? f : f + 1
}

export const clampInt = (v: number, lo: number, hi: number): number => (v < lo ? lo : v > hi ? hi : v)

/** Canvas ImageData (RGBA) to the BGR layout the models were exported for. */
export function rgbaToBgr(rgba: Uint8ClampedArray, width: number, height: number): BgrImage {
  const out = new Uint8Array(width * height * 3)
  for (let i = 0, j = 0; i < width * height * 4; i += 4, j += 3) {
    out[j] = rgba[i + 2]!
    out[j + 1] = rgba[i + 1]!
    out[j + 2] = rgba[i]!
  }
  return { width, height, data: out }
}

/** Crops [x0,x1) x [y0,y1) (clamped) and resizes to outW x outH, writing CHW float planes (values are whole numbers 0..255). */
export function cropResizeToChw(src: BgrImage, x0: number, y0: number, x1: number, y1: number, outW: number, outH: number, dst: Float32Array, dstOffset: number): void {
  x0 = clampInt(x0, 0, src.width - 1)
  y0 = clampInt(y0, 0, src.height - 1)
  x1 = clampInt(x1, x0 + 1, src.width)
  y1 = clampInt(y1, y0 + 1, src.height)
  const cw = x1 - x0
  const ch = y1 - y0
  const sx = cw / outW
  const sy = ch / outH
  const plane = outW * outH
  const d = src.data
  const stride = src.width * 3
  for (let oy = 0; oy < outH; oy++) {
    const fy = (oy + 0.5) * sy - 0.5
    const iy = Math.floor(fy)
    const wy = fy - iy
    const ya = clampInt(iy, 0, ch - 1) + y0
    const yb = clampInt(iy + 1, 0, ch - 1) + y0
    for (let ox = 0; ox < outW; ox++) {
      const fx = (ox + 0.5) * sx - 0.5
      const ix = Math.floor(fx)
      const wx = fx - ix
      const xa = (clampInt(ix, 0, cw - 1) + x0) * 3
      const xb = (clampInt(ix + 1, 0, cw - 1) + x0) * 3
      const o = dstOffset + oy * outW + ox
      for (let c = 0; c < 3; c++) {
        const p00 = d[ya * stride + xa + c]!
        const p01 = d[ya * stride + xb + c]!
        const p10 = d[yb * stride + xa + c]!
        const p11 = d[yb * stride + xb + c]!
        const v = (p00 * (1 - wx) + p01 * wx) * (1 - wy) + (p10 * (1 - wx) + p11 * wx) * wy
        dst[o + c * plane] = rint(v)
      }
    }
  }
}

/** Full-image bilinear resize to a BGR byte image (used before detection). */
export function resizeBilinear(src: BgrImage, outW: number, outH: number): BgrImage {
  const chw = new Float32Array(outW * outH * 3)
  cropResizeToChw(src, 0, 0, src.width, src.height, outW, outH, chw, 0)
  const out = new Uint8Array(outW * outH * 3)
  const plane = outW * outH
  for (let i = 0; i < plane; i++) {
    out[i * 3] = chw[i]!
    out[i * 3 + 1] = chw[i + plane]!
    out[i * 3 + 2] = chw[i + 2 * plane]!
  }
  return { width: outW, height: outH, data: out }
}

/** Inverse-maps each output pixel through the 2x3 forward matrix m (src -> dst), bilinear, zero border, CHW floats. */
export function warpAffineToChw(src: BgrImage, m: number[], outW: number, outH: number, dst: Float32Array): void {
  const det = m[0]! * m[4]! - m[1]! * m[3]!
  if (Math.abs(det) < 1e-12) throw new Error('singular affine transform')
  const ia = m[4]! / det
  const ib = -m[1]! / det
  const ic = -m[3]! / det
  const id = m[0]! / det
  const itx = -(ia * m[2]! + ib * m[5]!)
  const ity = -(ic * m[2]! + id * m[5]!)
  const plane = outW * outH
  const d = src.data
  const stride = src.width * 3
  const px = (x: number, y: number, c: number) => (x < 0 || y < 0 || x >= src.width || y >= src.height ? 0 : d[y * stride + x * 3 + c]!)
  for (let y = 0; y < outH; y++) {
    for (let x = 0; x < outW; x++) {
      const sx = ia * x + ib * y + itx
      const sy = ic * x + id * y + ity
      const x0 = Math.floor(sx)
      const y0 = Math.floor(sy)
      const wx = sx - x0
      const wy = sy - y0
      const o = y * outW + x
      for (let c = 0; c < 3; c++) {
        const v = (px(x0, y0, c) * (1 - wx) + px(x0 + 1, y0, c) * wx) * (1 - wy) + (px(x0, y0 + 1, c) * (1 - wx) + px(x0 + 1, y0 + 1, c) * wx) * wy
        dst[o + c * plane] = rint(v)
      }
    }
  }
}

/** Least-squares similarity (rotation, uniform scale, translation) src -> dst points (Umeyama, no reflection). 2x3 row-major. */
export function similarityTransform(src: number[][], dst: number[][]): number[] {
  const n = src.length
  let msx = 0, msy = 0, mdx = 0, mdy = 0
  for (let i = 0; i < n; i++) {
    msx += src[i]![0]!; msy += src[i]![1]!; mdx += dst[i]![0]!; mdy += dst[i]![1]!
  }
  msx /= n; msy /= n; mdx /= n; mdy /= n
  let a = 0, b = 0, v = 0
  for (let i = 0; i < n; i++) {
    const sx = src[i]![0]! - msx, sy = src[i]![1]! - msy
    const dx = dst[i]![0]! - mdx, dy = dst[i]![1]! - mdy
    a += sx * dx + sy * dy
    b += sx * dy - sy * dx
    v += sx * sx + sy * sy
  }
  if (v < 1e-9) throw new Error('degenerate landmarks')
  const sc = a / v
  const sn = b / v
  const tx = mdx - (sc * msx - sn * msy)
  const ty = mdy - (sn * msx + sc * msy)
  return [sc, -sn, tx, sn, sc, ty]
}

const grey = (img: BgrImage, x: number, y: number): number => {
  const i = (y * img.width + x) * 3
  return 0.114 * img.data[i]! + 0.587 * img.data[i + 1]! + 0.299 * img.data[i + 2]!
}

/** Variance of the 4-neighbour Laplacian on the grey ROI: a cheap blur proxy (quality gate only). */
export function laplacianVariance(img: BgrImage, x0: number, y0: number, x1: number, y1: number): number {
  x0 = clampInt(x0, 1, img.width - 2)
  y0 = clampInt(y0, 1, img.height - 2)
  x1 = clampInt(x1, x0 + 1, img.width - 1)
  y1 = clampInt(y1, y0 + 1, img.height - 1)
  let sum = 0, sum2 = 0, n = 0
  for (let y = y0; y < y1; y++) {
    for (let x = x0; x < x1; x++) {
      const l = grey(img, x - 1, y) + grey(img, x + 1, y) + grey(img, x, y - 1) + grey(img, x, y + 1) - 4 * grey(img, x, y)
      sum += l
      sum2 += l * l
      n++
    }
  }
  const mean = sum / n
  return sum2 / n - mean * mean
}

/** Mean grey level of an ROI (exposure gate). */
export function meanGrey(img: BgrImage, x0: number, y0: number, x1: number, y1: number): number {
  x0 = clampInt(x0, 0, img.width - 1)
  y0 = clampInt(y0, 0, img.height - 1)
  x1 = clampInt(x1, x0 + 1, img.width)
  y1 = clampInt(y1, y0 + 1, img.height)
  let s = 0
  for (let y = y0; y < y1; y++) for (let x = x0; x < x1; x++) s += grey(img, x, y)
  return s / ((x1 - x0) * (y1 - y0))
}
