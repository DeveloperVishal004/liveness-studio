// LOCAL-ONLY parity check: runs the browser engine's detector and PAD on the golden images and compares with the Python
// reference (research/fixtures/golden/golden.json). Not part of the public site; needs the local fixtures.
import { loadModels } from '../src/engine/models'
import { rgbaToBgr, type BgrImage } from '../src/engine/image'
import { scoreFace } from '../src/engine/pad'
import { detectFaces } from '../src/engine/yunet'

interface Rec { file: string; width: number; height: number; faces: { box: number[]; kps: number[][] }[]; pad: Record<string, number> }

async function decode(url: string): Promise<BgrImage> {
  const bmp = await createImageBitmap(await (await fetch(url)).blob())
  const c = document.createElement('canvas')
  c.width = bmp.width
  c.height = bmp.height
  const g = c.getContext('2d', { willReadFrequently: true })!
  g.drawImage(bmp, 0, 0)
  return rgbaToBgr(g.getImageData(0, 0, c.width, c.height).data, c.width, c.height)
}

async function main() {
  const golden = (await (await fetch('/golden/golden.json')).json()) as { det_width: number; records: Rec[] }
  const models = await loadModels()
  const rows: Record<string, unknown>[] = []
  for (const rec of golden.records) {
    let img: BgrImage
    let source = 'canvas-decode'
    if (rec.file === 'g00_image_F1.jpg') {
      // exact OpenCV-decoded pixels for one image: removes any JPEG decoder difference
      const raw = new Uint8Array(await (await fetch('/golden/g00_image_F1.jpg.cv2.bgr')).arrayBuffer())
      img = { width: rec.width, height: rec.height, data: raw }
      source = 'cv2-bgr'
    } else {
      img = await decode(`/golden/${rec.file}`)
    }
    const faces = await detectFaces(models.detector, img, golden.det_width, 0.6, 0.3)
    const row: Record<string, unknown> = { file: rec.file, source, goldenFaces: rec.faces.length, faces: faces.length }
    if (faces.length === rec.faces.length && faces.length > 0) {
      const f = faces[0]!
      const g = rec.faces[0]!
      row['boxErrPx'] = Math.max(Math.abs(f.x - g.box[0]!), Math.abs(f.y - g.box[1]!), Math.abs(f.w - g.box[2]!), Math.abs(f.h - g.box[3]!))
      row['lmErrPx'] = Math.max(...f.landmarks.flatMap((p, i) => [Math.abs(p[0]! - g.kps[i]![0]!), Math.abs(p[1]! - g.kps[i]![1]!)]))
      const [p27, p40] = await scoreFace(models.pads, img, f)
      row['pad27'] = p27
      row['pad40'] = p40
      row['pad27Err'] = Math.abs(p27! - rec.pad['2.7']!)
      row['pad40Err'] = Math.abs(p40! - rec.pad['4.0']!)
    }
    rows.push(row)
  }
  ;(window as unknown as { __parity: unknown }).__parity = rows
  document.getElementById('out')!.textContent = 'done: ' + rows.length + ' images'
}
main().catch((e) => {
  ;(window as unknown as { __parityError: string }).__parityError = String(e)
  document.getElementById('out')!.textContent = 'ERROR ' + e
})
