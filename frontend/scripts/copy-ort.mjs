// Copies the ONNX Runtime Web wasm binary and its small loader module next to the app so it is served from the same origin (no CDN, CSP stays tight).
import { copyFileSync, existsSync, mkdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
for (const name of ['ort-wasm-simd-threaded.wasm', 'ort-wasm-simd-threaded.mjs']) {
  const src = resolve(root, 'node_modules/onnxruntime-web/dist', name)
  const dst = resolve(root, 'public/ort', name)
  if (!existsSync(src)) {
    console.error('copy-ort: onnxruntime-web is not installed. Run npm install first.')
    process.exit(1)
  }
  mkdirSync(dirname(dst), { recursive: true })
  copyFileSync(src, dst)
}
console.log('copy-ort: wasm runtime and loader copied to public/ort/')
