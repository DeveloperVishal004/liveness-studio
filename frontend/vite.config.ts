import { defaultClientConditions } from 'vite'
import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Dev server proxies /api to the local Java engine (webcam.sh --ui --no-open prints its port in UI_URL).
// The engine only accepts same-origin POSTs, so the proxy rewrites Origin/Host to the engine's own.
const ENGINE = process.env.ENGINE_URL ?? 'http://127.0.0.1:4810'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // use the runtime build that expects its wasm to be served separately (from /ort/), so it is not bundled a second time
  resolve: { conditions: ['onnxruntime-web-use-extern-wasm', ...defaultClientConditions] },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: ENGINE,
        changeOrigin: true,
        configure: (proxy) => {
          proxy.on('proxyReq', (req) => req.setHeader('origin', ENGINE))
        },
      },
    },
  },
  build: { outDir: 'dist', sourcemap: false, chunkSizeWarningLimit: 600 },
  test: { environment: 'node', include: ['src/**/*.test.ts'] },
})
