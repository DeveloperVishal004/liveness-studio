import { defineConfig } from 'vite'
// Local-only build of parity/parity.html (never deployed). Serve dist-parity and copy the golden fixtures beside it.
export default defineConfig({ root: 'parity', publicDir: '../public', build: { outDir: '../dist-parity', emptyOutDir: true, chunkSizeWarningLimit: 2000 } })
