import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Preline's per-plugin builds (preline/plugins/overlay, …) register themselves on
// window when imported, but its package.json "sideEffects" list omits them, so
// Rollup would tree-shake the imports away. Mark them as side-effectful.
const prelineSideEffects = {
  name: 'preline-side-effects',
  transform(code, id) {
    if (/node_modules[\\/]preline[\\/]dist[\\/].+\.mjs$/.test(id)) return { code, map: null, moduleSideEffects: true }
  },
}

export default defineConfig({
  plugins: [react(), tailwindcss(), prelineSideEffects],
  server: { fs: { allow: ['..'] }, proxy: { '/api': 'http://localhost:8080', '/scim': 'http://localhost:8080', '/idp': 'http://localhost:8080', '/auth': 'http://localhost:8080' } },
})
