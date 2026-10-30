import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { gzipSync } from 'node:zlib'

import react from '@vitejs/plugin-react'
import type { Plugin } from 'vite'
import { defineConfig } from 'vitest/config'

// 官网 www.cdnca.com：纯静态站。`vite build` 出客户端包，`vite build --ssr`
// 出 dist-ssr/entry-server.js，scripts/prerender.mjs 逐路由写 dist/<路径>/index.html。
// 产物由 68 门户机 nginx 托管（apps/www/nginx-www.conf），无后端、无会话。
// Writes <file>.gz next to each text asset so nginx gzip_static can serve it
// without compressing per request (node's zlib only, no extra dependency).
// Prerendered HTML is written later by scripts/prerender.mjs and is not covered.
function precompress(): Plugin {
  return {
    name: 'cdnca-precompress',
    apply: 'build',
    writeBundle(options, bundle) {
      if (options.dir?.endsWith('dist-ssr')) return
      for (const [fileName, output] of Object.entries(bundle)) {
        if (!/\.(js|css|svg)$/.test(fileName)) continue
        const source = output.type === 'chunk' ? output.code : output.source
        if (source.length < 1024) continue
        const gz = gzipSync(source, { level: 9 })
        if (gz.length < source.length) writeFileSync(join(options.dir!, `${fileName}.gz`), gz)
      }
    },
  }
}

export default defineConfig(({ isSsrBuild }) => ({
  base: '/',
  plugins: [react(), precompress()],
  server: { port: 5180 },
  build: {
    assetsDir: 'assets',
    sourcemap: false,
    // Stable react chunk keeps its hash (and browser cache) across content-only releases.
    rollupOptions: isSsrBuild ? {} : {
      output: {
        manualChunks(id: string) {
          if (/\/node_modules\/(react|react-dom|scheduler)\//.test(id)) return 'vendor-react'
        },
      },
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
    globals: true,
    css: false,
    maxWorkers: 1,
    testTimeout: 30_000,
  },
}))
