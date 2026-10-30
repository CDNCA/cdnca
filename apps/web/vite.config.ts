import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { gzipSync } from 'node:zlib'

import react from '@vitejs/plugin-react'
import { loadEnv, type Plugin } from 'vite'
import { configDefaults, defineConfig } from 'vitest/config'

type ModuleInfoLookup = (id: string) => { importers: readonly string[] } | null

// 控制台壳（菜单标题）与全量资源 resources.ts 一起加载的翻译模块合成一个块：分散成
// 几十个小块时压缩率差、请求多（实测合并后少约 31 KB gzip）。公开页（注册）
// 也用到的翻译模块不并入，免得公开页为一个命名空间拉下整块。
const consoleI18nOwners = /\/src\/(?:routes\/navigation\.ts|components\/AppShell\.tsx|i18n\/resources\.ts)$/
const publicPageModules = /\/src\/pages\/RegisterPage\.tsx$/
const translationModule = /\/src\/(?:i18n\/([^/]+\.ts)|pages\/[^/]+\/(?:i18n|messages)\.ts)$/
// i18n 运行时与首包核心资源：按文件名精确列出，不算翻译模块。手动块会连带吸收成员的
// 静态依赖，每个翻译模块都导入 i18n/index.ts，所以这些文件（连同动态导入用的
// preload-helper）要先定到首屏的 i18n-runtime 块，否则会被吸进 console-i18n、拖进首包。
const i18nRuntimeFiles = new Set(['index.ts', 'coreResources.ts', 'traditional.ts', 'apiError.ts', 'formatters.ts', 'antdLocale.ts'])
const preloadHelper = /vite\/preload-helper\.js$/

function consoleI18nChunk(id: string, getModuleInfo: ModuleInfoLookup): string | undefined {
  if (preloadHelper.test(id)) return 'i18n-runtime'
  const match = translationModule.exec(id)
  if (!match) return undefined
  if (match[1] && i18nRuntimeFiles.has(match[1])) return 'i18n-runtime'
  const importers = getModuleInfo(id)?.importers ?? []
  if (match[1] !== 'resources.ts' && !importers.some((importer) => consoleI18nOwners.test(importer))) return undefined
  if (importers.some((importer) => publicPageModules.test(importer))) return undefined
  return 'console-i18n'
}

// 给每个文本产物写一份 <file>.gz，主控 nginx 的 gzip_static 直接发，不必每次请求现压
// （只用 node 自带 zlib，同 operator-console）。
function precompress(): Plugin {
  return {
    name: 'cdnca-precompress',
    apply: 'build',
    writeBundle(options, bundle) {
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

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', '')

  if (mode === 'production' && env.VITE_PACKAGE_COMMERCE_ENABLED === 'false') {
    throw new Error('Production Web builds must keep package commerce enabled')
  }

  return {
    base: '/dashboard/',
    plugins: [react(), precompress()],
    build: {
      rollupOptions: {
        output: {
          // Stable vendor chunks keep their content hash across business-only
          // releases, so the immutable /assets/ cache survives upgrades.
          manualChunks(id, { getModuleInfo }) {
            if (!id.includes('/node_modules/')) return consoleI18nChunk(id, getModuleInfo)
            if (/\/node_modules\/(react|react-dom|scheduler|react-router|react-router-dom)\//.test(id)) return 'vendor-react'
            if (/\/node_modules\/(i18next|react-i18next)\//.test(id)) return 'vendor-i18n'
            // antd is left to Rollup on purpose: a single vendor-antd chunk pulls every
            // lazily used component into the first load (+~108 kB gzip measured).
            // echarts/zrender are also left to Rollup so they stay lazy.
          },
        },
      },
    },
    server: {
      proxy: {
        '/v1': env.CDNCA_API_PROXY_TARGET || 'http://localhost:8080',
      },
    },
    test: {
      environment: 'jsdom',
      setupFiles: './src/test/setup.ts',
      // scripts/*.test.mjs run under node --test; src/tests/DefaultLookLock.test.ts covers them here.
      exclude: [...configDefaults.exclude, 'scripts/**'],
      globals: true,
      css: true,
      maxWorkers: 1,
      testTimeout: 30_000,
    },
  }
})
