#!/usr/bin/env node
// cdnca-site-theme：官网主题插件（cdnca.site-theme/v2）开发工具。
//
//   init <目录> --template user+site|user|site --plugin-id <命名空间.名称> [--name 名称]
//   check [目录] [--content dist/theme.json]
//   preview [目录] [--port 4173] [--content preview/content.json] [--screenshot]
//   pack [目录] [--out dist] [--version x.y.z] [--sign --key publisher.key [--cdnca-plugin 路径]]
//
// 退出码：0 成功，1 预检不通过或执行失败，2 用法错误。
import { readFileSync, realpathSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseArgs } from 'node:util'

import { buildContent, pack, sign } from '../lib/pack.mjs'
import { createPreviewServer } from '../lib/preview.mjs'
import { checkContent, PREVIEW_MAX_BYTES } from '../lib/rules.mjs'
import { scaffold, TEMPLATES } from '../lib/scaffold.mjs'
import { captureScreenshot } from '../lib/screenshot.mjs'

const USAGE = `用法：
  cdnca-site-theme init <目录> --template user+site|user|site --plugin-id <命名空间.名称> [--name 名称]
  cdnca-site-theme check [目录] [--content 文件]
  cdnca-site-theme preview [目录] [--port 4173] [--content preview/content.json] [--screenshot]
  cdnca-site-theme pack [目录] [--out dist] [--version x.y.z] [--sign --key publisher.key [--cdnca-plugin 路径]]`

function printFindings(findings) {
  for (const item of findings) console.error(`  ${item.code}  ${item.field || '(整个包)'}${item.detail ? `  ${item.detail}` : ''}`)
}

export async function main(argv) {
  const [command, ...rest] = argv
  let parsed
  try {
    parsed = parseArgs({
      args: rest, allowPositionals: true,
      options: {
        template: { type: 'string' }, 'plugin-id': { type: 'string' }, name: { type: 'string' }, content: { type: 'string' },
        port: { type: 'string', default: '4173' }, out: { type: 'string' }, version: { type: 'string' }, sign: { type: 'boolean' },
        key: { type: 'string' }, 'cdnca-plugin': { type: 'string' }, help: { type: 'boolean', short: 'h' },
        screenshot: { type: 'boolean' },
      },
    })
  } catch (error) {
    console.error(`${error.message}\n${USAGE}`)
    return 2
  }
  const { values, positionals } = parsed
  if (values.help || !command) {
    console.log(USAGE)
    return command ? 0 : 2
  }
  const dir = resolve(positionals[0] ?? '.')
  try {
    switch (command) {
      case 'init': {
        if (!positionals[0] || !TEMPLATES.includes(values.template ?? '') || !values['plugin-id']) {
          console.error(USAGE)
          return 2
        }
        const files = scaffold(dir, { template: values.template, pluginID: values['plugin-id'], name: values.name })
        console.log(`已生成 ${values.template} 模板：${dir}`)
        for (const file of files) console.log(`  ${file}`)
        console.log('\n下一步：\n  cdnca-site-theme preview   本地沙箱预览\n  cdnca-site-theme pack      打包并生成 manifest')
        return 0
      }
      case 'check': {
        const raw = values.content ? readFileSync(resolve(values.content)) : Buffer.from(`${JSON.stringify(buildContent(dir).content)}\n`)
        const manifest = values.content ? undefined : JSON.parse(readFileSync(join(dir, 'plugin.manifest.json'), 'utf8'))
        const findings = checkContent(raw, { pluginID: manifest?.metadata?.id })
        if (findings.ok) {
          console.log(`预检通过（${raw.length} 字节）`)
          return 0
        }
        console.error(`预检发现 ${findings.items.length} 个问题：`)
        printFindings(findings.items)
        return 1
      }
      case 'preview': {
        const port = Number(values.port)
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
          console.error(USAGE)
          return 2
        }
        const server = createPreviewServer(dir, { contentFile: values.content && resolve(values.content) })
        await new Promise((ok) => server.listen(port, '127.0.0.1', ok))
        if (values.screenshot) {
          // 截首屏生成主题卡片预览图，然后退出（不常驻）。只有用户端的主题截登录页。
          const built = buildContent(dir).content
          const page = built.site_bundle ? '/' : '/dashboard/login'
          try {
            const shot = await captureScreenshot(`http://127.0.0.1:${port}${page}`, dir)
            console.log(`预览图    ${shot.path}  (${shot.bytes} 字节，上限 ${PREVIEW_MAX_BYTES})`)
            if (shot.oversize) console.error('注意：预览图超过 512 KiB，pack 预检会报 preview_size；请压缩后再打包')
            return shot.oversize ? 1 : 0
          } finally {
            server.close()
          }
        }
        console.log(`本地预览：http://127.0.0.1:${port}/  登录页样式：http://127.0.0.1:${port}/dashboard/login`)
        console.log('页面包挂在 /site/t/<id>/<version>/，带 CSP sandbox（origin 为 null）与 ACAO；违规请求与 CSP 报告会打印在这里。Ctrl+C 退出。')
        await new Promise(() => {})
        return 0
      }
      case 'pack': {
        if (values.sign && !values.key) {
          console.error('--sign 需要 --key <发布者私钥文件>')
          return 2
        }
        const out = pack(dir, { outDir: values.out && resolve(values.out), version: values.version })
        for (const path of out.skipped) console.error(`跳过隐藏文件：${path}`)
        if (out.findings.length) {
          console.error(`预检发现 ${out.findings.length} 个问题，未生成 manifest：`)
          printFindings(out.findings)
          return 1
        }
        console.log(`content   ${out.contentPath}`)
        console.log(`  sha256  ${out.contentSHA256}  (${out.contentBytes} 字节，上限 8388608)`)
        console.log(`schema    sha256 ${out.schemaSHA256}`)
        console.log(`manifest  ${out.manifestPath}`)
        for (const warning of out.warnings) console.error(`注意：${warning}`)
        if (out.previewPath) console.log(`preview   ${out.previewPath}`)
        for (const notice of out.notices) console.error(`提示：${notice}`)
        if (values.sign) {
          const signed = sign(out.manifestPath, values.key, values['cdnca-plugin'])
          console.log(`signed    ${signed}`)
        } else {
          console.log('\n签名：cdnca-plugin sign-manifest -key publisher.key -in dist/manifest.json -out dist/manifest.signed.json')
        }
        return 0
      }
      default:
        console.error(USAGE)
        return 2
    }
  } catch (error) {
    console.error(`cdnca-site-theme: ${error.message}`)
    return 1
  }
}

/**
 * 本模块是否就是 node 正在执行的入口脚本。两边都先 fileURLToPath / realpath 归一化再比较文件身份：
 * 经软链或目录别名（如 macOS /var → /private/var）调用、路径含空格或需要 URL 编码的字符、
 * 无扩展名的 bin 软链都能识别；被其他模块 import 时 argv[1] 是别的文件，不执行 main。
 */
export function isEntrypoint(moduleURL, argv1) {
  if (!argv1) return false
  try {
    return realpathSync(fileURLToPath(moduleURL)) === realpathSync(resolve(argv1))
  } catch {
    return false
  }
}

if (isEntrypoint(import.meta.url, process.argv[1])) {
  process.exitCode = await main(process.argv.slice(2))
}
