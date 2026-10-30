import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

import { jobsApi, kindNameKeys } from '../api/jobs'
import { adminTaskFactMessages } from '../i18n/adminTasksParity'

// 契约：服务端 integratedKinds（kinds.go）与前端 kindNameKeys 必须逐项相等，
// 任一侧新增 kind 漏改另一侧时，后台任务弹窗会整表判为“服务响应无效”。
const kindsGo = readFileSync(
  resolve(__dirname, '../../../../services/control-api/internal/jobhttp/kinds.go'),
  'utf8',
)
const serverKinds = [...kindsGo.matchAll(/\{Kind: "([^"]+)", NameKey: "([^"]+)"\}/g)]
  .map(([, kind, nameKey]) => ({ kind, nameKey }))

describe('job kinds contract', () => {
  it('parses the server kind list from kinds.go', () => {
    expect(serverKinds.length).toBeGreaterThan(0)
    expect(serverKinds.some((entry) => entry.kind === 'dns.cname.stream_intent')).toBe(true)
  })

  it('front-end kindNameKeys equals the server integratedKinds entry by entry', () => {
    const server = Object.fromEntries(serverKinds.map((entry) => [entry.kind, entry.nameKey]))
    expect(kindNameKeys).toEqual(server)
  })

  it('every server name_key has zh-CN and en-US text', () => {
    for (const { nameKey } of serverKinds) {
      const key = nameKey.replace(/^jobs\.kindNames\./, '') as keyof typeof adminTaskFactMessages['zh-CN']['kindNames']
      expect(adminTaskFactMessages['zh-CN'].kindNames[key], nameKey).toBeTruthy()
      expect(adminTaskFactMessages['en-US'].kindNames[key], nameKey).toBeTruthy()
    }
  })

  it('accepts the exact catalog the server returns', async () => {
    const response = {
      data: serverKinds.map(({ kind, nameKey }) => ({
        kind, name_key: nameKey, integration: 'integrated', runtime_status: 'unknown',
      })),
    }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(response), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    }))
    await expect(jobsApi.kinds('token', 'platform')).resolves.toEqual(response)
    vi.restoreAllMocks()
  })
})
