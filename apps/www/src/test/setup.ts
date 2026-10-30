import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach, vi } from 'vitest'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

// 测试与预渲染一致：接口目录同步可用。
import { setCatalog, setGroupDetails, type ApiCatalog, type ApiGroupDetail } from '../content/apiCatalog'
import catalog from '../generated/api-catalog.json'
setCatalog(catalog as ApiCatalog)
setGroupDetails(Object.values(import.meta.glob<ApiGroupDetail>('../generated/api-operations/*.json', { eager: true, import: 'default' })))
