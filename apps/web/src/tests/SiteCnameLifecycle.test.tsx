import { describe, expect, it } from 'vitest'
import api from '../api/sites.ts?raw'
import editor from '../pages/site-edit/BasicSiteTab.tsx?raw'
import creator from '../pages/SiteListPage.tsx?raw'

describe('site CNAME lifecycle contract', () => {
  it('carries sold subscription and durable CNAME state through API and UI', () => {
    for (const field of ['package_subscription_id', 'cname_state', 'cname_task_id', 'cname_current_revision', 'cname_lkg_revision']) {
      expect(api).toContain(field)
    }
    // 已售套餐订阅在「添加网站」时绑定，创建结果里展示 CNAME 分配任务 ID（SiteListPage）；
    // 编辑页「基本信息」展示持久化的 CNAME 状态并允许失败后重新分配（BasicSiteTab）。
    expect(creator).toContain('package_subscription_id')
    expect(creator).toContain('cname_task_id')
    expect(editor).toContain('cname_state')
    expect(editor).toContain('cname_regenerate')
  })
})
