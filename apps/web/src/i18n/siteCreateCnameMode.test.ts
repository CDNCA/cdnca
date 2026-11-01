import i18n from './index'
import './siteCreate'

// 添加网站对话框 CNAME 一栏原写「分配模式按套餐生成」，而 cname_mode=package 的标签也叫「按套餐生成」，
// 实测建站 API 回读 cname_mode=site 被读成不一致。后端（site/store.go prepareCNAMEWriteIntent）按订阅快照
// per_site→site、shared→package 填充，无套餐只许 site。说明里写明这条对应，不再出现与 package 模式同名的含混说法。
describe('siteCreate cnamePackage', () => {
  it('states that the read-back mode follows the package snapshot (per_site→site, shared→package)', () => {
    const zh = i18n.getResource('zh-CN', 'siteCreate', 'cnamePackage.value') as string
    expect(zh).toContain('按网站生成')
    expect(zh).toMatch(/site（每个网站一条/)
    expect(zh).toMatch(/package（同一套餐共用一条）/)
    expect(zh).not.toContain('分配模式按套餐生成')
    const en = i18n.getResource('en-US', 'siteCreate', 'cnamePackage.value') as string
    expect(en).toContain('reads back as mode site')
    expect(en).toContain('reads back as package')
  })
})
