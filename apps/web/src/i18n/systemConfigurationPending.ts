import i18n from './index'

// fix-sysconfig: all system configuration categories share one revision stream; a
// category page warns about, and confirms, the other categories activated together.
export const systemConfigurationPendingNamespace = 'systemConfigurationPending'

const zhCN = {
  categories: {
    nginx: 'Nginx 配置', defaults: '默认配置', resources: '资源配置', error_pages: '错误页面配置',
    secrets: '敏感引用配置', node_monitoring: '节点监控', ddos_protection: '连接防护', access_log_fields: '访问日志字段',
  },
  notice: {
    title: '其他分类还有未生效的修改',
    description: '系统配置各分类共用一个版本，在本页检查并启用时会一并生效：{{categories}}',
  },
  confirm: {
    title: '确认一并生效其他分类的修改',
    description: '本次还会一并生效：{{categories}}。请确认这些修改无误后再继续。',
    ok: '确认并继续',
    cancel: '取消',
  },
  view: '去查看',
  scope: {
    title: '作用范围：全部节点的全局默认值（「区域配置」页签可按区域覆盖）',
    description: '保存方式：本页全部字段点「保存」一次提交，只生成新草稿，节点仍按已生效版本运行；要生效请到「节点监控」或「连接防护」页检查并启用（各分类共用一个版本，会一并生效）。',
  },
}

const enUS: typeof zhCN = {
  categories: {
    nginx: 'Nginx', defaults: 'Defaults', resources: 'Resources', error_pages: 'Error pages',
    secrets: 'Sensitive references', node_monitoring: 'Node monitoring', ddos_protection: 'Connection protection', access_log_fields: 'Access log fields',
  },
  notice: {
    title: 'Other categories have changes that are not active yet',
    description: 'All system configuration categories share one revision. Checking and activating here also makes these effective: {{categories}}',
  },
  confirm: {
    title: 'Also make other categories effective?',
    description: 'This will also make effective: {{categories}}. Review those changes before continuing.',
    ok: 'Confirm and continue',
    cancel: 'Cancel',
  },
  view: 'View',
  scope: {
    title: 'Applies to: the global defaults of every node (the region tab overrides them per region)',
    description: 'Saving: Save submits every field on this page as one new draft; nodes keep running the active revision. To make it effective, check and activate it on the Node monitoring or Connection protection page (all categories share one revision and become effective together).',
  },
}

for (const [locale, messages] of Object.entries({ 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': zhCN, 'qps-Ploc': zhCN })) {
  i18n.addResourceBundle(locale, systemConfigurationPendingNamespace, messages, true, true)
}
