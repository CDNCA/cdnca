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
  current: { pending: '本分类有已保存、尚未生效的修改。', activate: '去节点监控检查并启用' },
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
  current: { pending: 'This category has saved changes that are not active yet.', activate: 'Check and activate in Node monitoring' },
}

for (const [locale, messages] of Object.entries({ 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': zhCN, 'qps-Ploc': zhCN })) {
  i18n.addResourceBundle(locale, systemConfigurationPendingNamespace, messages, true, true)
}
