import i18n from './index'

const zhCN = {
  title: '关闭通知渠道会暂停用户的二次验证',
  email: '有 {{count}} 个用户设置了登录邮箱二次验证，渠道关闭期间这些用户无需验证码即可登录。',
  sms: '有 {{count}} 个用户设置了登录短信二次验证，渠道关闭期间这些用户无需验证码即可登录。',
  tail: '渠道重新开启后自动恢复。确认关闭吗？',
  ok: '确认关闭',
  cancel: '取消',
}

const enUS = {
  title: 'Switching this channel off suspends users\' second step',
  email: '{{count}} user(s) have an email second step at sign-in. While the channel is off they sign in without a code.',
  sms: '{{count}} user(s) have an SMS second step at sign-in. While the channel is off they sign in without a code.',
  tail: 'It resumes when the channel is switched on again. Switch it off?',
  ok: 'Switch off',
  cancel: 'Cancel',
}

for (const [locale, messages] of Object.entries({ 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': zhCN, 'qps-Ploc': zhCN })) {
  i18n.addResourceBundle(locale, 'channelDisableConfirm', messages, true, true)
}
