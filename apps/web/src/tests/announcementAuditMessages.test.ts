import { userLocales } from '../i18n'
import { observabilityLogCodeMessage } from '../i18n/observabilityLogs'

const actions = [
  'announcement.create', 'announcement.update', 'announcement.schedule', 'announcement.publish',
  'announcement.revise', 'announcement.withdraw', 'announcement.archive', 'announcement.restore',
  'announcement.deliver', 'announcement.read', 'announcement.global.create', 'announcement.global.update',
  'announcement.global.publish', 'announcement.global.withdraw', 'announcement.global.archive', 'announcement.global.restore',
]

it.each(userLocales)('localizes actual announcement action and reason codes in %s', (locale) => {
  for (const action of actions) {
    const label = observabilityLogCodeMessage(locale, 'action', action)
    expect(label).not.toBe(observabilityLogCodeMessage(locale, 'action', 'unrecognized.action'))
    expect(label).not.toBe(action)
    expect(observabilityLogCodeMessage(locale, 'reason', action)).toBe(label)
  }
})

// log-merge: the resource / field / state labels belonged to the removed
// SystemLogPage operation table; the log center shows server-rendered text.
it.each([
  ['zh-CN', '归档全局公告', '恢复全局公告'],
  ['zh-TW', '封存全域公告', '還原全域公告'],
  ['en-US', 'Archive global announcement', 'Restore global announcement'],
] as const)('renders global archive actions with exact %s labels', (locale, archive, restore) => {
  expect(observabilityLogCodeMessage(locale, 'action', 'announcement.global.archive')).toBe(archive)
  expect(observabilityLogCodeMessage(locale, 'action', 'announcement.global.restore')).toBe(restore)
})

it('keeps announcement pseudo-localization confined to its test locale', () => {
  expect(userLocales).toEqual(['zh-CN', 'zh-TW', 'en-US'])
  for (const action of actions) {
    const pseudo = observabilityLogCodeMessage('qps-Ploc', 'action', action)
    expect(pseudo).not.toBe(observabilityLogCodeMessage('en-US', 'action', action))
    expect(pseudo).not.toBe(observabilityLogCodeMessage('qps-Ploc', 'action', 'unrecognized.action'))
    expect(pseudo).toBe(observabilityLogCodeMessage('QPS-PLOC', 'reason', action))
  }
})
