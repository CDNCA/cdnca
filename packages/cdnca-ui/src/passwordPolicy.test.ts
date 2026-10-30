import { describe, expect, it } from 'vitest'
import { checkPassword, PASSWORD_SYMBOLS, passwordPolicyLocale, passwordPolicyMessage, passwordPolicyRule, passwordPolicyUnmetOf } from './passwordPolicy'

// Same cases as libs/passwordpolicy/passwordpolicy_test.go.
describe('checkPassword', () => {
  it.each([
    ['7 位拒绝', 'Abc1234', ['length']],
    ['8 位纯数字拒绝', '12345678', ['character_classes']],
    ['8 位纯小写拒绝', 'abcdefgh', ['character_classes']],
    ['字母加数字通过', 'abcd1234', []],
    ['大小写通过', 'abcdEFGH', []],
    ['符号加数字通过', '!@#$1234', []],
    ['全部符号均可用', PASSWORD_SYMBOLS + 'a', []],
    ['含空格拒绝', 'abcd 1234', ['invalid_character']],
    ['含中文拒绝', 'abcd1234密码', ['invalid_character']],
    ['含全角拒绝', 'abcd１２３４', ['character_classes', 'invalid_character']],
    ['含 emoji 拒绝', 'abcd1234😀', ['invalid_character']],
    ['含制表符拒绝', 'abcd\t1234', ['invalid_character']],
    ['含 DEL 拒绝', 'abcd1234\x7f', ['invalid_character']],
    ['空串', '', ['length', 'character_classes']],
    ['1024 字节通过', 'a1'.repeat(512), []],
    ['1025 字节拒绝', 'a1'.repeat(512) + 'b', ['length']],
    ['短且单类且非法', 'a 1', ['length', 'invalid_character']],
  ])('%s', (_name, password, unmet) => {
    expect(checkPassword(password)).toEqual(unmet)
  })
})

describe('passwordPolicyRule', () => {
  it('rejects with the first unmet message and accepts a valid password', async () => {
    const rule = passwordPolicyRule()
    await expect(rule.validator(undefined, '12345678')).rejects.toThrow(passwordPolicyMessage(['character_classes']))
    await expect(rule.validator(undefined, 'abcd1234')).resolves.toBeUndefined()
    await expect(rule.validator(undefined, '')).resolves.toBeUndefined()
  })
})

describe('helpers', () => {
  it('maps locales and reads a server error body', () => {
    expect(passwordPolicyLocale('en')).toBe('en-US')
    expect(passwordPolicyLocale(undefined)).toBe('zh-CN')
    expect(passwordPolicyUnmetOf({ error: { code: 'password_policy_unmet', details: { unmet: ['length', 'x'] } } })).toEqual(['length'])
    expect(passwordPolicyUnmetOf({ code: 'password_policy_unmet', details: { unmet: ['invalid_character'] } })).toEqual(['invalid_character'])
    expect(passwordPolicyUnmetOf({ code: 'invalid_request' })).toBeUndefined()
  })
})
