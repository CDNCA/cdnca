import i18n from './index'

const messages = {
  'zh-CN': {
    editor: {
      targetScopePlaceholder: '小写租户作用域 UUID',
      ownerPlaceholder: '所属用户 UUID',
    },
    evaluate: {
      ja4: 'JA4 指纹',
      ja4Placeholder: '输入 JA4 指纹',
    },
    headersCanonicalHint: '同名请求头的全部值均会保留；字段名按小写规范化。',
    headersInvalid: '请求头必须使用 Name: Value，每个值不超过 4096 字节，最多 100 个值。',
  },
  'en-US': {
    editor: {
      targetScopePlaceholder: 'Canonical lowercase tenant scope UUID',
      ownerPlaceholder: 'Owner user UUID',
    },
    evaluate: {
      ja4: 'JA4 fingerprint',
      ja4Placeholder: 'Enter a JA4 fingerprint',
    },
    headersCanonicalHint: 'All repeated-header values are retained and names are normalized to lowercase.',
    headersInvalid: 'Use Name: Value, at most 4096 bytes per value and 100 values in total.',
  },
} as const

for (const [locale, values] of Object.entries(messages)) {
  i18n.addResourceBundle(locale, 'securityPolicies', {
    editor: values.editor,
    evaluate: {
      ...values.evaluate,
      headersCanonicalHint: values.headersCanonicalHint,
      headersInvalid: values.headersInvalid,
    },
  }, true, true)
}

i18n.addResourceBundle('qps-ploc', 'securityPolicies', { editor: {
  targetScopePlaceholder: `［${messages['zh-CN'].editor.targetScopePlaceholder}］`,
  ownerPlaceholder: `［${messages['zh-CN'].editor.ownerPlaceholder}］`,
}, evaluate: {
  ja4: `［${messages['zh-CN'].evaluate.ja4}］`,
  ja4Placeholder: `［${messages['zh-CN'].evaluate.ja4Placeholder}］`,
  headersCanonicalHint: `［${messages['zh-CN'].headersCanonicalHint}］`,
  headersInvalid: `［${messages['zh-CN'].headersInvalid}］`,
} }, true, true)
i18n.addResourceBundle('qps-Ploc', 'securityPolicies', { editor: {
  targetScopePlaceholder: `［${messages['zh-CN'].editor.targetScopePlaceholder}］`,
  ownerPlaceholder: `［${messages['zh-CN'].editor.ownerPlaceholder}］`,
}, evaluate: {
  ja4: `［${messages['zh-CN'].evaluate.ja4}］`,
  ja4Placeholder: `［${messages['zh-CN'].evaluate.ja4Placeholder}］`,
  headersCanonicalHint: `［${messages['zh-CN'].headersCanonicalHint}］`,
  headersInvalid: `［${messages['zh-CN'].headersInvalid}］`,
} }, true, true)
