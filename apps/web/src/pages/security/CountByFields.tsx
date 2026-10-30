import { Checkbox, Form, Input, InputNumber, Select, Space, Typography, type FormInstance } from 'antd'
import { useTranslation } from 'react-i18next'

import type { SecurityPolicyCountKeyName, SecurityPolicyRule } from '../../api/securityPolicies'
import '../../i18n/securityPoliciesCountBy'
import { countByFromForm, countByPreview, countByProblem, countKeyOrder, defaultCountPrefix, namedCountKeys, v7CountKeys, type CountNames, type CountPrefix } from './countBy'

/**
 * 统计对象 of one CC rule (Form.List item `ruleName`): what requests are
 * counted by (one or two keys, client_cidr with its prefixes) and, for a
 * temporary ban, whether to ban the whole counted key. Form values:
 * count_keys / count_prefix / count_names / action_target (countByFromForm
 * turns the first three into count_by).
 */
export function CountByFields({ ruleName, form }: { ruleName: number; form: FormInstance }) {
  const { t } = useTranslation('securityPolicies')
  const path = (...names: string[]) => ['rules', ruleName, ...names]
  return (
    <Form.Item noStyle shouldUpdate>
      {({ getFieldValue }) => {
        const keys = (getFieldValue(path('count_keys')) as SecurityPolicyCountKeyName[] | undefined) ?? []
        const prefix = getFieldValue(path('count_prefix')) as CountPrefix | undefined
        const names = getFieldValue(path('count_names')) as CountNames | undefined
        const rule = getFieldValue(['rules', ruleName]) as SecurityPolicyRule & { count_keys?: SecurityPolicyCountKeyName[] }
        const countBy = countByFromForm(keys, prefix, names)
        const banning = rule?.action === 'rate_limit' && rule.action_config?.rate_limit?.response_action === 'temporary_ban'
        const preview = rule ? countByPreview(t, { ...rule, count_by: countBy }) : undefined
        return (
          <Space direction="vertical" size={4} style={{ width: '100%' }}>
            <Space size={10} wrap align="start">
              <Form.Item
                name={[ruleName, 'count_keys']} label={t('countBy.label')} tooltip={t('countBy.help')}
                rules={[{
                  validator: (_, value: SecurityPolicyCountKeyName[] | undefined) => {
                    const current = form.getFieldValue(['rules', ruleName]) as SecurityPolicyRule
                    const problem = countByProblem({ ...current, count_by: countByFromForm(value, prefix, names) }, value)
                    return problem ? Promise.reject(new Error(t(`countBy.problems.${problem}`))) : Promise.resolve()
                  },
                }]}
              >
                <Select
                  mode="multiple" virtual={false} aria-label={t('countBy.label')} placeholder={t('countBy.placeholder')} style={{ minWidth: 260 }}
                  options={countKeyOrder.map((value) => ({ value, label: t(`countBy.keys.${value}`) }))}
                  onChange={() => form.setFieldValue(path('action_target'), undefined)}
                />
              </Form.Item>
              {keys.includes('client_cidr') ? <>
                <Form.Item name={[ruleName, 'count_prefix', 'ipv4_prefix']} label={t('countBy.ipv4Prefix')} initialValue={defaultCountPrefix.ipv4_prefix}
                  rules={[{ required: true, type: 'number', min: 8, max: 32 }]}>
                  <InputNumber aria-label={t('countBy.ipv4Prefix')} min={8} max={32} precision={0} />
                </Form.Item>
                <Form.Item name={[ruleName, 'count_prefix', 'ipv6_prefix']} label={t('countBy.ipv6Prefix')} initialValue={defaultCountPrefix.ipv6_prefix}
                  rules={[{ required: true, type: 'number', min: 32, max: 128 }]}>
                  <InputNumber aria-label={t('countBy.ipv6Prefix')} min={32} max={128} precision={0} />
                </Form.Item>
              </> : null}
              {namedCountKeys.filter((key) => keys.includes(key)).map((key) => (
                <Form.Item key={key} name={[ruleName, 'count_names', key]} label={t(`countBy.names.${key}`)}
                  rules={[{ required: true, whitespace: true },
                    { pattern: key === 'header' ? /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$/ : /^[A-Za-z0-9_.:[\]-]{1,128}$/, message: t('countBy.nameInvalid') }]}>
                  <Input aria-label={t(`countBy.names.${key}`)} placeholder={t(`countBy.namePlaceholders.${key}`)} style={{ width: 160 }} />
                </Form.Item>
              ))}
              {banning && countBy ? (
                <Form.Item name={[ruleName, 'action_target']} tooltip={t('countBy.targetHelp')}
                  getValueProps={(value) => ({ checked: value === 'count_key' })}
                  getValueFromEvent={(event) => (event.target.checked ? 'count_key' : undefined)}>
                  <Checkbox>{t('countBy.target')}</Checkbox>
                </Form.Item>
              ) : null}
            </Space>
            {countBy ? <Typography.Text type="secondary">{t('countBy.nodeHelp')}</Typography.Text> : null}
            {keys.includes('ja4') ? <Typography.Text type="secondary">{t('countBy.ja4Help')}</Typography.Text> : null}
            {keys.some((key) => v7CountKeys.includes(key)) ? <Typography.Text type="secondary">{t('countBy.v7Help')}</Typography.Text> : null}
            {preview ? <Typography.Text>{preview}</Typography.Text> : null}
          </Space>
        )
      }}
    </Form.Item>
  )
}
