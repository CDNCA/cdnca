import { Form, Select, Space, type FormInstance } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'

import { securityPoliciesApi, type SecurityPolicyReference, type SecurityPolicyReferenceKind } from '../../api/securityPolicies'

// User filter types the nodes run (the server expands them like catalog filters; url_auth and projected legacy types are refused).
const runnableFilterTypes = ['req_rate', 'browser_verify_auto', 'five_second', 'click', 'simple_click', 'slider', 'simple_slider', 'captcha', 'rotate_image', '302_challenge']

async function listEnabled(accessToken: string, kind: SecurityPolicyReferenceKind, scopeId: string | undefined): Promise<SecurityPolicyReference[]> {
  const items: SecurityPolicyReference[] = []
  for (let page = 1; page <= 20; page++) {
    const result = await securityPoliciesApi.listReferences(accessToken, kind, { page, limit: 100, status: 'enabled', scope_id: scopeId })
    items.push(...result.items)
    if (result.items.length === 0 || items.length >= result.total) break
  }
  return items.filter((item) => !item.system_rule && (kind === 'matcher' || runnableFilterTypes.includes(item.type ?? '')))
}

/**
 * The enabled, user-made CC matchers and filters a reference rule may use:
 * the tenant's own (scopeId undefined), or (administrators) those of the
 * policy's target scope; none while it is '' (no target picked yet).
 */
export function useCCReferenceOptions(accessToken: string, scopeId: string | undefined, enabled: boolean) {
  const ready = enabled && Boolean(accessToken) && scopeId !== ''
  const matchers = useQuery({
    queryKey: ['security-policy-references', 'rule-options', 'matcher', scopeId ?? 'own'],
    enabled: ready, retry: false,
    queryFn: () => listEnabled(accessToken, 'matcher', scopeId),
  })
  const filters = useQuery({
    queryKey: ['security-policy-references', 'rule-options', 'filter', scopeId ?? 'own'],
    enabled: ready, retry: false,
    queryFn: () => listEnabled(accessToken, 'filter', scopeId),
  })
  return { matchers: ready ? matchers.data ?? [] : [], filters: ready ? filters.data ?? [] : [], loading: ready && (matchers.isLoading || filters.isLoading) }
}

export type CCReferenceOptions = ReturnType<typeof useCCReferenceOptions>

/** 规则来源「匹配器与过滤器」of one CC rule (Form.List item `ruleName`): matcher, filter 1, optional filter 2, action. */
export function CCReferenceRuleFields({ ruleName, form, options }: { ruleName: number; form: FormInstance; options: CCReferenceOptions }) {
  const { t } = useTranslation('securityPolicies')
  const path = (name: string) => ['rules', ruleName, 'cc_reference', name]
  // An unnamed rule takes「匹配器名 · 过滤器名」, so hit logs show what it is.
  const fillName = () => {
    const current = (form.getFieldValue(['rules', ruleName, 'name']) as string | undefined)?.trim()
    const matcher = options.matchers.find((item) => item.id === form.getFieldValue(path('matcher_id')))
    const filter = options.filters.find((item) => item.id === form.getFieldValue(path('filter1_id')))
    if (!current && matcher && filter) form.setFieldValue(['rules', ruleName, 'name'], `${matcher.name} · ${filter.name}`)
  }
  const choices = (items: SecurityPolicyReference[]) => items.map((item) => ({ value: item.id, label: item.name }))
  return (
    <Space size={10} wrap align="start">
      <Form.Item name={[ruleName, 'cc_reference', 'matcher_id']} label={t('cc.editor.matcher')} rules={[{ required: true, message: t('cc.editor.matcherRequired') }]}>
        <Select aria-label={t('cc.editor.matcher')} placeholder={t('cc.editor.matcherPlaceholder')} showSearch optionFilterProp="label" style={{ minWidth: 200 }}
          loading={options.loading} options={choices(options.matchers)} onChange={fillName} />
      </Form.Item>
      <Form.Item name={[ruleName, 'cc_reference', 'filter1_id']} label={t('cc.editor.filterOne')} rules={[{ required: true, message: t('cc.editor.filterRequired') }]}>
        <Select aria-label={t('cc.editor.filterOne')} placeholder={t('cc.editor.filterOnePlaceholder')} showSearch optionFilterProp="label" style={{ minWidth: 200 }}
          loading={options.loading} options={choices(options.filters)} onChange={fillName} />
      </Form.Item>
      <Form.Item name={[ruleName, 'cc_reference', 'filter2_id']} label={t('cc.editor.filterTwo')}>
        <Select aria-label={t('cc.editor.filterTwo')} placeholder={t('cc.editor.filterTwoPlaceholder')} allowClear showSearch optionFilterProp="label" style={{ minWidth: 200 }}
          loading={options.loading} options={choices(options.filters)} />
      </Form.Item>
      <Form.Item name={[ruleName, 'cc_reference', 'action']} label={t('cc.editor.action')} initialValue="block" rules={[{ required: true }]}>
        <Select aria-label={t('cc.editor.action')} style={{ width: 140 }}
          options={(['block', 'log'] as const).map((value) => ({ value, label: t(`actionsMap.${value}`) }))} />
      </Form.Item>
    </Space>
  )
}
