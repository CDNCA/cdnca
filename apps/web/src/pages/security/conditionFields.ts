import type { TFunction } from 'i18next'

import '../../i18n/securityPoliciesConditionFields'

// Rule condition fields grouped in the field
// dropdown, each with a one-line help (i18n conditionFields.help.<field>).
export type ConditionFieldGroup = 'basic' | 'client' | 'content' | 'fingerprint' | 'geo'

const groupOf: Record<string, ConditionFieldGroup> = {
  path: 'basic', method: 'basic', host: 'basic', port: 'basic', http_version: 'basic', request_uri: 'basic', uri_length: 'basic',
  client_ip: 'client', ip_list: 'client', distinct_user_agents: 'client', status_404_count: 'client',
  ja4: 'fingerprint',
  country: 'geo', asn: 'geo', province: 'geo', city: 'geo', carrier: 'geo', ip_tag: 'geo',
}
const groupOrder: ConditionFieldGroup[] = ['basic', 'client', 'content', 'fingerprint', 'geo']

/** WAF fields looked up in the node's IP intelligence library (IP_INTEL v2). */
export const wafGeoFields = ['country', 'asn', 'province', 'city', 'carrier', 'ip_tag']
/** Equality fields (no free text): one value or a set, one per line. */
export const wafSetFields = ['ja4', ...wafGeoFields]
// A list of one is equals; stored equals / not_equals conditions stay listed.
export const wafSetOperators = ['in', 'not_in', 'equals', 'not_equals']
/** ja4 equals / in (WAFMatch.JA4, JA4 v1); not_in (WAFMatch.NotJA4) also needs WAF_JA4_NEGATION. */
export const wafJA4Operators = ['in', 'not_in', 'equals']

/** Grouped Select options for the given fields, in their listed order within a group. */
export function groupedFieldOptions(t: TFunction<'securityPolicies'>, fields: string[]) {
  return groupOrder
    .map((group) => ({
      label: t(`conditionFields.groups.${group}`),
      options: fields.filter((field) => (groupOf[field] ?? 'content') === group).map((field) => ({
        value: field, label: t(`fields.${field}`), title: t(`conditionFields.help.${field}`, { defaultValue: '' }) || undefined,
      })),
    }))
    .filter((group) => group.options.length > 0)
}

// edgeconfig.JA4Pattern: what the native module emits.
const ja4Pattern = /^[tqd](?:1[0-3]|s[23]|d[1-3]|00)[di][0-9]{4}[0-9A-Za-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$/

/** The values (one per line) that are not a JA4 fingerprint. */
export function invalidJA4Values(values: string[]): string[] {
  return values.filter((value) => !ja4Pattern.test(value))
}

/** Value placeholder for a field (examples of the canonical form). */
export function conditionValuePlaceholder(t: TFunction<'securityPolicies'>, field: string): string | undefined {
  return wafSetFields.includes(field) ? t(`conditionFields.placeholder.${field}`) : undefined
}
