// 节点管理 > DNS配置 provider choices in the competitor's order, with the
// ID / Token labels it shows and our credential contract (api/dns.ts).

export type ProviderChoice = 'aliyun' | 'huawei' | 'dns_la' | 'dnspod_cn' | 'dnspod_intl' | 'dns_com' | 'cloudflare' | 'namecom' | 'custom_http' | 'plugin'

export interface ProviderSpec {
  // [ID label, Token label]; Cloudflare has no ID field (API Token only).
  labels: [string, string]
  identifier?: string
  secret: string
  minTTL: number
  maxTTL: number
  supported: boolean
  // DNS lines the adapter writes (dnsproviderremote.SupportedLines):
  // all = 默认/电信/联通/移动/境外, none = 默认 only, plan = by the
  // DNS.COM plan tier (dnsproviderremote.DNSComPlanLines).
  lines: 'all' | 'none' | 'plan'
}

export const providerChoices: ProviderChoice[] = ['aliyun', 'huawei', 'dns_la', 'dnspod_cn', 'dnspod_intl', 'dns_com', 'cloudflare', 'namecom', 'custom_http']
export const huaweiRegions = ['cn-north-4', 'ap-southeast-3']
// DNS.COM plan tiers (credential field "plan"; absent = free).
export const dnsComPlans = ['free', 'enterprise', 'flagship'] as const
export type DNSComPlan = typeof dnsComPlans[number]

export function dnsComPlanOf(value: string | undefined): DNSComPlan {
  return dnsComPlans.find((plan) => plan === value) ?? 'free'
}

// dnsComPlanLineHint is the hints.lines key of a DNS.COM plan.
export function dnsComPlanLineHint(plan: DNSComPlan): string {
  return `dnsCom${plan[0].toUpperCase()}${plan.slice(1)}`
}

// TTL ranges every plan of the provider accepts at most; Cloudflare's lowest
// non-automatic TTL is 60 seconds. Paid-plan minimums are enforced by the
// provider itself when records are written.
export const providerSpecs: Record<ProviderChoice, ProviderSpec> = {
  aliyun: { labels: ['AccessKey ID', 'AccessKey Secret'], identifier: 'access_key_id', secret: 'access_key_secret', minTTL: 1, maxTTL: 86400, supported: true, lines: 'all' },
  huawei: { labels: ['Access Key Id', 'Secret Access Key'], identifier: 'access_key', secret: 'secret_key', minTTL: 1, maxTTL: 86400, supported: true, lines: 'all' },
  dns_la: { labels: ['APIID', 'API密钥'], identifier: 'api_id', secret: 'api_secret', minTTL: 1, maxTTL: 86400, supported: true, lines: 'all' },
  dnspod_cn: { labels: ['ID', 'Token'], identifier: 'dp_id', secret: 'dp_key', minTTL: 1, maxTTL: 86400, supported: true, lines: 'all' },
  dnspod_intl: { labels: ['ID', 'Token'], identifier: 'dp_id', secret: 'dp_key', minTTL: 1, maxTTL: 86400, supported: false, lines: 'none' },
  dns_com: { labels: ['API Key', 'API Secret'], identifier: 'api_key', secret: 'api_secret', minTTL: 1, maxTTL: 86400, supported: true, lines: 'plan' },
  cloudflare: { labels: ['', 'API Token'], secret: 'api_token', minTTL: 60, maxTTL: 86400, supported: true, lines: 'none' },
  // name.com Core API: Basic username + API token; TTL floor 300; no lines.
  namecom: { labels: ['Username', 'API Token'], identifier: 'username', secret: 'api_token', minTTL: 300, maxTTL: 86400, supported: true, lines: 'none' },
  custom_http: { labels: ['接口地址', '签名密钥'], identifier: 'endpoint', secret: 'secret', minTTL: 1, maxTTL: 86400, supported: true, lines: 'all' },
  // Third-party DNS plugins (PA-22): no secret, the plugin is chosen by id.
  plugin: { labels: ['', ''], secret: '', minTTL: 1, maxTTL: 86400, supported: true, lines: 'all' },
}

// Select values of third-party DNS plugins: plugin:<plugin id>.
export const pluginChoicePrefix = 'plugin:'

export function pluginChoice(pluginID: string): string {
  return pluginChoicePrefix + pluginID
}

// pluginCredentials is the provider_type plugin credential set.
export function pluginCredentials(value: string): Record<string, string> | null {
  if (!value.startsWith(pluginChoicePrefix)) return null
  const pluginID = value.slice(pluginChoicePrefix.length)
  return /^[a-z0-9]+(?:[.-][a-z0-9]+)+$/.test(pluginID) ? { plugin_id: pluginID } : null
}

export interface CredentialFields {
  identifier: string
  secret: string
  region: string
  projectID: string
  plan?: string
}

// dnsConfigCredentials maps the form to the provider's credential fields, or
// null when a required field is missing.
export function dnsConfigCredentials(type: ProviderChoice, form: CredentialFields): Record<string, string> | null {
  const spec = providerSpecs[type]
  const identifier = form.identifier.trim()
  const secret = form.secret.trim()
  if (!spec.supported || !secret || (spec.identifier && !identifier)) return null
  const credentials: Record<string, string> = { [spec.secret]: secret }
  if (spec.identifier) credentials[spec.identifier] = identifier
  if (type === 'huawei') {
    if (!huaweiRegions.includes(form.region) || !/^[a-f0-9]{32}$/.test(form.projectID.trim())) return null
    credentials.region = form.region
    credentials.project_id = form.projectID.trim()
  }
  if (type === 'dns_com') credentials.plan = dnsComPlanOf(form.plan)
  return credentials
}

export function validTTL(type: ProviderChoice, value: string): boolean {
  const spec = providerSpecs[type]
  if (!/^\d+$/.test(value.trim())) return false
  const ttl = Number(value)
  return ttl >= spec.minTTL && ttl <= spec.maxTTL
}
