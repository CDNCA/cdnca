import { networkApiError, responseApiError } from './auth'

// Third-party provider plugins (PA-22, /v1/admin/plugin-providers): DNS / SMS
// / ICP plugins with their installation contract results. A plugin can be
// enabled only after its contract passed, and only a usable one can be
// chosen (e.g. as the DNS provider).

export type ProviderKind = 'dns' | 'sms' | 'icp' | 'payment' | 'mail'
export type ContractStatus = 'pending' | 'passed' | 'failed'

export interface ContractCase {
  kind: ProviderKind
  id: string
  passed: boolean
  code?: string
}

export interface ContractReport {
  version: string
  passed: boolean
  cases: ContractCase[]
  duration_ms: number
}

export interface PluginProvider {
  plugin_id: string
  version: string
  base_url: string
  kinds: ProviderKind[]
  status: 'active' | 'withdrawn'
  contract_status: ContractStatus
  contract_version?: string
  contract_checked_at?: string
  contract_report?: ContractReport
  enabled: boolean
  usable: boolean
  updated_at: string
  // PA-23: a payment plugin is a high-risk permission. Enabling it needs the
  // acknowledged risk_notice and an MFA step-up for tenant_id (audience and
  // action paymentStepUpAction).
  high_risk?: boolean
  risk_notice?: string
  tenant_id?: string
  payment_confirmed_at?: string
}

export const paymentStepUpAction = 'plugin.provider.enable_payment'

export interface EnableConfirmation {
  risk_acknowledged: boolean
  step_up_token: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

async function request<T>(accessToken: string, path: string, init: RequestInit = {}): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: { Authorization: `Bearer ${accessToken}`, 'X-Request-ID': crypto.randomUUID(), ...init.headers },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  return (await response.json()) as T
}

export const pluginProvidersApi = {
  async list(accessToken: string): Promise<PluginProvider[]> {
    const page = await request<{ items: PluginProvider[] }>(accessToken, '/v1/admin/plugin-providers')
    return page.items
  },
  action(accessToken: string, pluginID: string, action: 'contract' | 'enable' | 'disable',
    confirmation?: EnableConfirmation): Promise<PluginProvider> {
    return request(accessToken, `/v1/admin/plugin-providers/${encodeURIComponent(pluginID)}/${action}`, {
      method: 'POST',
      ...(confirmation ? { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(confirmation) } : {}),
    })
  },
}

// paymentPlugins are the payment provider plugins (shown on the payment
// channel page); usablePaymentPlugins can back a plugin channel.
export function paymentPlugins(providers: PluginProvider[]): PluginProvider[] {
  return providers.filter((provider) => provider.kinds.includes('payment'))
}

export function usablePaymentPlugins(providers: PluginProvider[]): PluginProvider[] {
  return paymentPlugins(providers).filter((provider) => provider.usable)
}

// usableDNSPlugins are the DNS plugins an administrator may choose as the
// DNS provider.
export function usableDNSPlugins(providers: PluginProvider[]): PluginProvider[] {
  return providers.filter((provider) => provider.usable && provider.kinds.includes('dns'))
}

// usableMailPlugins are the mail plugins an administrator may choose as the
// system mail sender (system settings → mail).
export function usableMailPlugins(providers: PluginProvider[]): PluginProvider[] {
  return providers.filter((provider) => provider.usable && provider.kinds.includes('mail'))
}
