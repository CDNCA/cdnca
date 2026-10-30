import { ApiError, networkApiError, responseApiError } from './auth'

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

export type SystemRuleKind = 'cc_rule_group' | 'cc_matcher' | 'cc_filter' | 'waf_rule_set'

export interface SystemRuleGroupEntry {
  matcher_key: string
  filter1_key: string
  filter2_key: string
  action: 'block' | 'allow' | 'log'
  mode: 'break' | 'continue'
  enabled: boolean
}

export interface SystemRuleBody {
  cc_rule_group?: { entries: SystemRuleGroupEntry[] }
  cc_matcher?: { conditions: Array<{ field: string; operator: string; key: string; values: string[] }> }
  cc_filter?: { type: string; within_second: number; max_req: number; max_req_per_uri: number; extra: Record<string, string>
    params?: { ban_seconds: number; pass_seconds?: number; pow_bits?: number; delay_seconds?: number; challenge_seconds?: number
      bind_ipv4_prefix?: number; bind_ipv6_prefix?: number; key_rotate_seconds?: number } }
  waf_rule_set?: {
    rules?: Array<{ id: string; name: string; enabled: boolean; action: string;
      matcher_groups: Array<{ id: string; matchers: Array<{ field: string; operator: string; key: string; transform: string; value: string }> }> }>
    engine?: { engine: string; files: string[]; include_ids: number[]; exclude_ids: number[]; action: 'block' | 'log'; paranoia: number; threshold: number }
    settings?: { engine: string; request_body_limit: number; request_body_no_files_limit: number; request_body_limit_action: string
      arguments_limit: number; json_depth_limit: number; pcre_match_limit: number }
    bundle?: { engine: string; version: string; files: Array<{ name: string; sha256: string; gzip: string }> }
  }
}

export interface SystemRule {
  system_key: string
  kind: SystemRuleKind
  legacy_id: string
  name: string
  description: string
  sort: number
  revision: number
  body: SystemRuleBody
  status: 'active' | 'withdrawn'
  selectable: boolean
  enabled: boolean
  visibility?: { visible: boolean; show_to_scope_ids: string[]; revision: number }
  updated_at: string
}

async function request<T>(token: string, path: string, init: RequestInit = {}): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${token}`,
        'X-Request-ID': crypto.randomUUID(),
        ...(init.body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  try {
    return await response.json() as T
  } catch {
    throw new ApiError('invalid response', 502, 'invalid_response')
  }
}

/** A CRS rule text change being republished to the caller's scopes (all
 * scopes for a platform admin). */
export interface SystemRuleRepublication {
  pending: boolean
  pending_scopes: number
}

/** One default trusted crawler (platform list with the official IP ranges
 * the license service fetched); ready = it can verify (networks or rDNS). */
export interface DefaultCrawler {
  name: string
  members: string[]
  categories: string[]
  user_agent_tokens: string[]
  networks: string[]
  rdns_suffixes: string[]
  ready: boolean
}

export const securitySystemRulesApi = {
  defaultCrawlers: (token: string) =>
    request<{ items: DefaultCrawler[] }>(token, '/v1/security-system-rules/default-crawlers').then((result) => result.items ?? []),
  republication: (token: string) => request<SystemRuleRepublication>(token, '/v1/security-system-rules/republication')
    .then((value) => ({ pending: value?.pending === true,
      pending_scopes: Number.isSafeInteger(value?.pending_scopes) && value.pending_scopes > 0 ? value.pending_scopes : 0 })),
  list: (token: string, kind: SystemRuleKind) =>
    request<{ items: SystemRule[] }>(token, `/v1/security-system-rules?kind=${kind}`).then((result) => result.items ?? []),
  setEnabled: (token: string, key: string, enabled: boolean) =>
    request<SystemRule>(token, `/v1/security-system-rules/${encodeURIComponent(key)}/${enabled ? 'enable' : 'disable'}`, { method: 'POST' }),
  setVisibility: (token: string, key: string, visible: boolean, showTo: string[]) =>
    request<SystemRule>(token, `/v1/security-system-rules/${encodeURIComponent(key)}/visibility`, {
      method: 'PUT', body: JSON.stringify({ visible, show_to_scope_ids: showTo }),
    }),
}
