import { ApiError, networkApiError, responseApiError } from './auth'

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

// Rule packs (cdnca.rule-pack/v1, ADR 0007 §5.4): "download" (import) is
// separate from "enable"; enablement inherits platform -> tenant -> site in
// three states, per pack and per exported rule.
export type RulePackLevel = 'platform' | 'tenant' | 'site'
export type RulePackState = 'inherit' | 'enabled' | 'disabled'

export interface LevelRef { level: RulePackLevel | 'default'; object_id?: string }

export interface ParamSpec {
  type: 'integer' | 'string' | 'boolean'
  minimum?: number
  maximum?: number
  enum?: string[]
  bind: { target: string; rules: string[] }
}

export interface RulePackVersion {
  version: string
  engine: string
  engine_min_version: number
  sha256: string
  size_bytes: number
  source: string
  state: 'available' | 'downloaded'
  downloaded_at: string | null
  created_at: string
}

export interface RulePackEffect {
  enabled: boolean
  enabled_at: LevelRef
  // What this level's "inherit" follows (the levels above it).
  inherited: boolean
  adjustable: LevelRef[]
  priority: number
  params: Record<string, unknown>
  rule_states: Record<string, boolean>
  rule_source: Record<string, LevelRef>
  ignored_overrides: number
}

export interface RulePack {
  pack_id: string
  layer: 'system' | 'developer' | 'user'
  owner_scope_id: string | null
  current_version: string
  update_policy: 'auto' | 'manual'
  name: string
  description: string
  engine: string
  exports: { rule_id: string; name: string }[]
  params_schema: Record<string, ParamSpec> | null
  defaults: Record<string, unknown> | null
  requires: string[]
  cost: { rules: number; regexes: number; units: number }
  versions: RulePackVersion[]
  effect: RulePackEffect | null
  updated_at: string
}

export interface RulePackOverride {
  level: RulePackLevel
  level_object_id: string | null
  pack_id: string
  rule_id: string
  state: RulePackState
  allow_lower: boolean
  priority: number | null
  params: Record<string, unknown> | null
  updated_at: string
}

export interface RulePackLevelView {
  level: LevelRef
  packs: RulePack[]
  overrides: RulePackOverride[]
}

export interface OverrideInput {
  level: RulePackLevel
  level_object_id: string | null
  pack_id: string
  rule_id: string
  state: RulePackState
  allow_lower: boolean
  priority: number | null
  params: Record<string, unknown> | null
}

export interface ConflictSide { layer: string; pack_id: string; version: string; rule_id?: string; enabled_at: LevelRef }
export interface Remedy { action: 'disable_pack' | 'disable_rule'; at: LevelRef; pack_id: string; rule_id?: string }
export interface Conflict { code: string; message: string; sides: ConflictSide[]; remedies: Remedy[] }

export interface NodeRule {
  layer: string
  pack_id: string
  version: string
  rule_id: string
  node_id: string
  engine: string
  priority: number
  name: string
  waf?: { action: string; flow: string }
  cc?: { action: { kind: string } }
  crs?: { action: string; paranoia: number }
}

export interface Mount { layer: string; pack_id: string; version: string; sha256: string; engine: string; priority: number; params: Record<string, unknown> }
export interface Security { mounts: Mount[]; resolved_sha256: string }

export interface Resolution {
  security: Security | null
  rules: NodeRule[]
  conflicts: Conflict[]
  warnings: Conflict[]
  cost: { rules: number; regexes: number; units: number }
  requires: string[]
}

export interface SiteMounts {
  site_id: string
  published: { revision: number; security: Security; published_at: string; published_by_user_id: string | null } | null
  resolution: Resolution
  up_to_date: boolean
}

// RulePackConflictError: publishing was refused; resolution lists both
// sides of every conflict and the "disable at level" remedies.
export class RulePackConflictError extends ApiError {
  constructor(readonly resolution: Resolution) {
    super('rule pack conflict', 422, 'rule_pack_conflict')
  }
}

async function request<T>(token: string, path: string, init: RequestInit = {}, rawBody = false): Promise<T> {
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
  if (response.status === 422 && !rawBody) {
    const body = await response.clone().json().catch(() => null) as { error?: { code?: string; resolution?: Resolution } } | null
    if (body?.error?.code === 'rule_pack_conflict' && body.error.resolution) throw new RulePackConflictError(body.error.resolution)
  }
  if (!response.ok) throw await responseApiError(response)
  if (response.status === 204) return undefined as T
  try {
    return await response.json() as T
  } catch {
    throw new ApiError('invalid response', 502, 'invalid_response')
  }
}

function levelQuery(level: RulePackLevel, objectID: string | null): string {
  const params = new URLSearchParams({ level })
  if (objectID) params.set('object_id', objectID)
  return params.toString()
}

export const rulePacksApi = {
  view: (token: string, level: RulePackLevel, objectID: string | null) =>
    request<RulePackLevelView>(token, `/v1/rule-packs?${levelQuery(level, objectID)}`),
  importPack: (token: string, content: string) =>
    request<RulePack>(token, '/v1/rule-packs', { method: 'POST', body: content }),
  update: (token: string, packID: string, update: { current_version?: string; update_policy?: 'auto' | 'manual' }) =>
    request<RulePack>(token, `/v1/rule-packs?${new URLSearchParams({ pack_id: packID })}`, { method: 'PATCH', body: JSON.stringify(update) }),
  removeVersion: (token: string, packID: string, version: string) =>
    request<void>(token, `/v1/rule-packs/versions?${new URLSearchParams({ pack_id: packID, version })}`, { method: 'DELETE' }),
  putOverride: (token: string, input: OverrideInput) =>
    request<RulePackOverride | undefined>(token, '/v1/rule-packs/enablements', { method: 'PUT', body: JSON.stringify(input) }),
  site: (token: string, siteID: string) =>
    request<SiteMounts>(token, `/v1/sites/${encodeURIComponent(siteID)}/security-mounts`),
  publish: (token: string, siteID: string) =>
    request<SiteMounts>(token, `/v1/sites/${encodeURIComponent(siteID)}/security-mounts/publish`, { method: 'POST' }),
}

// rowState is the state the level itself sets for a pack (or one rule):
// inherit when the level has no row.
export function rowState(overrides: RulePackOverride[], packID: string, ruleID = ''): RulePackOverride | null {
  return overrides.find((row) => row.pack_id === packID && row.rule_id === ruleID) ?? null
}

// adjustableAt reports whether the pack can be set at the level now (the
// levels above allow it).
export function adjustableAt(pack: RulePack, level: LevelRef): boolean {
  return Boolean(pack.effect?.adjustable.some((item) => item.level === level.level && (item.object_id ?? '') === (level.object_id ?? '')))
}

// disableInput is the override a remedy applies: switch one side off at a level.
export function disableInput(remedy: Remedy): OverrideInput {
  return {
    level: remedy.at.level as RulePackLevel,
    level_object_id: remedy.at.object_id ?? null,
    pack_id: remedy.pack_id,
    rule_id: remedy.action === 'disable_rule' ? remedy.rule_id ?? '' : '',
    state: 'disabled',
    allow_lower: false,
    priority: null,
    params: null,
  }
}
