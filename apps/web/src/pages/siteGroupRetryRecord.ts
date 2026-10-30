export type SiteGroupRetryOwner = readonly ['platform' | 'tenant', string, string]
export interface SiteGroupAttempt {
  action: 'create' | 'rename' | 'delete'
  scope: string
  id?: string
  revision?: number
  name?: string
  remark?: string
  key: string
  phase: 'ready' | 'unknown' | 'accepted' | 'done'
  accepted?: { id: string; revision: number; name: string; remark?: string }
  superseded?: true
}
export interface SiteGroupRetry { version: 1; owner: SiteGroupRetryOwner; items: SiteGroupAttempt[] }
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const maxLength = 200000

export function siteGroupRetryStorageKey(owner: SiteGroupRetryOwner): string {
  if (!Array.isArray(owner) || owner.length !== 3 || !['platform', 'tenant'].includes(owner[0]) ||
    !owner.slice(1).every((value) => typeof value === 'string' && uuidPattern.test(value))) return ''
  return `cdnca:site-groups-retry:${owner.join(':')}`
}

function validSiteGroupRetry(value: unknown, owner: SiteGroupRetryOwner): value is SiteGroupRetry {
  const fields = (object: unknown, required: string[], optional: string[] = []): object is Record<string, unknown> =>
    Boolean(object) && typeof object === 'object' && !Array.isArray(object) && required.every((key) => Object.hasOwn(object!, key)) &&
    Object.keys(object!).every((key) => required.includes(key) || optional.includes(key))
  const uuid = (id: unknown) => typeof id === 'string' && uuidPattern.test(id)
  const revision = (number: unknown) => typeof number === 'number' && Number.isSafeInteger(number) && number > 0 && number < Number.MAX_SAFE_INTEGER
  const name = (text: unknown) => typeof text === 'string' && text === text.trim() && [...text].length >= 1 && [...text].length <= 128 && !/\p{Cc}/u.test(text)
  const remark = (text: unknown) => typeof text === 'string' && [...text].length <= 1024 && ![...text].some((character) => /\p{Cc}/u.test(character) && !['\t', '\n', '\r'].includes(character))
  if (!siteGroupRetryStorageKey(owner) || !fields(value, ['version', 'owner', 'items']) || value.version !== 1 ||
    JSON.stringify(value.owner) !== JSON.stringify(owner) || !Array.isArray(value.items) || value.items.length < 1 || value.items.length > 100) return false
  const keys = new Set<string>()
  const targets = new Set<string>()
  let unfinished = false
  for (const item of value.items) {
    if (!fields(item, ['action', 'scope', 'key', 'phase'], ['id', 'revision', 'name', 'remark', 'accepted', 'superseded']) ||
      !['create', 'rename', 'delete'].includes(String(item.action)) || !uuid(item.scope) ||
      item.superseded !== undefined && (item.superseded !== true || item.phase !== 'done' || item.action === 'delete') ||
      (owner[0] === 'tenant' && item.scope !== owner[1]) ||
      typeof item.key !== 'string' || !/^[A-Za-z0-9._-]{1,128}$/.test(item.key) || keys.has(item.key) ||
      !['ready', 'unknown', 'accepted', 'done'].includes(String(item.phase)) || (unfinished && item.phase !== 'ready')) return false
    keys.add(item.key)
    if (item.phase !== 'done') unfinished = true
    if (value.items.length > 1 && item.action !== 'delete') return false
    if (item.action === 'create') {
      if (item.id !== undefined || item.revision !== undefined) return false
    } else {
      if (!uuid(item.id) || !revision(item.revision) || targets.has(`${item.scope}:${item.id}`)) return false
      targets.add(`${item.scope}:${item.id}`)
    }
    if (item.action === 'delete' ? item.name !== undefined || item.remark !== undefined : !name(item.name) || !remark(item.remark)) return false
    if (item.action === 'delete' || item.phase === 'ready' || item.phase === 'unknown') {
      if (item.accepted !== undefined) return false
    } else {
      const ack = item.accepted
      if (!fields(ack, ['id', 'revision', 'name'], ['remark']) || !uuid(ack.id) || !revision(ack.revision) ||
        ack.name !== item.name || (ack.remark !== undefined && ack.remark !== item.remark) ||
        (item.action === 'create' ? ack.revision !== 1 : ack.id !== item.id ||
          ack.revision !== item.revision && ack.revision !== Number(item.revision) + 1)) return false
    }
  }
  return true
}

export function restoreSiteGroupRetry(owner: SiteGroupRetryOwner): { record: SiteGroupRetry | null; blocked: boolean } {
  const key = siteGroupRetryStorageKey(owner)
  if (!key) return { record: null, blocked: true }
  try {
    const raw = sessionStorage.getItem(key)
    if (raw === null) return { record: null, blocked: false }
    if (raw.length > maxLength) return { record: null, blocked: true }
    const record: unknown = JSON.parse(raw)
    return validSiteGroupRetry(record, owner) ? { record, blocked: false } : { record: null, blocked: true }
  } catch { return { record: null, blocked: true } }
}

export function persistSiteGroupRetry(next: SiteGroupRetry, expected: SiteGroupRetry | null): boolean {
  if (!validSiteGroupRetry(next, next.owner)) return false
  try {
    const before = restoreSiteGroupRetry(next.owner)
    if (before.blocked || JSON.stringify(before.record) !== JSON.stringify(expected)) return false
    if (expected) {
      if (expected.items.length !== next.items.length) return false
      const rank = { ready: 0, unknown: 1, accepted: 2, done: 3 }
      for (let i = 0; i < next.items.length; i += 1) {
        const { phase: oldPhase, accepted: oldAccepted, superseded: oldSuperseded, ...oldInput } = expected.items[i]
        const { phase, accepted, superseded, ...input } = next.items[i]
        if (JSON.stringify(oldInput) !== JSON.stringify(input) || rank[phase] < rank[oldPhase] ||
          oldSuperseded && !superseded ||
          oldAccepted && JSON.stringify(oldAccepted) !== JSON.stringify(accepted)) return false
      }
    }
    const raw = JSON.stringify(next)
    if (raw.length > maxLength) return false
    sessionStorage.setItem(siteGroupRetryStorageKey(next.owner), raw)
    return sessionStorage.getItem(siteGroupRetryStorageKey(next.owner)) === raw
  } catch { return false }
}

export function clearSiteGroupRetry(expected: SiteGroupRetry): boolean {
  try {
    const before = restoreSiteGroupRetry(expected.owner)
    if (before.blocked || !before.record || JSON.stringify(before.record) !== JSON.stringify(expected)) return false
    const key = siteGroupRetryStorageKey(expected.owner)
    sessionStorage.removeItem(key)
    return sessionStorage.getItem(key) === null
  } catch { return false }
}
