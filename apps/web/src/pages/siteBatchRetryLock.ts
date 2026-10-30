import type { BatchSiteAction, BatchSiteActionRequest } from '../api/sites'

export interface SiteBatchAttempt {
  action: BatchSiteAction
  targets: Array<{ id: string; domain: string; version: number }>
  input: BatchSiteActionRequest
  body: string
  key: string
  // fix-regen: a row's own action (one site, single-site wording)
  single?: boolean
}

export interface SiteBatchRetryLockState {
  storageKey: string | null
  attempt: SiteBatchAttempt | null
  corrupted: boolean
  persistenceFailed: boolean
}

export function siteBatchRetryStorageKey(scopeID: string, userID: string): string {
  return `cdnca:site-batch-retry:${encodeURIComponent(scopeID)}:${encodeURIComponent(userID)}`
}

function validSiteBatchAttempt(value: unknown): value is SiteBatchAttempt {
  if (typeof value !== 'object' || value === null) return false
  const attempt = value as Partial<SiteBatchAttempt>
  if (
    (attempt.action !== 'enable' &&
      attempt.action !== 'disable' &&
      attempt.action !== 'delete' &&
      attempt.action !== 'regenerate_cname') ||
    typeof attempt.key !== 'string' ||
    attempt.key.length === 0 ||
    typeof attempt.body !== 'string' ||
    !Array.isArray(attempt.targets) ||
    attempt.targets.length < 1 ||
    attempt.targets.length > 100 ||
    typeof attempt.input !== 'object' ||
    attempt.input === null ||
    attempt.input.action !== attempt.action ||
    !Array.isArray(attempt.input.items) ||
    attempt.input.items.length !== attempt.targets.length ||
    (attempt.single !== undefined && (attempt.single !== true || attempt.targets.length !== 1))
  ) {
    return false
  }
  const ids = new Set<string>()
  for (let index = 0; index < attempt.targets.length; index += 1) {
    const target = attempt.targets[index]
    const item = attempt.input.items[index]
    if (
      typeof target !== 'object' ||
      target === null ||
      typeof target.id !== 'string' ||
      target.id.length === 0 ||
      ids.has(target.id) ||
      typeof target.domain !== 'string' ||
      !Number.isInteger(target.version) ||
      target.version < 1 ||
      typeof item !== 'object' ||
      item === null ||
      item.id !== target.id ||
      item.expected_version !== target.version
    ) {
      return false
    }
    ids.add(target.id)
  }
  return attempt.body === JSON.stringify(attempt.input)
}

export function restoreSiteBatchRetry(storageKey: string | null): SiteBatchRetryLockState {
  if (!storageKey) {
    return { storageKey, attempt: null, corrupted: false, persistenceFailed: false }
  }
  try {
    const stored = sessionStorage.getItem(storageKey)
    if (stored === null) {
      return { storageKey, attempt: null, corrupted: false, persistenceFailed: false }
    }
    const attempt: unknown = JSON.parse(stored)
    return validSiteBatchAttempt(attempt)
      ? { storageKey, attempt, corrupted: false, persistenceFailed: false }
      : { storageKey, attempt: null, corrupted: true, persistenceFailed: false }
  } catch {
    return { storageKey, attempt: null, corrupted: true, persistenceFailed: false }
  }
}

export function persistSiteBatchRetry(
  storageKey: string | null,
  attempt: SiteBatchAttempt,
): boolean {
  if (!storageKey) return false
  try {
    sessionStorage.setItem(storageKey, JSON.stringify(attempt))
    return true
  } catch {
    return false
  }
}

export function clearSiteBatchRetry(storageKey: string | null): boolean {
  if (!storageKey) return true
  try {
    sessionStorage.removeItem(storageKey)
    return true
  } catch {
    return false
  }
}
