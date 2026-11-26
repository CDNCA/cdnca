import { useEffect, useState, useSyncExternalStore } from 'react'

// A manual backup stops control-api and the Gateway: once POST /backups
// answered 202 the page waits for that run id instead of reporting the
// expected outage as failures. Kept in localStorage so a reload resumes the
// wait; shared by the backup panel and the node address panel (writes locked).
export interface PendingBackup {
  runID: string
  startedAt: number
  state: 'queued' | 'running'
}

export const pendingBackupKey = 'cdnca.control-backup.pending'
/** Past this the wait ends with an error and a log link. */
export const backupWaitTimeoutMs = 15 * 60_000

const listeners = new Set<() => void>()
let memory: string | null = null
let cached: { raw: string | null; value: PendingBackup | null } = { raw: null, value: null }

function readRaw(): string | null {
  try { return window.localStorage.getItem(pendingBackupKey) } catch { return memory }
}

function readPendingBackup(): PendingBackup | null {
  const raw = readRaw()
  if (raw === cached.raw) return cached.value
  let value: PendingBackup | null = null
  try {
    const parsed = JSON.parse(raw ?? 'null') as Partial<PendingBackup> | null
    if (parsed && typeof parsed.runID === 'string' && parsed.runID && typeof parsed.startedAt === 'number' && Number.isFinite(parsed.startedAt)) {
      value = { runID: parsed.runID, startedAt: parsed.startedAt, state: parsed.state === 'running' ? 'running' : 'queued' }
    }
  } catch { value = null }
  cached = { raw, value }
  return value
}

export function setPendingBackup(value: PendingBackup | null) {
  memory = value ? JSON.stringify(value) : null
  try {
    if (memory) window.localStorage.setItem(pendingBackupKey, memory)
    else window.localStorage.removeItem(pendingBackupKey)
  } catch { /* storage blocked: the in-memory copy lasts until reload */ }
  listeners.forEach((listener) => listener())
}

function subscribe(listener: () => void) {
  listeners.add(listener)
  const onStorage = (event: StorageEvent) => { if (event.key === pendingBackupKey) listener() }
  window.addEventListener('storage', onStorage)
  return () => { listeners.delete(listener); window.removeEventListener('storage', onStorage) }
}

function usePendingBackup(): PendingBackup | null {
  return useSyncExternalStore(subscribe, readPendingBackup, () => null)
}

/** The pending backup and whether its wait is still within the time limit
 * (writes stay locked); re-renders when the limit passes. */
export function useBackupWait(): { pending: PendingBackup | null; waiting: boolean } {
  const pending = usePendingBackup()
  const [, tick] = useState(0)
  const deadline = pending ? pending.startedAt + backupWaitTimeoutMs : 0
  const waiting = Boolean(pending) && Date.now() < deadline
  useEffect(() => {
    if (!waiting) return
    const timer = window.setTimeout(() => tick((value) => value + 1), Math.min(deadline - Date.now() + 1, 2147483647))
    return () => window.clearTimeout(timer)
  }, [waiting, deadline])
  return { pending, waiting }
}
