import type { AudienceDirectoryEntry } from '../api/announcements'

/** A picked audience target. value is the wire key; label is what the user sees. */
export interface AudienceOption { value: string; label: string }

const lookupBatch = 100

/** Display name for a directory entry; built-in roles get their localized name. */
export function audienceEntryLabel(entry: AudienceDirectoryEntry, t: (key: string, options?: Record<string, unknown>) => string): string {
  if (entry.system) {
    const builtIn = t(`form.systemRoles.${entry.name}`, { defaultValue: '' })
    if (builtIn) return builtIn
  }
  return entry.detail && entry.detail !== entry.name ? `${entry.name}（${entry.detail}）` : entry.name
}

/** Resolves stored IDs to entries in batches the directory endpoint accepts. */
export async function lookupAudienceEntries(ids: string[], lookup: (ids: string[]) => Promise<AudienceDirectoryEntry[]>): Promise<AudienceDirectoryEntry[]> {
  const unique = [...new Set(ids)]
  const result: AudienceDirectoryEntry[] = []
  for (let index = 0; index < unique.length; index += lookupBatch) {
    result.push(...await lookup(unique.slice(index, index + lookupBatch)))
  }
  return result
}
