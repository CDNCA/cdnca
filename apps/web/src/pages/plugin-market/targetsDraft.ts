// Draft of a tenant plugin's targets in the confirm / change dialogs.
import { maxTargetTenants, type PluginInstallationTargets } from '../../api/pluginInstallations'

export interface TenantOption { value: string; label: string }

export interface TargetsDraft { allTenants: boolean; tenants: TenantOption[] }

export const allTenantsDraft: TargetsDraft = { allTenants: true, tenants: [] }

export function draftTargets(draft: TargetsDraft): PluginInstallationTargets {
  return draft.allTenants ? { all_tenants: true, tenant_scope_ids: [] }
    : { all_tenants: false, tenant_scope_ids: [...new Set(draft.tenants.map((tenant) => tenant.value))] }
}

export function draftComplete(draft: TargetsDraft): boolean {
  return draft.allTenants || (draft.tenants.length >= 1 && draft.tenants.length <= maxTargetTenants)
}
