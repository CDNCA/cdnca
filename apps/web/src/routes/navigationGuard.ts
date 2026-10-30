import { create } from 'zustand'

import i18n from '../i18n'

export function unsavedChangesMessage(): string {
  return i18n.t('sites:edit.confirm.unsavedChanges')
}

interface NavigationGuardState {
  dirty: boolean
  setDirty: (dirty: boolean) => void
}

export const useNavigationGuardStore = create<NavigationGuardState>((set) => ({
  dirty: false,
  setDirty: (dirty) => set({ dirty }),
}))

export function canLeaveCurrentPage(): boolean {
  return !useNavigationGuardStore.getState().dirty || window.confirm(unsavedChangesMessage())
}

export function resetNavigationGuard(): void {
  useNavigationGuardStore.setState({ dirty: false })
}
