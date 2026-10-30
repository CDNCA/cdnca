// "稍后再看" on the login announcement popup: the announcement does
// not pop up again for the rest of this sign-in (also across reloads of the
// tab), and pops up again after the next sign-in. Kept in sessionStorage and
// cleared by every new sign-in (setSession with update 'new').
const storageKey = 'cdnca.announcement-popup.later'

function read(): string[] {
  try {
    const value: unknown = JSON.parse(window.sessionStorage.getItem(storageKey) ?? '[]')
    return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : []
  } catch {
    return []
  }
}

export function announcementPopupLater(): string[] {
  return read()
}

export function rememberAnnouncementPopupLater(key: string): void {
  try {
    window.sessionStorage.setItem(storageKey, JSON.stringify([...new Set([...read(), key])].slice(-200)))
  } catch {
    // Storage unavailable: the component state still hides it for this page.
  }
}

export function forgetAnnouncementPopupLater(): void {
  try {
    window.sessionStorage.removeItem(storageKey)
  } catch {
    // Nothing stored.
  }
}
