import { refererDomainPattern, refererExtensionPattern, type HttpPolicyRefererCheck } from '../../api/httpPolicies'

// Hotlink protection draft (防盗链): lists edited one item per line.
export interface RefererDraft {
  allowEmpty: boolean
  allowSameDomain: boolean
  allowedDomains: string
  deniedDomains: string
  checkOrigin: boolean
  extensions: string
}

function lines(value: string): string[] {
  return [...new Set(value.split('\n').map((item) => item.trim()).filter(Boolean))]
}

export const emptyRefererDraft = (): RefererDraft => ({
  allowEmpty: true, allowSameDomain: true, allowedDomains: '', deniedDomains: '', checkOrigin: false, extensions: '',
})

export function refererDraftFrom(check: HttpPolicyRefererCheck): RefererDraft {
  return {
    allowEmpty: check.allow_empty, allowSameDomain: check.allow_same_domain, allowedDomains: check.allowed_domains.join('\n'),
    deniedDomains: check.denied_domains.join('\n'), checkOrigin: check.check_origin, extensions: check.extensions.join('\n'),
  }
}

// refererCheckFrom returns the canonical check, or null when the draft is invalid.
export function refererCheckFrom(draft: RefererDraft): HttpPolicyRefererCheck | null {
  const allowed = lines(draft.allowedDomains).map((item) => item.toLowerCase())
  const denied = lines(draft.deniedDomains).map((item) => item.toLowerCase())
  const extensions = lines(draft.extensions).map((item) => item.toLowerCase().replace(/^\./, ''))
  if (!allowed.every((item) => refererDomainPattern.test(item)) || !denied.every((item) => refererDomainPattern.test(item)) ||
    !extensions.every((item) => refererExtensionPattern.test(item)) || denied.some((item) => allowed.includes(item)) ||
    allowed.length > 64 || denied.length > 64 || extensions.length > 32 ||
    !draft.allowSameDomain && allowed.length === 0 && denied.length === 0) return null
  return {
    allow_empty: draft.allowEmpty, allow_same_domain: draft.allowSameDomain, allowed_domains: [...allowed].sort(),
    denied_domains: [...denied].sort(), check_origin: draft.checkOrigin, extensions: [...new Set(extensions)].sort(),
  }
}
