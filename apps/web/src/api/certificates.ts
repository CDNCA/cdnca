import { ApiError, networkApiError, responseApiError } from './auth'
import { parseCertificatePublication, parseCertificateRollout, type CertificatePublicationDetail, type CertificatePublicationRollout } from './certificatePublicationStatus'

export type CertificateChallengeType = 'http-01' | 'dns-01'
export type CertificateOrderStatus =
  | 'pending'
  | 'validating'
  | 'issuing'
  | 'issued'
  | 'deploying'
  | 'active'
  | 'renewal_due'
  | 'failed'
  | 'revoked'

export interface CertificateOrder {
  id: string
  scope_id: string
  dns_provider_id?: string
  domains: string[]
  challenge_type: CertificateChallengeType
  status: CertificateOrderStatus
  auto_renew: boolean
  /** The frozen CA; absent for orders on the platform default issuer. */
  issuer?: CertificateIssuer
  name?: string
  remark?: string
  renewal_of_order_id?: string
  not_after?: string
  failure_code?: string
  /** The CA's redacted explanation (≤512 characters) beside failure_code. */
  failure_reason?: string
  retry_error_code?: string
  retry_error_reason?: string
  issued_asset_id?: string
  issued_version_id?: string
  issued_at?: string
  version: number
  created_at: string
  updated_at: string
}

export interface CertificateOrderList {
  items: CertificateOrder[]
}

export type CertificateDefaultType = 'acme' | 'uploaded'
/** CAs an order or a user default may name (CERT-04). */
export type CertificateIssuer = 'lets_encrypt' | 'zerossl' | 'google_trust'
const certificateIssuers = new Set<CertificateIssuer>(['lets_encrypt', 'zerossl', 'google_trust'])
export interface CertificateIssuerList {
  items: CertificateIssuer[]
  default: CertificateIssuer
}

export interface CertificateDefaults {
  scope_id: string
  user_id: string
  certificate_type: CertificateDefaultType
  dns_provider_id?: string
  issuer?: CertificateIssuer
  revision: number
  updated_at?: string
}

export interface UpdateCertificateDefaultsInput {
  target_scope_id?: string
  target_user_id?: string
  certificate_type: CertificateDefaultType
  dns_provider_id?: string
  issuer?: CertificateIssuer
  expected_revision: number
}

export interface CreateCertificateOrderInput {
  target_scope_id?: string
  dns_provider_id?: string
  domains: string[]
  challenge_type: CertificateChallengeType
  auto_renew: boolean
  issuer?: CertificateIssuer
  name?: string
  remark?: string
}

export type CertificateAssetSource = 'uploaded' | 'acme'
export type CertificateAssetVersionStatus =
  | 'default'
  | 'pending_activation'
  | 'active'
  | 'superseded'
  | 'revoked'
  | 'expired'

export interface CertificateAsset {
  id: string
  display_id: string
  tenant_scope_id: string
  tenant: { id: string; display_id: string; name: string }
  owner: { id: string; display_id: string; username: string; display_name: string } | null
  owner_status: 'recorded' | 'legacy_unknown'
  name: string
  remark?: string
  source: CertificateAssetSource
  // fix-autorenew（迁移 540）：证书是否自动续签；手动上传恒为 false。
  auto_renew?: boolean
  // fix-certops（迁移 552）：禁用的证书不能绑定网站、不自动续签。
  disabled?: boolean
  revision: number
  created_by: string
  updated_by: string
  created_at: string
  updated_at: string
  deleted_at?: string
}

export interface CertificateAssetVersion {
  id: string
  asset_id: string
  tenant_scope_id: string
  version: number
  status: CertificateAssetVersionStatus
  fingerprint_sha256: string
  certificate_pem: string
  sans: string[]
  subject: string
  serial_number: string
  public_key_algorithm: string
  public_key_bits: number
  signature_algorithm: string
  not_before: string
  not_after: string
  acme_order_id?: string
  renewal_due_at?: string
  renewal_due: boolean
  imported_by: string
  imported_at: string
}

export type CertificateAssetStatusFilter = 'normal' | 'expiring' | 'expired' | 'auto_renew' | 'manual_renew'

/** Assets per status under the search, over every page (证书状态胶囊). */
export interface CertificateAssetCounts {
  all: number
  normal: number
  expiring: number
  expired: number
  auto_renew: number
  manual_renew: number
}

export interface CertificateAssetList {
  items: CertificateAsset[]
  /** Assets under the search and status filter. */
  total: number
  /** The server always sends it; optional for callers that only page. */
  counts?: CertificateAssetCounts
}

/** The list's advanced search (CERT-05); the server applies it to items, total and counts. */
export interface CertificateAssetListFilters {
  domain?: string
  /** Exact; the latest version's SANs contain every one. */
  domains?: string[]
  user?: string
  certificate_id?: string
  name?: string
  remark?: string
  source?: CertificateAssetSource
  dns_provider_id?: string
  expiry?: 'within30' | 'within90' | 'expired'
  auto_renew?: boolean
  issue?: 'issued' | 'failed'
  sync?: 'complete' | 'pending' | 'failed'
}

export interface CertificateAssetListQuery {
  page: number
  limit: number
  search: string
  status?: CertificateAssetStatusFilter
  filters?: CertificateAssetListFilters
}

export interface CertificateAssetDetail {
  asset: CertificateAsset
  versions: CertificateAssetVersion[]
}

export interface CertificateAssetBinding {
	tenant_scope_id: string
	site_id: string
	asset_id: string
	version_id: string
	revision: number
	default: boolean
	bound: boolean
	changed_by: string
	changed_at: string
}

export interface CertificateAssetBindingList {
	items: CertificateAssetBinding[]
}

export interface CertificateSiteBindingDetail {
  binding: CertificateAssetBinding
  version: CertificateAssetVersion
}

export interface ImportCertificateAssetInput {
  name: string
  remark?: string
  owner_user_id?: string
  certificate_pem: string
  private_key_pem: string
}

export interface CertificateAssetRevisionInput {
	expected_revision: number
}

export interface BindCertificateAssetInput {
	site_id: string
	version_id: string
	expected_revision: number
	default: boolean
}

export interface SetCertificateAssetAutoRenewInput {
  enabled: boolean
  expected_revision: number
}

export interface DeleteCertificateAssetInput {
  expected_revision: number
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

const assetSources = new Set<CertificateAssetSource>(['uploaded', 'acme'])
const assetVersionStatuses = new Set<CertificateAssetVersionStatus>(['default', 'pending_activation', 'active', 'superseded', 'revoked', 'expired'])

function isAsset(value: unknown): value is CertificateAsset {
  return isRecord(value) && typeof value.id === 'string' && typeof value.tenant_scope_id === 'string' &&
    typeof value.display_id === 'string' && /^[1-9]\d*$/.test(value.display_id) &&
    isRecord(value.tenant) && typeof value.tenant.id === 'string' &&
    typeof value.tenant.display_id === 'string' && /^[1-9]\d*$/.test(value.tenant.display_id) && typeof value.tenant.name === 'string' &&
    ((value.owner_status === 'legacy_unknown' && value.owner === null) ||
      (value.owner_status === 'recorded' && isRecord(value.owner) && typeof value.owner.id === 'string' &&
        typeof value.owner.display_id === 'string' && /^[1-9]\d*$/.test(value.owner.display_id) &&
        typeof value.owner.username === 'string' && typeof value.owner.display_name === 'string')) &&
    typeof value.name === 'string' && assetSources.has(value.source as CertificateAssetSource) &&
    (value.auto_renew === undefined || typeof value.auto_renew === 'boolean') &&
    (value.disabled === undefined || typeof value.disabled === 'boolean') &&
    Number.isSafeInteger(value.revision) && typeof value.created_by === 'string' && typeof value.updated_by === 'string' &&
    typeof value.created_at === 'string' && typeof value.updated_at === 'string' &&
    (value.deleted_at === undefined || typeof value.deleted_at === 'string')
}

function isAssetVersion(value: unknown): value is CertificateAssetVersion {
  return isRecord(value) && !('private_key_pem' in value) && typeof value.id === 'string' && typeof value.asset_id === 'string' &&
    typeof value.tenant_scope_id === 'string' && Number.isSafeInteger(value.version) &&
    assetVersionStatuses.has(value.status as CertificateAssetVersionStatus) && typeof value.fingerprint_sha256 === 'string' &&
    typeof value.certificate_pem === 'string' && Array.isArray(value.sans) && value.sans.every((item) => typeof item === 'string') &&
    typeof value.subject === 'string' && typeof value.serial_number === 'string' && typeof value.public_key_algorithm === 'string' &&
    Number.isSafeInteger(value.public_key_bits) && typeof value.signature_algorithm === 'string' &&
    typeof value.not_before === 'string' && typeof value.not_after === 'string' &&
    (value.acme_order_id === undefined || typeof value.acme_order_id === 'string') &&
    (value.renewal_due_at === undefined || typeof value.renewal_due_at === 'string') && typeof value.renewal_due === 'boolean' &&
    typeof value.imported_by === 'string' && typeof value.imported_at === 'string'
}

const assetCountKeys = ['all', 'normal', 'expiring', 'expired', 'auto_renew', 'manual_renew'] as const

function isAssetList(value: unknown): value is CertificateAssetList {
	return isRecord(value) && Array.isArray(value.items) && value.items.every(isAsset) &&
		Number.isSafeInteger(value.total) && (value.total as number) >= 0 &&
		(value.counts === undefined || isRecord(value.counts) &&
			assetCountKeys.every((key) => Number.isSafeInteger((value.counts as Record<string, unknown>)[key]) &&
				((value.counts as Record<string, number>)[key] ?? -1) >= 0))
}

function isAssetDetail(value: unknown): value is CertificateAssetDetail {
  if (!isRecord(value) || !isAsset(value.asset) || !Array.isArray(value.versions)) return false
  const asset = value.asset
  return value.versions.every((version) => isAssetVersion(version) && version.asset_id === asset.id && version.tenant_scope_id === asset.tenant_scope_id)
}

function isBinding(value: unknown): value is CertificateAssetBinding {
  return isRecord(value) && typeof value.tenant_scope_id === 'string' && typeof value.site_id === 'string' &&
    typeof value.asset_id === 'string' && typeof value.version_id === 'string' && Number.isSafeInteger(value.revision) &&
    typeof value.default === 'boolean' && typeof value.bound === 'boolean' && typeof value.changed_by === 'string' && typeof value.changed_at === 'string'
}

function isBindingList(value: unknown): value is CertificateAssetBindingList {
  return isRecord(value) && Array.isArray(value.items) && value.items.every(isBinding)
}

function isSiteBindingDetail(value: unknown): value is CertificateSiteBindingDetail {
  if (!isRecord(value) || !isBinding(value.binding) || !isAssetVersion(value.version)) return false
  const { binding, version } = value
  return binding.bound && binding.asset_id === version.asset_id &&
    binding.version_id === version.id && binding.tenant_scope_id === version.tenant_scope_id &&
    version.status === 'active'
}

function invalidResponse(): ApiError {
  return new ApiError('Invalid certificate asset response', 502, 'invalid_response')
}

function isCertificateDefaults(value: unknown): value is CertificateDefaults {
  return isRecord(value) && typeof value.scope_id === 'string' && typeof value.user_id === 'string' &&
    (value.certificate_type === 'acme' || value.certificate_type === 'uploaded') &&
    (value.dns_provider_id === undefined || typeof value.dns_provider_id === 'string') &&
    typeof value.revision === 'number' && Number.isSafeInteger(value.revision) && value.revision >= 0 &&
    (value.updated_at === undefined || typeof value.updated_at === 'string')
}

function targetPath(path: string, targetScopeID?: string): string {
  if (!targetScopeID) return path
  return `${path}${path.includes('?') ? '&' : '?'}target_scope_id=${encodeURIComponent(targetScopeID)}`
}

async function request<T>(accessToken: string, path: string, validate: (value: unknown) => value is T, init: RequestInit = {}): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  let value: unknown
  try { value = await response.json() } catch { throw invalidResponse() }
  if (!validate(value)) throw invalidResponse()
  return value
}

export const certificatesApi = {
  getPublicationStatus(accessToken: string, siteID: string, revision: number, targetScopeID?: string): Promise<CertificatePublicationDetail> {
    return request(accessToken, targetPath(`/v1/certificate-publications/${encodeURIComponent(siteID)}/revisions/${revision}`, targetScopeID),
      (value): value is CertificatePublicationDetail => parseCertificatePublication(value) && value.current.site_id === siteID &&
        value.current.binding_revision === revision && (!targetScopeID || value.current.tenant_scope_id === targetScopeID))
  },
  getPublicationRollout(accessToken: string, rolloutID: string, targetScopeID?: string): Promise<CertificatePublicationRollout> {
    const path = targetScopeID
      ? `/v1/admin/site-rollouts/${encodeURIComponent(rolloutID)}?scope_id=${encodeURIComponent(targetScopeID)}`
      : `/v1/site-rollouts/${encodeURIComponent(rolloutID)}`
    return request(accessToken, path, (value): value is CertificatePublicationRollout => parseCertificateRollout(value) &&
      value.id === rolloutID && (!targetScopeID || value.configuration_scope_id === targetScopeID))
  },
  getDefaults(accessToken: string, targetScopeID?: string, targetUserID?: string): Promise<CertificateDefaults> {
    const params = new URLSearchParams()
    if (targetScopeID) params.set('target_scope_id', targetScopeID)
    if (targetUserID) params.set('target_user_id', targetUserID)
    const query = params.toString()
    return request(accessToken, `/v1/certificate-defaults${query ? `?${query}` : ''}`, isCertificateDefaults)
  },
  updateDefaults(accessToken: string, input: UpdateCertificateDefaultsInput, idempotencyKey: string): Promise<CertificateDefaults> {
    return request(accessToken, '/v1/certificate-defaults', isCertificateDefaults, {
      method: 'PATCH',
      headers: { 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify(input),
    })
  },
  list(accessToken: string): Promise<CertificateOrderList> {
    return request(accessToken, '/v1/certificate-orders', (value): value is CertificateOrderList => isRecord(value) && Array.isArray(value.items))
  },
  /** CAs a new request may name: Let's Encrypt and each platform-configured EAB CA (CERT-04). */
  listIssuers(accessToken: string): Promise<CertificateIssuerList> {
    return request(accessToken, '/v1/certificate-issuers', (value): value is CertificateIssuerList =>
      isRecord(value) && Array.isArray(value.items) && value.items.every((item) => certificateIssuers.has(item as CertificateIssuer)) &&
      certificateIssuers.has(value.default as CertificateIssuer))
  },
  create(accessToken: string, input: CreateCertificateOrderInput, idempotencyKey: string): Promise<CertificateOrder> {
    return request(accessToken, '/v1/certificate-orders', (value): value is CertificateOrder => isRecord(value) && typeof value.id === 'string' && typeof value.status === 'string', {
      method: 'POST',
      headers: { 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify(input),
    })
  },
	listAssets(
		accessToken: string,
		targetScopeID?: string,
		query?: CertificateAssetListQuery,
	): Promise<CertificateAssetList> {
		let path = '/v1/certificate-assets'
		if (query) {
			const parameters = new URLSearchParams({ page: String(query.page), limit: String(query.limit) })
			if (query.search) parameters.set('search', query.search)
			if (query.status) parameters.set('status', query.status)
			for (const [key, value] of Object.entries(query.filters ?? {})) {
				if (value === undefined || value === '' || (Array.isArray(value) && value.length === 0)) continue
				parameters.set(key, Array.isArray(value) ? value.join(',') : String(value))
			}
			path += `?${parameters}`
		}
		return request(accessToken, targetPath(path, targetScopeID), isAssetList)
	},
  getAsset(accessToken: string, assetID: string, targetScopeID?: string): Promise<CertificateAssetDetail> {
    return request(accessToken, targetPath(`/v1/certificate-assets/${encodeURIComponent(assetID)}`, targetScopeID), isAssetDetail)
  },
	uploadAsset(
	    accessToken: string,
	    input: ImportCertificateAssetInput,
	    idempotencyKey: string,
	    requestID: string,
	    targetScopeID?: string,
	  ): Promise<CertificateAssetDetail> {
	    return request(accessToken, targetPath('/v1/certificate-assets', targetScopeID), isAssetDetail, {
	      method: 'POST',
	      headers: { 'Idempotency-Key': idempotencyKey, 'X-Request-ID': requestID },
	      body: JSON.stringify(input),
	    })
	  },
	activateAssetVersion(
		accessToken: string,
		assetID: string,
		versionID: string,
			input: CertificateAssetRevisionInput,
			idempotencyKey: string,
			requestID: string,
			targetScopeID?: string,
		): Promise<CertificateAssetVersion> {
			return request(accessToken, targetPath(`/v1/certificate-assets/${encodeURIComponent(assetID)}/versions/${encodeURIComponent(versionID)}/activate`, targetScopeID), (value): value is CertificateAssetVersion => isAssetVersion(value) && value.asset_id === assetID && value.id === versionID, {
			method: 'POST',
			headers: { 'Idempotency-Key': idempotencyKey, 'X-Request-ID': requestID },
			body: JSON.stringify(input),
		})
	},
  getSiteBinding(accessToken: string, siteID: string, targetScopeID?: string): Promise<CertificateSiteBindingDetail> {
    return request(
      accessToken,
      targetPath(`/v1/sites/${encodeURIComponent(siteID)}/certificate-binding`, targetScopeID),
      (value): value is CertificateSiteBindingDetail =>
        isSiteBindingDetail(value) && value.binding.site_id === siteID,
    )
  },
		listAssetBindings(accessToken: string, assetID: string, targetScopeID?: string): Promise<CertificateAssetBindingList> {
			return request(accessToken, targetPath(`/v1/certificate-assets/${encodeURIComponent(assetID)}/bindings`, targetScopeID), isBindingList)
	},
	bindAsset(
		accessToken: string,
		assetID: string,
			input: BindCertificateAssetInput,
			idempotencyKey: string,
			requestID: string,
			targetScopeID?: string,
		): Promise<CertificateAssetBinding> {
			return request(accessToken, targetPath(`/v1/certificate-assets/${encodeURIComponent(assetID)}/bindings`, targetScopeID), (value): value is CertificateAssetBinding => isBinding(value) && value.asset_id === assetID, {
			method: 'POST',
			headers: { 'Idempotency-Key': idempotencyKey, 'X-Request-ID': requestID },
			body: JSON.stringify(input),
		})
	},
	unbindAsset(
		accessToken: string,
		assetID: string,
		siteID: string,
			input: CertificateAssetRevisionInput,
			idempotencyKey: string,
			requestID: string,
			targetScopeID?: string,
		): Promise<CertificateAssetBinding> {
			return request(accessToken, targetPath(`/v1/certificate-assets/${encodeURIComponent(assetID)}/bindings/${encodeURIComponent(siteID)}`, targetScopeID), (value): value is CertificateAssetBinding => isBinding(value) && value.asset_id === assetID && value.site_id === siteID, {
			method: 'DELETE',
			headers: { 'Idempotency-Key': idempotencyKey, 'X-Request-ID': requestID },
			body: JSON.stringify(input),
		})
	},
  setAssetAutoRenew(
    accessToken: string,
    assetID: string,
    input: SetCertificateAssetAutoRenewInput,
    idempotencyKey: string,
    requestID: string,
    targetScopeID?: string,
  ): Promise<CertificateAsset> {
    return request(accessToken, targetPath(`/v1/certificate-assets/${encodeURIComponent(assetID)}/auto-renew`, targetScopeID),
      (value): value is CertificateAsset => isAsset(value) && value.id === assetID && value.auto_renew === input.enabled, {
        method: 'PATCH',
        headers: { 'Idempotency-Key': idempotencyKey, 'X-Request-ID': requestID },
        body: JSON.stringify(input),
      })
  },
  setAssetDisabled(
    accessToken: string,
    assetID: string,
    input: { disabled: boolean; expected_revision: number },
    idempotencyKey: string,
    requestID: string,
    targetScopeID?: string,
  ): Promise<CertificateAsset> {
    return request(accessToken, targetPath(`/v1/certificate-assets/${encodeURIComponent(assetID)}/disabled`, targetScopeID),
      (value): value is CertificateAsset => isAsset(value) && value.id === assetID && Boolean(value.disabled) === input.disabled, {
        method: 'PATCH',
        headers: { 'Idempotency-Key': idempotencyKey, 'X-Request-ID': requestID },
        body: JSON.stringify(input),
      })
  },
  // 下载证书：zip（fullchain.pem + privkey.pem），文件名取响应 Content-Disposition。
  async downloadAsset(accessToken: string, assetID: string, requestID: string, targetScopeID?: string): Promise<{ blob: Blob; filename: string }> {
    let response: Response
    try {
      response = await fetch(`${apiRoot}${targetPath(`/v1/certificate-assets/${encodeURIComponent(assetID)}/download`, targetScopeID)}`, {
        credentials: 'include',
        headers: { Authorization: `Bearer ${accessToken}`, 'X-Request-ID': requestID },
      })
    } catch {
      throw networkApiError()
    }
    if (!response.ok) throw await responseApiError(response)
    if (!(response.headers.get('Content-Type') ?? '').startsWith('application/zip')) throw invalidResponse()
    const match = /filename="([^"]+)"/.exec(response.headers.get('Content-Disposition') ?? '')
    return { blob: await response.blob(), filename: match?.[1] ?? `certificate-${assetID}.zip` }
  },
  deleteAsset(
    accessToken: string,
    assetID: string,
		input: DeleteCertificateAssetInput,
		idempotencyKey: string,
		requestID: string,
		targetScopeID?: string,
	  ): Promise<CertificateAsset> {
	    return request(accessToken, targetPath(`/v1/certificate-assets/${encodeURIComponent(assetID)}`, targetScopeID), (value): value is CertificateAsset => isAsset(value) && Boolean(value.deleted_at), {
      method: 'DELETE',
      headers: { 'Idempotency-Key': idempotencyKey, 'X-Request-ID': requestID },
      body: JSON.stringify(input),
    })
  },
}
