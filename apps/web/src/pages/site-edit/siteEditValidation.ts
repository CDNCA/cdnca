import {
  canonicalSiteDomains,
  safeSiteTLSProtocolSelection,
  siteTLSNeedsLegacyCiphers,
  validSiteTLSCipherSuites,
  type SiteBasicConfig,
} from '../../api/sites'
import type { TFunction } from 'i18next'

export interface BasicValidationErrors {
  domains?: string
  http_listen_ports?: string
  https_listen_ports?: string
  tls_protocols?: string
  tls_cipher_suites?: string
  tls_client_ca_pem?: string
  origins?: string
}

function validEndpoint(value: string): boolean {
  if (!value || /\s/.test(value)) return false
  try {
    const url = new URL(`http://${value}`)
    return (
      (url.hostname.includes('.') || url.hostname.includes(':')) &&
      url.pathname === '/' &&
      url.search === '' &&
      url.hash === '' &&
      url.username === '' &&
      url.password === ''
    )
  } catch {
    return false
  }
}

function validPort(value: string): boolean {
  if (!/^\d+$/.test(value)) return false
  const port = Number(value)
  return port >= 1 && port <= 65_535
}

export function validateBasicConfig(
  value: SiteBasicConfig,
  t: TFunction<['sites', 'siteTLS', 'siteListenerDomains']>,
): BasicValidationErrors {
  const errors: BasicValidationErrors = {}

  if (!canonicalSiteDomains(value.domains)) {
    errors.domains = t('siteListenerDomains:validation.domains')
  }

  if (
    !value.http_enabled ||
    value.http_listen_ports.length === 0 ||
    value.http_listen_ports.length > 32 ||
    value.http_listen_ports.some((port) => !validPort(port)) ||
    new Set(value.http_listen_ports).size !== value.http_listen_ports.length
  ) {
    errors.http_listen_ports = t('edit.validation.httpPorts')
  }

  if (
    value.https_listen_ports.length > 32 ||
    value.https_listen_ports.some((port) => !validPort(port)) ||
    new Set(value.https_listen_ports).size !== value.https_listen_ports.length ||
    value.https_enabled && value.https_listen_ports.length === 0
  ) {
    errors.https_listen_ports = t('siteListenerDomains:validation.httpsPorts')
  } else if (value.https_listen_ports.some((port) => value.http_listen_ports.includes(port))) {
    errors.https_listen_ports = t('siteListenerDomains:validation.portConflict')
  }

  if (!safeSiteTLSProtocolSelection(value.tls_protocols) ||
    siteTLSNeedsLegacyCiphers(value.tls_protocols) && (value.tls_cipher_preset ?? 'modern') !== 'legacy') {
    errors.tls_protocols = t('siteTLS:validation.safeOnly')
  }
  if (value.tls_cipher_preset === 'custom' && !validSiteTLSCipherSuites(value.tls_cipher_suites)) {
    errors.tls_cipher_suites = t('siteTLS:validation.customCiphers')
  }
  if ((value.tls_client_auth === 'optional' || value.tls_client_auth === 'required') &&
    !(value.tls_client_ca_pem ?? '').includes('-----BEGIN CERTIFICATE-----')) {
    errors.tls_client_ca_pem = t('siteTLS:validation.clientCA')
  }

  if (value.origins.length === 0 || value.origins.some((origin) => !validEndpoint(origin))) {
    errors.origins = t('edit.validation.origins')
  }

  return errors
}
