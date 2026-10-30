// Plugin backend side (Node.js 18+): verify a call the cdnca control plane
// proxied from a ui_page (docs/developer/plugin-integration.md §8.3).
//
//   const verifier = createVerifier({ publicKey, keyId, basePath: '/v1' })
//   const context = verifier.verify({ method, pathWithQuery, body, headers })
//
// publicKey / keyId: shown on the control plane's plugin installation detail
// ("安装签名公钥", GET /v1/plugin-ui/signing-key). basePath is the path part
// of your api_base_url: the signature covers the path relative to it.
// verify throws on any failure; on success it returns the decoded context
// (installation_id, plugin_id, page_id, user_id, role, tenant_scope_id,
// site_id, locale, request_id, nonce, issued_at, expires_at).

import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto'

export const SIGNATURE_DOMAIN = 'cdnca-plugin-ui-proxy/v1'
export const CONTEXT_SCHEMA = 'cdnca.plugin-ui-context/v1'

export function signatureMessage(method, target, body, contextHeader) {
  const digest = createHash('sha256').update(body).digest('hex')
  return Buffer.from(`${SIGNATURE_DOMAIN}\n${method}\n${target}\n${digest}\n${contextHeader}`, 'utf8')
}

function header(headers, name) {
  const value = typeof headers.get === 'function' ? headers.get(name) : headers[name.toLowerCase()] ?? headers[name]
  if (typeof value !== 'string' || !value) throw new Error(`missing ${name}`)
  return value
}

export function createVerifier({ publicKey, keyId, basePath = '', now = () => Date.now(), nonceTTLms = 120000 }) {
  const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: publicKey }, format: 'jwk' })
  const prefix = basePath.replace(/\/$/, '')
  // Each nonce is accepted once within its validity (use a shared store if
  // you run several backend instances).
  const seen = new Map()
  return {
    verify({ method, pathWithQuery, body = Buffer.alloc(0), headers }) {
      if (header(headers, 'X-Cdnca-Plugin-Key-Id') !== keyId) throw new Error('unknown key id')
      if (prefix && !pathWithQuery.startsWith(`${prefix}/`)) throw new Error('path outside api_base_url')
      const target = pathWithQuery.slice(prefix.length)
      const contextHeader = header(headers, 'X-Cdnca-Plugin-Context')
      const signature = Buffer.from(header(headers, 'X-Cdnca-Plugin-Signature'), 'base64url')
      const raw = Buffer.isBuffer(body) ? body : Buffer.from(body)
      if (!verifySignature(null, signatureMessage(method.toUpperCase(), target, raw, contextHeader), key, signature)) {
        throw new Error('bad signature')
      }
      const context = JSON.parse(Buffer.from(contextHeader, 'base64url').toString('utf8'))
      const current = now()
      if (context.schema !== CONTEXT_SCHEMA) throw new Error('unknown context schema')
      if (Date.parse(context.issued_at) > current + 30000 || Date.parse(context.expires_at) <= current) {
        throw new Error('context expired')
      }
      for (const [nonce, expires] of seen) if (expires <= current) seen.delete(nonce)
      if (seen.has(context.nonce)) throw new Error('replayed nonce')
      seen.set(context.nonce, current + nonceTTLms)
      return context
    },
  }
}
