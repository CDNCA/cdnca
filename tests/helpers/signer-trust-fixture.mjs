// Test-only: an offline-signed cdnca.edge-signer-trust/v1 document in the exact
// wire form libs/entitlement/edgesignertrust.Sign produces (field order of the
// Go structs, json.Marshal without spaces; PEM and IDs here need no escaping).
import { createHash, generateKeyPairSync, sign } from 'node:crypto'

export function offlineRoot(keyID = 'cdnca-offline-root', generation = 1) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(12)
  return { keyID, generation, privateKey, pin: { key_id: keyID, generation, public_key: raw.toString('base64url') } }
}

export function signerTrustDocument({ revision = 1, trusted = [], revoked = [] } = {}) {
  const sorted = (list) => [...list].sort((a, b) => (a.key_id < b.key_id ? -1 : a.key_id > b.key_id ? 1 : 0))
  return { schema: 'cdnca.edge-signer-trust/v1', revision, issued_at: '2026-10-26T00:00:00Z',
    trusted_keys: sorted(trusted).map(({ key_id, public_key_pem, usage }) => ({ key_id, public_key_pem, ...(usage ? { usage } : {}) })),
    revoked_keys: sorted(revoked).map(({ key_id, public_key_sha256, revoked_at, reason }) =>
      ({ key_id, ...(public_key_sha256 ? { public_key_sha256 } : {}), revoked_at, reason })) }
}

// signSignerTrust returns the wire bytes. tamper(document) changes the
// document after signing (the digest no longer matches).
export function signSignerTrust(document, root, { tamper } = {}) {
  const documentBytes = JSON.stringify(document)
  const envelope = { schema: 'cdnca.edge-signer-trust-envelope/v1', algorithm: 'Ed25519', authority_kind: 'offline_root',
    authority_key_id: root.keyID, authority_key_generation: root.generation,
    document_sha256: createHash('sha256').update(documentBytes).digest('base64url') }
  const signature = sign(null, Buffer.from(JSON.stringify(envelope)), root.privateKey).toString('base64url')
  const body = tamper ? JSON.stringify(tamper(structuredClone(document))) : documentBytes
  return `{"document":${body},"envelope":${JSON.stringify(envelope)},"signature":"${signature}"}`
}
