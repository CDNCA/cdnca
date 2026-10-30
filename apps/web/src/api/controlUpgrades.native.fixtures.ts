export const nativePlanID = '00000000-0000-4000-8000-000000000010'
export const nativeInstallationID = '00000000-0000-4000-8000-000000000011'
export const nativeActorID = '00000000-0000-4000-8000-000000000012'

export function nativeBundleFixture() {
  const artifact = (version: string, sequence: number, digest: string) => ({
    manifest: {
      schema: 'cdnca.release.artifact-manifest/v3', audience: 'cdnca-control-plane',
      purpose: 'cdnca-release-artifact', artifact_id: nativeInstallationID, component: 'control-api',
      version, protocol_min: 1, protocol_max: 1, artifact_size_bytes: 1024,
      release_sequence: sequence, digest_algorithm: 'sha256', sha256_digest: digest,
      download_url: 'https://artifacts.invalid/private-download?signature=DO-NOT-DISPLAY',
    },
    signature_algorithm: 'Ed25519', signature_key_id: 'test-key', manifest_signature: 'A'.repeat(86),
  })
  return {
    algorithm: 'Ed25519', key_id: 'test-key', signature: 'A'.repeat(86),
    bundle: {
      schema: 'cdnca.upgrade.plan-artifact-bundle/v2', audience: 'cdnca-control-plane-upgrade-plan',
      purpose: 'cdnca-upgrade-plan-artifact-bundle', bundle_id: nativePlanID, plan_id: nativePlanID,
      initial_plan_revision: 1, parent_grant_id: nativePlanID, parent_grant_sha256: 'A'.repeat(43),
      parent_grant_issued_at: 1780000000, parent_grant_expires_at: 1780000900,
      customer_id: nativeActorID, installation_id: nativeInstallationID, license_id: nativePlanID,
      channel: 'stable', channel_revision: 3, component: 'control-api', current_version: '1.0.0',
      version: '1.1.0', protocol_version: 1,
      forward: artifact('1.1.0', 5, 'A'.repeat(43)), rollback: artifact('1.0.0', 4, 'A'.repeat(43)),
      issued_at: 1780000000, command_issuance_not_after: 1890000000,
    },
  }
}

export function nativePublicationFixture() {
  return {
    schema: 'cdnca.control-plane-upgrade-publication/v1' as const,
    receipt_id: `${nativePlanID}:1`, plan_id: nativePlanID, bundle_sha256: 'a'.repeat(64),
    publication_revision: 1, expected_revision: 0, channel_revision: 3, release_sequence: 5,
    installation_id: nativeInstallationID, component: 'control-api' as const,
    current_version: '1.0.0', current_digest: '0'.repeat(64), target_version: '1.1.0',
    target_digest: '0'.repeat(64), rollback_version: '1.0.0', rollback_digest: '0'.repeat(64),
    protocol_version: 1, idempotency_sha256: 'b'.repeat(64), request_id: 'request-1',
    actor_user_id: nativeActorID, actor_scope_id: nativeInstallationID, published_at: 1780000000,
  }
}

export function nativeStatusFixture() {
  return {
    schema: 'cdnca.native-control-upgrade-status/v1' as const, observed_at: new Date().toISOString(),
    mode: 'native-standalone' as const, publication_revision: 0, publication: null,
    execution: { state: 'not_started' as const, phase: null, receipt: null },
    runtime: { ready: true, reason: 'ready' },
  }
}
