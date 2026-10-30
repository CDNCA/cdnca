# OpenResty security release evidence

`runtime-lock.json` records the exact runtime source and base-image identity in
`runtime.env`. `advisory-snapshot.json` records the applicable upstream Nginx
advisories observed for the bundled Nginx version.

The current lock is deliberately not release eligible. Its source is OpenResty
`1.31.1.1` with the patch chain of `native/sources.lock.json` (FX19); the
advisory snapshot is still the historical one taken for `1.27.1.2` (Nginx
`1.27.1`) and has not been re-reviewed for the patched build. A production hotfix must replace this lock with a
reviewed OpenResty release containing a fixed Nginx version or a separately
reviewed immutable backport set. It must then bind the source, runtime image,
patch manifest, SPDX SBOM, provenance, advisory snapshot, protocol regression
evidence, and signature bundle into the Agent's signed
`cdnca.edge.security-hotfix/v1` manifest.

The Agent policy accepts only the `security-hotfix` channel. It limits the
initial cohort to one or two explicit nodes, requires automatic rollback,
requires successful canary evidence before expansion, supports a signed pause,
and binds rollback to a signed last-known-good runtime identity. The static
driver proves this contract without claiming that a patched image has been
built or scanned.
