# Certificate runtime mount

This directory intentionally contains no certificate or private-key material.
The edge Agent compiles validated bundles into its private state root and starts
OpenResty against the atomically selected `current` release. Certificate state
must be supplied at runtime; it must never be baked into the image.

See `docs/runbooks/edge-certificate-runtime.md` for the bundle contract,
permissions, activation flow, recovery procedure, and current scope boundary.
