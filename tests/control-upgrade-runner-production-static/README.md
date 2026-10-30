# Control upgrade runner production contract

This driver owns the final affected gate for OPS-06. It checks the two Go packages,
the Kubernetes runner environment, the systemd sandbox, the production values/schema,
and the runbook completion boundary without starting Kubernetes, PostgreSQL, NATS,
Docker, or a browser.

The Kubernetes runner obtains the signed plan over HTTPS with TLS 1.3 mutual TLS and
an internal bearer token. One existing read-only Secret supplies the CA, client
certificate, client private key, and token; the chart never creates or inlines that
Secret. The last verified plan is stored on the runner PVC and is bound to the
installation, operation, revision, ETag, and digest before degraded replay.

When the runner is enabled, the Control API exposes the internal GET plan source and
reads its bearer token from the same `controlUpgradeRunner.planSource` existing Secret
and key as the runner. The separate plan writer continues to target `planSecret`.
Disabling the runner removes the plan-source enabled environment value, token mount,
and source Secret volume together.

The OpenAPI fragment records the handler's actual wire behavior: JSON signed-plan
bytes for 200, an empty 304 replay, and plain-text 401/404/405/503 responses. It does
not claim an unsupported 400 response or administrator-session authentication.

`controlUpgradeRunner.planSecret` remains the Control API writer destination. The
runner does not mount it as a plan source; `controlUpgradeRunner.planSource` configures
the separate HTTPS source credentials and must be replaced with deployment-specific
Secret and endpoint values.

The values check deep-merges the default and production overlays, then validates the
complete `controlUpgradeRunner` subtree against its strict schema. Existing full-chart
schema drift in unrelated `operatorIngress` and `analyticsIngest` fields is tracked by
the integration owner and is not treated as an OPS-06 result.

Run the complete affected gate once:

```bash
bash tests/control-upgrade-runner-production-static/run.sh
```
