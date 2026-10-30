# Notification runtime wiring

The control API notification runtime is disabled by default. Enabling it starts the PostgreSQL outbox worker before HTTP serving, waits for one successful `ProcessBatch` call, verifies every enabled database channel and template, checks the configured email and/or SMS provider, and then exposes the worker to Account Recovery.

This wiring does not use a noop sender. Startup fails closed when any required database, worker, template, resolver, TLS, authentication, or provider dependency is unavailable.

## Required configuration

Set `NOTIFICATION_RUNTIME_ENABLED=true` and provide every variable below:

| Boundary | Variables |
| --- | --- |
| PostgreSQL | `DATABASE_URL`; migrations `001..029` or newer |
| Worker | `NOTIFICATION_WORKER_BATCH_SIZE`, `NOTIFICATION_WORKER_LEASE_DURATION`, `NOTIFICATION_WORKER_LEASE_SAFETY_MARGIN`, `NOTIFICATION_WORKER_MAX_ATTEMPTS`, `NOTIFICATION_WORKER_BASE_DELAY`, `NOTIFICATION_WORKER_MAX_DELAY` |
| Supervisor | `NOTIFICATION_RUNTIME_IDLE_WAIT`, `NOTIFICATION_RUNTIME_ERROR_BACKOFF_BASE`, `NOTIFICATION_RUNTIME_ERROR_BACKOFF_MAX`, `NOTIFICATION_RUNTIME_MAX_CONSECUTIVE_FAILURES`, `NOTIFICATION_RUNTIME_SEND_TIMEOUT`, `NOTIFICATION_RUNTIME_STARTUP_TIMEOUT`, `NOTIFICATION_RUNTIME_SHUTDOWN_TIMEOUT` |
| Email template | `ACCOUNT_RECOVERY_EMAIL_TEMPLATE_ID`, `ACCOUNT_RECOVERY_EMAIL_TEMPLATE_VERSION` |
| Email provider | `NOTIFICATION_EMAIL_PROVIDER=smtp_tls` or `smtp_starttls`; `NOTIFICATION_SMTP_ADDRESS`, `NOTIFICATION_SMTP_SERVER_NAME`, `NOTIFICATION_SMTP_USERNAME`, `NOTIFICATION_SMTP_PASSWORD`, `NOTIFICATION_SMTP_FROM` |
| Email trust | Optional `NOTIFICATION_SMTP_CA_FILE` PEM CA bundle; otherwise system roots are used |
| SMS template | `ACCOUNT_RECOVERY_SMS_TEMPLATE_ID`, `ACCOUNT_RECOVERY_SMS_TEMPLATE_VERSION` |
| SMS provider | `NOTIFICATION_SMS_PROVIDER=https_json`, `NOTIFICATION_SMS_ENDPOINT`, `NOTIFICATION_SMS_READY_ENDPOINT`, `NOTIFICATION_SMS_AUTH_TOKEN` |
| SMS trust | Optional `NOTIFICATION_SMS_CA_FILE` PEM CA bundle; otherwise system roots are used |

Configure the email template/provider pair for email-only delivery, the SMS template/provider pair for SMS-only delivery, or both pairs for both delivery channels. The enabled database channels must match the configured pairs; a missing, disabled, or mismatched channel/template rejects startup.

`smtp_tls` opens implicit TLS immediately. `smtp_starttls` connects to SMTP and requires a successful STARTTLS upgrade before authentication or delivery. There is no plaintext fallback or downgrade path. Both modes verify the certificate against `NOTIFICATION_SMTP_SERVER_NAME` exactly and use the configured CA bundle or system roots. Authentication is SMTP `AUTH PLAIN` only inside the verified TLS connection.

The `https_json` SMS adapter requires HTTPS send and readiness endpoints with the same origin. Userinfo, query strings, and fragments are rejected. TLS verifies the endpoint hostname against the configured CA bundle or system roots; the bearer token is never sent to a different origin.

Each configured template must exist in `notification_templates`, match its configured version, and contain only variables supported by the Account Recovery workflow.

## Local Compose

`compose.full.yaml` wires the email-only path to Mailpit with mandatory STARTTLS, the generated local CA, and dedicated generated local SMTP credentials. The SMTP username and password are not shared with Edge NATS or another subsystem, are stored only in the mode-`0600` generated runtime environment outside the repository, and are not printed by the local-stack runner. Compose fails closed when either value is missing. It deliberately does not configure an SMS provider. `NOTIFICATION_RUNTIME_ENABLED` remains `false` by default and may be explicitly overridden for acceptance work.

Before setting `NOTIFICATION_RUNTIME_ENABLED=true`, create/enable the matching email channel and the exact configured template ID/version in PostgreSQL. Compose does not seed or fake that business state. Missing or mismatched channel/template state fails readiness closed.

## Runtime supervision

The worker is not ready merely because its goroutine started. Readiness becomes true only after the first successful outbox batch, including a successful empty batch, plus resolver and SMTP readiness. A PostgreSQL error clears readiness and enters bounded backoff. A later `/health/ready` probe actively rechecks the database resolver and SMTP dependency before restoring readiness.

An unexpected terminal worker exit stops the control API through the existing required-background-runtime error channel. Operational logs and health output contain only stable state, count, and class fields.

Endpoints:

- `GET /health/ready` includes the notification runtime when enabled and returns the existing generic 503 response on failure.
- `GET /health/notification-runtime` returns only `enabled`, `state`, `ready`, `worker_running`, `enabled_channels`, `consecutive_failures`, and `last_error_class`.

Shutdown first stops accepting readiness/dispatcher work, cancels and joins the outbox worker within `NOTIFICATION_RUNTIME_SHUTDOWN_TIMEOUT`, then closes the dispatcher registry and SMTP transport. Account Recovery closes its dispatcher registration before the notification runtime closes.

## Delivery semantics

Delivery is at least once. The stable outbox deduplication key is sent as `X-CDNCA-Idempotency-Key` and is also used to derive a stable `Message-ID`, but SMTP has no standard provider idempotency operation. A crash after the SMTP server accepts a message and before PostgreSQL settlement can send the message again. Do not describe this adapter as exactly once.

Before sending a queued member email, the runtime resolves the exact tenant scope, tenant, user, and membership in one PostgreSQL transaction. The scope must be tenant-scoped, the tenant, user, and membership must still be active, and the resolver holds share locks through its commit. A tenant suspension that commits before that resolver commit produces the permanent failure `recipient_unavailable`; the outbox becomes `permanent_failed`, no SMTP call occurs, and a process restart does not revive it. If the resolver commits first, that already-resolved delivery may complete.

The resolver transaction is committed before the SMTP transport is called. No PostgreSQL transaction or identity lock is held across SMTP I/O. Platform audience selection and existing user or membership revocation behavior are unchanged; a platform scope is not accepted as a tenant member delivery scope.

## Verification

Run:

```bash
scripts/notification-runtime-wiring-smoke.sh
```

The smoke starts a task-owned PostgreSQL 17 container when `TEST_DATABASE_URL` is unset, applies migrations `001..029` in an isolated schema, runs the real SMTP TLS test server and process integration test under the race detector, then runs focused vet, ShellCheck, and a sensitive-log source scan.

Tenant active-fence acceptance additionally runs the notification process integration group against task-owned PostgreSQL 17.9 with `listen_addresses=''` and a Unix socket only. It covers active, disabled, suspended, missing, and platform-scope recipient facts, both resolver/suspension commit orders, zero SMTP after commit-first suspension, and terminal-state survival across a runtime restart.

## Remaining wiring boundaries

- Production Helm secret injection remains to be wired; local Compose uses only task-generated development credentials.
- Local Compose does not wire SMS. Production can configure the `https_json` adapter through a secret-managed HTTPS endpoint and CA bundle.
- SMTP does not provide provider-side idempotency or an HTTP-style `Retry-After`; 4xx replies, including nonstandard 429, are temporary failures without a provider retry duration.
- The notification bridge is passed into Account Recovery, but the command still has no production `TrustedContext` resolver for the public Account Recovery HTTP runtime. Account Recovery HTTP is therefore not fully enabled by this change.
