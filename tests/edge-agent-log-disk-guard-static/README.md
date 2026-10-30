# Edge Agent log disk guard static contract

This static-only check pins the OPS-10 production wiring without starting the
Agent, Docker, or a test filesystem. It verifies the bounded telemetry-spool
cleaner, daemon configuration, systemd write boundary, tmpfiles exclusions,
logrotate retention, and the operator runbook.

Run the dynamic full-disk injection only in the consolidated seventh-round
isolation environment described by the runbook.
