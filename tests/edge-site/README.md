# Edge site data-plane smoke

Run the real OpenResty site smoke from the repository root:

```sh
./scripts/edge-site-smoke.sh
```

The harness compiles the Linux `edge-site-smoke` binary, builds the pinned
OpenResty runtime, and starts a uniquely named container with task-owned state.
Container port `18081` is published to a Docker-selected loopback port. The
harness rejects host ports `15173` and `8080`, does not inspect or change any
pre-existing container, and removes only its own container, image tag, and
temporary directory on exit.

The command inside the container uses the production deployment manager for
precheck, immutable release creation, atomic activation, runtime health
confirmation, and rollback. The shell harness then sends a separate host-side
request with `Host: round-robin.example.test` and requires HTTP 200, the
`X-CDNCA-Config-Version: cfg-v2` response header, a backend identity, and a
body beginning with `backend:`.

## Evidence matrix

| Area | Real smoke evidence | Boundary not claimed by this smoke |
| --- | --- | --- |
| Site listener and virtual host | The generated bundle listens on the requested container port and routes real HTTP requests by `Host`; the host-side probe reaches the Docker-published random loopback port. | TLS listeners, IPv6 listeners, port migration, and production firewall integration. |
| Five origin-balancing methods | Real requests exercise round robin, `ip_hash`, URI hash, least connections, and random selection. Stable mappings and multi-backend observations are asserted as appropriate to each algorithm. | Capacity or distribution guarantees under production-scale load. |
| IP, DNS, and mixed origins | The runtime starts with both literal IP and `localhost` origins and proxies requests to task-owned backends. | A DNS origin is resolved by OpenResty when configuration is loaded or reloaded. TTL-driven dynamic re-resolution and automatic convergence after an address change are not implemented or claimed. |
| Safe upstream retry | GET and HEAD requests fail over from a failing origin to a healthy origin. A failed POST is observed only at the first origin and is not replayed. Exhausting all origins returns an explicit gateway error without failing runtime health or rolling back the active release. | Application-specific retry policies beyond the generated defaults. |
| WebSocket | A real HTTP Upgrade receives `101 Switching Protocols` and an echoed frame. | Connection continuity across reload, large-frame handling, extensions, and sustained long-connection load. |
| Range | A real single-range request returns 206 with the expected `Content-Range` and body slice. | Multi-range responses, cache hit/miss behavior, and invalid-range coverage. |
| Activation and rollback | v1 and v2 activate through the deployment manager. An injected v3 runtime health/version mismatch causes `StateReverted`; a subsequent real request still reports `cfg-v2`. | Multi-node rollout and cross-node rollback orchestration. |

HTTP/2 over TLS and HTTP/3/QUIC are not exercised by this HTTP/1.1 container
smoke. They remain separate protocol acceptance gates.
