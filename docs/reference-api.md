# Reference system API observation notes

> 本文件只保存参考系统的黑盒证据，不是本项目公开契约。可调用接口以[开发者索引](developer/README.md)链接的 OpenAPI 为准；本文件中的 legacy 请求不会被契约检查器当成已实现 endpoint。

These notes record only black-box behavior observed from the public demo. They are compatibility evidence, not an instruction to reproduce the reference system's internals or its response envelope verbatim.

The public help site was also opened page by page in a real browser. Its 68 API pages are indexed in [the help-document inventory](help-doc-inventory.md). They add legacy method, field and workflow evidence, but do not upgrade an item to `Observed`; demo traffic or an isolated compatibility test is still required.

## Evidence rules

- `Observed` means the request was captured while using the demo UI on 2026-07-21.
- Only URL, method, status and response field names were inspected. Authentication headers, token values, passwords and response values are intentionally omitted.
- Our public API remains OpenAPI-first and uses our own versioned resource model. A compatibility adapter may be added later if an integration needs the legacy shape.

## Authentication and navigation

| Method | Path | Purpose | Observed response shape |
| --- | --- | --- | --- |
| `GET` | `/v1/common/sysinfo` | Login-page branding and system settings | Not yet sampled |
| `GET` | `/v1/common/captcha-type` | Select configured CAPTCHA mode | Not yet sampled |
| `POST` | `/v1/login` | Authenticate administrator or user | `{ code, data: { access_token, type, uid, username }, msg }` |
| `GET` | `/v1/common/auth` | Resolve current authorization state | Not yet sampled |
| `GET` | `/v1/common/menu2` | Resolve role-specific header and sidebar navigation | `{ code, data: { header: MenuItem[], sider: MenuItem[] }, msg }` |

Observed header menu fields: `hideSider`, `icon`, `name`, `path`, `title`.

Observed sidebar menu fields at the first level: `header`, `icon`, `path`, `title`. Nested entries require a deeper sample before the contract is fixed.

## Administrator overview

The administrator home triggered these reads in parallel:

- `GET /v1/log/login?limit=2&page=1&uid={uid}`
- `GET /v1/admin/overview`
- `GET /v1/monitor/site/top?recent_time=30m&type=top-domain`
- `GET /v1/monitor/usage-count?start={date}&end={date}`
- `GET /v1/new-user/count?start={date}&end={date}`
- `GET /v1/package-sold/count?start={date}&end={date}`
- `GET /v1/order/count?limit=0&state={state}&type={type}&group_by=day&start={date}&end={date}`
- `GET /v1/monitor/usage?start={date}&end={date}&type=bandwidth`

Our implementation should expose one purpose-built overview endpoint for initial rendering and separate drill-down endpoints. This avoids making page load correctness depend on many unrelated requests while preserving independently refreshable charts.

## Sites

Observed list request:

```text
GET /v1/sites?action=search&page=1&limit=10&is_default_server=&cname_hostname=&uid=&node_group=&region=&package=&cname_domain=&sync_state=
```

Opening the administrator edit page for a known demo site produced:

```text
GET /v1/sites/{site_id}
GET /v1/site-sys-config
GET /v1/l2-configs?limit=0&region_id={region_id}
GET /v1/user-packages?limit=0&uid={user_id}
GET /v1/site-groups?limit=0&uid={user_id}
GET /v1/acls?enable=1&limit=0&uid={user_id}
GET /v1/cc-rules?limit=0&is_show=1&internal_self=1&uid={user_id}
GET /v1/certs?limit=0&valid=1&uid={user_id}
```

The reference page requests all selection catalogs on entry. Our API should avoid caller-supplied `uid` as an authorization boundary: user requests are scoped from the authenticated tenant, while platform administrators provide an explicit tenant/resource scope that is authorized server-side. Catalogs may be loaded lazily per tab when that reduces initial latency without changing visible behavior.

Observed envelope:

```text
{ code: number, count: number, data: Site[] }
```

Observed `Site` field names:

```text
acl
acme_proxy_to_orgin
backend
backend_host
backend_http_port
backend_https_port
backend_port_mapping
backend_protocol
backup_node_group
backup_node_group_name
balance_way
block_proxy
block_region
cc_default_rule
cc_switch
cname_domain
cname_hostname
cname_mode
cname_state
cname_task_id
cors
create_at
create_at2
depend
domain
enable
enable_backup_group
end_at
extra_cc_rule
group_name
groups
gzip_enable
gzip_types
health_check
hotlink
http_listen
https_listen
id
name
node_group_id
node_group_name
package_id
package_name
post_size_limit
proxy_cache
proxy_http_version
proxy_ssl_protocols
proxy_timeout
range
record_id
region_id
region_name
site_state
spider_allow
state
sync_state
task_id
uid
up_cname_domain
up_cname_hostname
update_at
update_at2
ups_keepalive
ups_keepalive_conn
ups_keepalive_timeout
url_rewrite
user_package
version
websocket_enable
```

The broad legacy `Site` object mixes identity, desired configuration, display joins and asynchronous status. Our model should separate them:

- `Site`: tenant ownership, canonical domains, lifecycle and selected policy references.
- `OriginPool`: origins, conditional routing, health checks, retry and authentication.
- `SiteListener`: HTTP/HTTPS ports, protocols, certificate and transport settings.
- `SitePolicyBinding`: cache, WAF/CC, ACL, headers, rewrite and hotlink policies.
- `SiteDeployment`: desired version, generated artifact digest, per-node rollout and synchronization state.
- Read models may join these records for a table response without making the write model equally wide.

## Nodes

Opening the administrator node list produced these reads:

```text
GET /v1/nodes?enable=0&disable_by=sync_error
GET /v1/regions?limit=0
GET /v1/nodes?sub-ip=1&page=1&limit=10
```

The paginated response uses the same `{ code, count, data }` envelope as the site list. Observed node item fields:

```text
bw_limit
check_on
check_protocol
config_task
create_at
des
disable_at
disable_by
enable
id
inbound
ip
month_traffic
name
node_group_count
outbound
pid
region_id
region_name
sort
state
total_ip
type
update_at
```

The legacy read model mixes administrator intent (`enable`, limits, region and sort), transient observations (`inbound`, `outbound`, `state`) and asynchronous work (`config_task`). Our write model keeps these separate:

- `Node` and `NodeGroup` hold inventory and administrator intent in PostgreSQL.
- Online state is derived from expiring Agent leases; loss of Redis yields `unknown`, not an invented healthy/offline fact.
- `NodeObservation` stores rate-limited durable summaries and state changes.
- `NodeDeployment` and `Task` expose configuration progress; a task identifier is not embedded as the authoritative node state.
- Table endpoints may compose this information into a single row read model.

## Next samples

Before fixing the corresponding contracts, capture field/state evidence for:

1. Node list, registration, heartbeat and sync task pages.
2. Site create/edit, origin pool and deployment detail.
3. Certificate request, DNS provider credential and renewal states.
4. WAF/CC rule builder, matching order and continue/stop behavior.
5. Package purchase, renewal, traffic reset and global traffic pack.
6. Four-layer forwarding and Proxy Protocol configuration.
