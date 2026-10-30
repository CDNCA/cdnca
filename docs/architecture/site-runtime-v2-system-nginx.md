# site runtime v2：系统 nginx 设置与多租户合并规则

状态：1.0.35 定（缺口 6）。规则：以平台系统设置为底；租户和站点级覆盖只影响自己的 server 块；http 级指令一律取平台值。

## 文档里带什么

v2 文档（`site-runtime.v2.json`）新增可选字段 `system`（`edgeconfig.SiteRuntimeSystem`，`libs/edgeconfig/site_runtime_system.go`）：

- `platform_scope_id`、`revision`、`snapshot_sha256`：对应平台系统配置的哪一个版本。
- `nginx`：平台的 nginx 底值，时长统一用毫秒。取值范围和 v1 渲染器相同（`normalizeNginxSettings`），而且必须是规范形式（resolver、proxy_cache_methods 已排序）。主控和节点使用同一个 `Validate()`。

主控发布时 `system` 的取值（`edgepublish/system_configuration.go` 的 `loadSiteRuntimeV2System`）：

- 系统配置激活时的那次发布：带上正在激活的版本。
- 其他所有 v2 发布（手动、自动、挑战、套餐同步等）：带上当前生效的版本（`systemconfig.LoadActiveEdgeNginx`）。v1 只在激活那一次带系统设置，之后任何一次普通发布都会把节点打回内置默认值；v2 修正了这个问题。
- 还没有激活过系统配置：不带 `system`，节点使用内置默认值（`worker_processes auto`、`worker_connections 4096`、`server_tokens off`）。

和激活并发时的一致性：激活会先锁住它要重新发布的每个租户 scope（`systemconfigpublish.loadTargets` 选中有站点或四层、并且有节点的 scope，用 FOR UPDATE 锁定），再切换生效版本；普通发布是先锁 scope 再读生效版本。所以对这些 scope，并发的普通发布要么排在激活之前（随后会被激活重新发布覆盖），要么排在之后（读到的已经是新版本）。例外是激活时还没有资源的 scope：它和激活同时进行的首次发布，可能带上旧版本，要等到下一次发布才会更新（v1 同样如此）。

## 节点怎么渲染

| 层级 | 指令 | 取值 |
|---|---|---|
| main | `worker_processes`、`worker_rlimit_nofile`、`worker_shutdown_timeout` | 平台值 |
| events | `worker_connections` | 平台值 |
| http | `resolver`、`resolver_timeout`、`gzip*`、`proxy_buffering`、`proxy_cache_methods`、`proxy_max_temp_file_size`、`proxy_connect/send/read_timeout`、`server_tokens`、Server 头、`client_max_body_size`、`default_type`、`keepalive_requests/timeout`、`log_not_found`、`server_names_hash_max_size` | 平台值，每个 nginx.conf 只写一次 |
| server / location | 站点自己的回源连接/读取超时（`proxy_connect_timeout`、`proxy_read_timeout`）、HTTP 策略的上传上限（`client_max_body_size`）、keepalive 池等 | 站点值，只写在该站点自己的块里；按 nginx 继承规则覆盖 http 级的平台值，不影响其他站点 |

四层：v1 和 v2 的每个 stream server 都写了自己的 `proxy_timeout`（`edgeconfig/config.go` renderStreams），所以 stream 级的平台默认值 `stream_proxy_timeout` 永远会被覆盖，v2 不渲染它。这个字段只是随文档带着。

`proxy_cache_max_bytes`、`proxy_cache_zone_bytes` 也随文档带着，供 v2 缓存（g11-v2b）使用。

## 多租户节点上的合并（`edgeconfig.SelectSiteRuntimeSystem`）

一个节点上组合了多个 scope 时，main、events、http 这三层全节点只有一份：

1. 取各 scope 文档里 `revision` 最大的那个 `system`。激活时会重新发布所有 scope，所以版本号更低的只是还没轮到重新发布的 scope。系统配置回滚也会生成新的、更大的版本号（`systemconfig/store.go` rollback），所以“取最大”不会退回到旧值。
2. 没带 `system` 的 scope 不参与选择；所有 scope 都没带时，使用内置默认值。
3. 拒绝组合，并保持当前版本不变的两种情况：同一个版本号对应了两个不同的快照摘要；或者出现了两个平台 scope。

租户和站点自己的设置不进入 main、events、http 层，所以一个租户改了设置，不会影响同一节点上的其他租户。

## 已知未做

- 系统设置里按地区、按节点的覆盖（`systemconfig.ResolveScopedConfiguration`）在边缘渲染中还没有生效，v1 也一样。要支持的话，主控需要按节点分别生成文档（v2 本来就按节点加密，可以做到）。另行安排。
