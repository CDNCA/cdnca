# 访问与安全事件查询运行手册

## 当前边界

`control-api` 在 `ANALYTICS_QUERY_ENABLED=true` 时正式挂载访问日志、原始安全事件、
汇总、趋势和五类排行查询。日志契约见
`api/control-analytics-logs.openapi.yaml`；canonical control OpenAPI 只引用该 fragment。

当前可查询：

- `access_events` 的访问事件；
- `security_events` 的原始安全事件；
- summary、hourly trend，以及 URL、IP、域名、地区、运营商五类排行。

`logs/blocks/current` 和 `logs/blocks/history` 仍固定返回
`422 analytics_logs_capability_unsupported`。原始 `security_events` 不是 append-only 的
block transition history，也不能证明 active/unlocked/expired block state。解锁命令、异步
导出仍不在本契约内。JA4、三项 origin timing、请求/响应头和请求/响应体已经进入查询契约，
但 authoritative edge source 仍未生成这些值，不能把 nullable/空响应当作全链完成。

## 路由与作用域

| 身份域 | 路由 | tenant scope |
| --- | --- | --- |
| platform | `/v1/admin/analytics/logs/access` | `tenant_id` 必填且只能选择一个 tenant |
| tenant | `/v1/analytics/logs/access` | 只取认证主体；出现 `tenant_id` 即 403 |
| platform | `/v1/admin/analytics/logs/block-events` | `tenant_id` 必填且只能选择一个 tenant |
| tenant | `/v1/analytics/logs/block-events` | 只取认证主体；出现 `tenant_id` 即 403 |
| 两身份域 | 对应 `blocks/current`、`blocks/history` | 校验和授权后 422，零 ClickHouse 查询 |

每个成功查询前都重新认证并校验 `sites.read`。平台日志路由只接受 Bearer session；租户
路由接受 Bearer 或 `CdncaKey`。tenant、site、node 和完整筛选都作为 ClickHouse typed
parameters 传递，不能由 payload、角色 header、`X-Tenant-ID`、Cookie 或 query token
覆盖。认证、scope、权限或依赖失败一律 fail closed。

## Snapshot keyset 分页

- `from` 左闭、`to` 右开，最多毫秒精度，窗口最长 31 天。
- 默认 `limit=50`，最大 100。查询读取 `limit+1`，有后续页时返回前 `limit` 行和
  `meta.next_cursor`。
- 全序固定为 `occurred_at DESC, event_id DESC`。
- 首次查询由 ClickHouse 取得前一毫秒 tick 的 `snapshot_at`；后续页只读取
  `ingested_at <= snapshot_at`，避免查询后同毫秒 default insert 污染 cursor chain。
- cursor 是 base64url opaque 值，最大 2048 字节，绑定版本、tenant、事件类型、完整
  filter、排序方向、snapshot 和最后一个全序键。
- cursor 跨 tenant、access/security 类型、时间窗、site/node 或其他 filter 使用时返回
  `400 analytics_logs_invalid_request`，且不会改写 scope。
- 非法 base64、非法 JSON、未知字段、空值和过长 cursor 在进入 ClickHouse 前拒绝。
- 每页返回 `consistency=snapshot`、
  `replacement_consistency=latest_event_id_at_snapshot` 和 `pagination=keyset`。

查询先在 occurrence window 内找 candidate event ID，再跨月分区读取这些 ID 的全部
snapshot-visible 版本，最后只对 latest 重放 occurrence window、filter、cursor 和 limit。
这保证旧版本在窗内而新版本移出时不会复活，也能返回从窗外移入的最新版本。相同
`event_id + ingested_at` 的完整 payload 用 exact distinct 计数；完全相同的重投保持幂等，
任意历史版本出现多个 payload 变体则整次 fail closed。`002_analytics_authority_capture`
为 raw 表增加 authority/capture/JA4/timing 列；001 保持只读。

## 过滤与输出

access 支持 site、node、精确 IPv4/IPv6、URI path、状态码、方法、协议、缓存状态、
国家/地区代码、运营商、JA4 和三项 origin timing 范围。security 支持 site、node、精确 IP、
URI path、状态码（含未记录 HTTP 状态的 0）、国家/地区代码、运营商、JA4 和 timing 范围，
并拒绝 access-only filter。未知、重复、空 query key、坏 percent encoding、
IPv6 zone identifier 和超过 8192 字节的 RawQuery 均返回 400。

URI 只返回 origin-form path；第一个 `?` 或 `#` 及其后内容会被删除。capture 只返回经过
allowlist、大小限制和敏感名 `[REDACTED]` 校验的结构；响应不得返回 Authorization、Cookie、
token、未验证的任意 header/body 或 ClickHouse 凭据。Client 对
每行重新验证 UUID、event ID、IP、时间窗、filter、字符串上限、重复 ID 和全序；未知 JSON
字段、坏行、partial JSON 或响应超限不返回部分数据。

## 稳定错误

| HTTP | code | 含义 |
| --- | --- | --- |
| 400 | `analytics_logs_invalid_request` | body、时间、筛选、limit 或已解码 cursor 与查询不匹配 |
| 401 | `analytics_logs_authentication_required` | 认证缺失或无效 |
| 403 | `analytics_logs_permission_denied` | 缺少读取权限 |
| 403 | `analytics_logs_scope_forbidden` | 身份域错误或 tenant 尝试覆盖 scope |
| 404 | `analytics_logs_route_not_found` | 路由或方法不属于日志 Handler |
| 422 | `analytics_logs_capability_unsupported` | block-state、非法 opaque cursor 形状或等版本歧义 |
| 503 | `analytics_logs_storage_unavailable` | ClickHouse 不可用、拒绝、坏响应或响应超限 |
| 503 | `analytics_logs_unavailable` | 认证/授权依赖不可用 |
| 504 | `analytics_logs_query_timeout` | 查询 deadline 或 caller cancellation |

所有响应设置 `Cache-Control: no-store` 和 `X-Request-ID`。错误 envelope 使用稳定 code，
不透传数据库、SQL、URL、响应正文或认证错误细节。

## 真实验证

包级门禁：

```sh
cd services/control-api
GOWORK=off go test ./internal/analytics ./internal/analyticslog
GOWORK=off go test -race ./internal/analytics ./internal/analyticslog
GOWORK=off go vet ./internal/analytics ./internal/analyticslog
```

真实 ClickHouse 25.3 测试使用唯一 task database：

```sh
cd services/control-api
: "${TEST_CLICKHOUSE_URL:?set the task-owned ClickHouse HTTP endpoint}"
formal_log=$(mktemp)
trap 'rm -f "${formal_log}"' EXIT
if ! TEST_CLICKHOUSE_REQUIRED=1 \
  TEST_CLICKHOUSE_URL="${TEST_CLICKHOUSE_URL}" \
  TEST_CLICKHOUSE_USERNAME="${TEST_CLICKHOUSE_USERNAME:-}" \
  TEST_CLICKHOUSE_PASSWORD="${TEST_CLICKHOUSE_PASSWORD:-}" \
  GOWORK=off go test ./internal/analyticslog \
    -run '^(TestClickHouseAnalyticsLogIntegration|TestClickHouseMutableOccurredAtCandidateResolution|TestClickHouseProductionClientCapacity)$' \
    -count=1 -v >"${formal_log}" 2>&1; then
  cat "${formal_log}"
  rm -f "${formal_log}"
  exit 1
fi
cat "${formal_log}"
if rg -q -- '^--- SKIP:' "${formal_log}"; then
  rm -f "${formal_log}"
  exit 1
fi
for test_name in TestClickHouseAnalyticsLogIntegration \
  TestClickHouseMutableOccurredAtCandidateResolution \
  TestClickHouseProductionClientCapacity; do
  rg -q -- "^--- PASS: ${test_name} " "${formal_log}" || {
    rm -f "${formal_log}"
    exit 1
  }
done
rm -f "${formal_log}"

TEST_CLICKHOUSE_URL=http://127.0.0.1:8123 \
TEST_CLICKHOUSE_DATABASE=task_analytics_query \
TEST_CLICKHOUSE_USERNAME=... TEST_CLICKHOUSE_PASSWORD=... \
GOWORK=off go test ./internal/analytics \
  -run TestAnalyticsClickHouseQueryIntegration -count=1 -v
```

正式 analyticslog gate 会拒绝任何非 `25.3.6.56` 服务端，并要求三个测试均出现 `PASS`、
输出中没有 `SKIP`。旧查询已验证 101 行两页无重复遗漏、五行三页全序、snapshot 后插入不污染后续页、
equal-version 歧义 fail closed、access/security platform/tenant scope，以及 summary、trend、
五类排行与 raw event 精确对账。当前 production 两阶段 SQL 的 cross-month replacement、
完全重复和历史 equal-version conflict 已有 integration test；新增 runtime harness 通过
production `Client.ListAccess`/`ListBlockEvents` 并发 2 路各分页 5000 行，从相同 production
SQL 常量提取 candidate scan 执行 `EXPLAIN indexes=1`，并以每页请求样本断言 p95 <= 2 秒、
p99 <= 5 秒。本轮没有 ClickHouse 串行资源窗口，因此这些 runtime 断言仍未执行，不能称为通过。

真实 NATS -> ClickHouse consumer 测试还覆盖 commit-then-fail 后 NAK、runtime 重建、稳定
重投、access/security ACK 和重复投递的逻辑幂等。Gateway 必须提供唯一且合法的
node/tenant/site/config/installation authority headers；subject、envelope 和每个 event 必须
与 header 一致，否则 NAK/TERM 或 quarantine，不能写入错误租户。

## 剩余边界

- signed manifest、EdgeConfig 和 OpenResty 尚未生成 task/JA4/timing/capture source；固定 source audit 为 19 RED。
- 空 capture 在 envelope/publication 仍会丢失 presence，`null` 与 `{}` 尚未闭合。
- block current/history、解锁任务、异步导出和生产容量/告警尚未完成。
- Analytics UI 已有 zh-CN/pseudo、loading/empty/error/403、分页筛选和多 viewport 证据，
  但仍缺六个 origin timing 控件、installation/response body/timing 详情和 11 个 i18n key。
  因此当前状态仍是 edge/control runtime partial，不是 OBS-05/06/10 全链路完成。
