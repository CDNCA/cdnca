# 插件安装授权与运营工作流

本文只描述 `PLUG-INSTALL-HTTP-OPERATOR-02` 已接线的安装授权生命周期。机器可读
契约以 [`license.yaml`](../../api/openapi/v1/license.yaml) 为准；manifest 与发布者信任
链仍由 [`plugin-supply-chain.md`](plugin-supply-chain.md) 说明。

## 1. 当前边界

九个接口都位于 `license-service` 的 operator trust domain，并且同时绑定
`customer_id`、`installation_id` 和相关 verification/authorization：

| Method | Path | 用途 |
| --- | --- | --- |
| `GET` | `/operator/v1/customers/{customer_id}/installations/{installation_id}/plugin-installation-candidates/{verification_id}` | 预览不可变安装事实与权限确认集 |
| `GET` | `/operator/v1/customers/{customer_id}/installations/{installation_id}/plugin-installations` | 分页读取安装授权 |
| `POST` | `/operator/v1/customers/{customer_id}/installations/{installation_id}/plugin-installations` | 创建待确认授权 |
| `GET` | `/operator/v1/customers/{customer_id}/installations/{installation_id}/plugin-installations/{authorization_id}` | 读取授权、不可变回执和脱敏身份元数据 |
| `POST` | `.../{authorization_id}/confirm` | 二次确认权限 |
| `POST` | `.../{authorization_id}/install-applied` | 记录安装完成并冻结初始 LKG |
| `POST` | `.../{authorization_id}/enable` | 启用冻结的 LKG |
| `POST` | `.../{authorization_id}/disable` | 保护性禁用并撤销有效身份 |
| `POST` | `.../{authorization_id}/uninstall` | 保护性卸载并撤销有效身份 |

本模块没有 operator 服务身份签发接口。公开响应不包含签名 token、signature、请求
digest、`Idempotency-Key`、operator ID 或内部 audit ID。它也不允许插件直连平台或客户
数据库、不把插件代码装入核心进程，并且不让 `license-service` 进入边缘请求处理链路。

## 2. 认证、RBAC 与租户隔离

所有接口只接受独立的 `OperatorSession` Cookie，并在每次读取、写入和成功幂等 replay
时实时复查唯一权限 `licensing.plugin_installations.manage`。权限被撤销后，下一次请求立即
返回 `403 forbidden`。所有 POST 还要求精确 operator-console `Origin`；其他身份域的
Bearer token、control-api session 或租户 session 不能替代 operator Cookie。

路径 UUID 必须是非零、小写 canonical UUID。查询把 customer、installation 和
authorization 一起绑定；错配与不存在统一返回 `404 not_found`，避免暴露其他客户或
安装实例的记录。列表只返回指定 customer/installation 下的数据。

## 3. 候选事实与 installability

候选响应分别公开：

- `manifest_scopes`：manifest 声明的严格排序权限。
- `approved_scopes`：绑定同一 customer、installation 与 verification 的最新有效能力授权
  回执中批准的 scope 子集。它不能来自其他安装实例或旧 verification。
- `sensitive_scopes`：在签名权限分类法落地前，保守地包含全部 manifest scope。
- `new_scopes`：相对同一安装、同一插件最近一次已卸载授权的新增权限。
- `configuration_schema_sha256` 与 `configuration_schema_verified`：独立 schema 事实，
  不从 manifest 签名、默认 schema 或其他 digest 推导。

生产创建和升级安装授权前必须先完成独立 capability attestation 与安装实例级 capability
approval，并让验证事实同时满足 manifest、目录序列、发布者证明、主控兼容性、
configuration schema、scope subset 与 `external_https` entrypoint 检查。授权缺失、撤销、
过期或绑定错误时返回稳定 `scope_approval_required` 或 `resource_unavailable`，候选保持
`installable=false`。不得把 UI 确认冒充能力证明。

## 4. 权限确认与状态机

状态按以下方向推进：

```text
pending_confirmation -> authorized -> disabled -> enabled
                              |          |          |
                              +----------+----------+-> uninstalled
                                         ^          |
                                         +-- disable+
```

能力授权页先从 Manifest 声明中选择 scope/event/webhook 子集；未选择能力默认拒绝。当
所选集合包含 `sensitive_capabilities` 或 `new_capabilities` 时必须分别确认并写入不可变
approval receipt。`confirm` 正文随后必须提交与候选完全相同、顺序相同的
`approved_scopes`。当
`sensitive_scopes` 非空时 `sensitive_permissions_confirmed` 必须为 `true`；当
`new_scopes` 非空时 `new_permissions_confirmed` 必须为 `true`。两类确认相互独立。

`install-applied` 再次核对同一不可变 verification，设置初始 LKG 和 identity generation，
并进入默认 `disabled`；`enable` 才进入 `enabled`。升级回执也会在详情中出现：成功升级用
`upgrade_applied`，失败且保留 LKG 用 `upgrade_failed_lkg_preserved`。后者仍递增 revision，
但保持原状态、identity generation 与 LKG，便于审计失败尝试而不伪造生效。

`disable` 和 `uninstall` 都必须提交去除首尾空白后 1 到 500 个 Unicode code point 的
`reason`。它被写入不可变 transition receipt 与 audit。两条保护性路径不重新加载候选，
不会被当前 `installable=false`、发布者禁用、发布者密钥失效或 capability attestation
缺失阻断。成功禁用/卸载在同一事务中撤销该 authorization 的全部 active service
identity；后续使用旧身份应因 generation/status 撤销而失败。

## 5. CAS、幂等与结果未知

除创建外，每个 POST 都要求单个强 `If-Match: "<revision>"`。缺失、弱 ETag、未加引号、
零、非规范十进制、重复值或列表值返回 `400 invalid_if_match`；有效但过期的 revision
返回 `409 revision_conflict`。详情、创建和转换成功响应都返回同格式强 `ETag`，并通过
`Access-Control-Expose-Headers` 对 operator-console 可见。

每个 POST 还要求原样的单个 `Idempotency-Key`：1 到 128 bytes，每个 byte 在
`0x21..0x7e`。同 operator、operation、目标与 canonical request digest 的精确 replay
返回原结果；同 key 不同 digest 返回 `409 idempotency_conflict`。网络错误、`5xx` 或
`504 request_timeout` 后必须保留原 JSON、原 `If-Match` 和原 key 精确重试，不能换 key
猜测结果。operator-console 在结果未知时锁住弹窗关闭，并只提供精确重试或刷新后关闭。

## 6. 审计、回执与 LKG

创建和每次成功/失败升级转换都写入追加式 audit 与不可变 transition receipt。禁用和
卸载的 reason 同时进入两者。公开 receipt 只保留稳定 action、状态、revision、尝试的
verification/version、result、稳定原因码、identity generation、LKG 与时间，不泄露
幂等或操作员内部事实。

LKG 只引用已验证的 exact verification/version/schema digest。`enable` 恢复冻结的 LKG，
不会从当前目录、发布者或密钥状态静默换版本；失败升级明确保留原 LKG。授权中心离线或
当前插件信任事实后来失效都不能让已有边缘流量同步依赖授权中心。

客户端只按稳定 `code` 处理错误。安装专用 code 包括
`manifest_unverified`、`catalog_sequence_invalid`、`publisher_proof_invalid`、
`control_api_incompatible`、`configuration_schema_unverified`、
`scope_approval_required`、`execution_mode_invalid`、`transition_invalid`、
`revision_conflict` 与 `resource_unavailable`；不得把服务端内部英文或数据库错误直接显示
给运营人员。

兼容范围、开发者验证器和弃用时间线见
[`插件兼容与弃用契约`](plugin-compatibility-and-deprecation.md)。
