# 客户主控插件安装客户端示例

本示例对应 `cdnca.control.plugin-installation/v1`。客户浏览器只向自己的 Control API
发送租户 Bearer 会话；它不能调用 License Operator API，也不能把客户 token 转发给
`license-service`。当前共享 HTTP mount 由集成 owner 串行接线；mount 缺失时必须默认拒绝，
不得使用数据库直连或假响应绕过。

读取当前租户的安装授权：

```http
GET /v1/tenant-scopes/018cc251-f400-7def-8000-000000000020/plugin-installations?limit=50&status=pending_confirmation
Authorization: Bearer <tenant-session>
Accept: application/json
X-Request-ID: plugin-installation-list-example-1
```

确认安装或升级时必须保留相同的 `If-Match`、`Idempotency-Key` 和 JSON 进行结果未知重试：

```http
POST /v1/tenant-scopes/018cc251-f400-7def-8000-000000000020/plugin-installations/018cc251-f400-7def-8000-000000000021/confirm
Authorization: Bearer <tenant-session>
Content-Type: application/json
If-Match: "3"
Idempotency-Key: plugin-installation-confirm-example-1
X-Request-ID: plugin-installation-confirm-example-1

{"verification_id":"018cc251-f400-7def-8000-000000000023","approved_scopes":["cache.purge","sites.read"],"sensitive_permissions_confirmed":true,"new_permissions_confirmed":true}
```

`approved_scopes` 只能是签名 Manifest 权限的子集。敏感权限与升级新增权限必须分别确认；
未批准权限默认拒绝。禁用和卸载提交 1 到 500 个 Unicode code point 的审计原因，并且
即使当前发布者、Manifest 或能力证明失效也允许执行保护性动作。

开发者在请求安装前可运行正式兼容验证器：

```sh
node docs/developer/examples/validate-plugin-manifest.mjs \
  --control-api-version 0.5.0 \
  tests/contracts/plugin-manifest-v1.json \
  tests/contracts/plugin-publisher-v1.json
```

验证成功不代表自动安装；客户确认、License 签名事实、Control 兼容检查和进程外执行边界
仍必须全部通过。任何升级失败都保留最近可用版本，并通过稳定原因码展示，不能静默换版。

成功响应中的 `schema`、`status`、`revision`、`stable_reason_code` 和 `updated_at` 是客户页面
可展示的权威服务端结果。页面不得用内置目录或本地状态补造安装成功。服务端在同一事务写入
不可变 transition receipt 与 audit，但 Control 公开响应不暴露内部 receipt ID；客户端以返回
revision 或随后 GET 的同一 revision 确认结果。

`plugin_installation_result_unknown`、网络失败、408 或 5xx 必须保留原 JSON、原
`If-Match`、原 `Idempotency-Key` 与原 `X-Request-ID` 精确重试。403 不可重试，应申请
`plugin_installations.manage`；`plugin_installation_version_incompatible` 或
`control_api_incompatible` 必须显示为不兼容并保留 LKG。禁用和卸载成功后，旧工作负载身份
已被撤销；客户端不得继续复用旧 token。
