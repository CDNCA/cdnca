# 自定义 HTTP 接口 DNS 服务商（custom_http）

对接自建或未内置的 DNS 系统。主控（control-api）把记录操作以签名 JSON 发到运营方提供的一个 HTTPS 地址，由对方写入自己的 DNS。实现：`services/control-api/internal/dnscustomhttp`；参考服务端：同目录 `fake.go`（`FakeEndpoint`）。

## 凭据

| 字段 | 说明 |
| --- | --- |
| `endpoint` | `https://` 地址，不含用户名密码、查询串、片段；不能是 `localhost` 或内网/保留地址 |
| `secret` | 16–512 个可打印 ASCII 字符，双方共享的签名密钥 |

凭据与其他服务商一样经 `AESGCMCredentialCipher` 加密存储，不回显、不写日志。

## 传输与安全

- 只用 HTTPS 并校验证书（TLS 1.2+），不跟随重定向，响应上限 1 MiB，单次请求 15 秒超时。
- 每次连接在拨号时检查解析出的地址：环回、私网、链路本地（含云元数据 169.254.169.254）、CGNAT、组播、文档/基准网段、NAT64/6to4/Teredo、保留段一律拒绝，防 SSRF 与 DNS 重绑定。
- 请求方法 `POST`，`Content-Type: application/json`，头：
  - `X-Cdnca-Timestamp`：Unix 秒
  - `X-Cdnca-Nonce`：32 位十六进制随机数
  - `X-Cdnca-Signature`：`hex(HMAC-SHA256(secret, "cdnca.dns-custom-http/v1\n" + timestamp + "\n" + nonce + "\n" + hex(SHA256(body))))`
- 服务端必须：常量时间比较签名；拒绝与本机时间相差超过 300 秒的时间戳；拒绝重复 nonce（至少保留 10 分钟）；签名不对返回 HTTP 401。

## 请求与响应

请求体：`{"protocol":"cdnca.dns-custom-http/v1","action":"<动作>", ...参数}`。

响应（HTTP 200）：

```json
{"protocol": "cdnca.dns-custom-http/v1", "ok": true, "data": {}}
{"protocol": "cdnca.dns-custom-http/v1", "ok": false, "error": {"code": "not_found", "message": "..."}}
```

`error.code` 为小写字母、数字、下划线，≤64 字符；`message` 不会被主控展示或保存。HTTP 401/403 = 签名或密钥错误，429 = 限流（稍后重试），5xx = 暂不可用（重试）。

记录对象：

```json
{"id": "r1", "name": "s1.cdn.example.com", "type": "A", "value": "192.0.2.1", "ttl": 300, "line": "电信"}
```

- `name` 为完整域名（可带或不带结尾点），`type` 为 `A`/`AAAA`/`CNAME`/`TXT`（其他类型列出时会被忽略）。
- `line` 为统一线路名：`默认`、`电信`、`联通`、`移动`、`境外`；缺省视为 `默认`。由服务端映射到自身线路。
- `id` 由服务端分配，≤256 个可打印字符，在区域内唯一。

| action | 参数 | 成功 data |
| --- | --- | --- |
| `verify` | — | `{}`（用于保存后“验证”） |
| `list_records` | `zone`，可选 `name`（只列该主机） | `{"records":[记录...]}`，最多 10000 条 |
| `create_record` | `zone`，`record`（无 `id`） | `{"id":"..."}` |
| `update_record` | `zone`，`record`（含 `id`） | `{}` |
| `delete_record` | `zone`，`id` | `{}`；记录不存在返回 `ok:false` + `not_found` |

`zone` 不属于该接口时返回 `ok:false` + `zone_not_found`。

## 主控如何使用

- DNS-01 证书验证：创建 TXT（TTL 600），回读确认，用完删除。
- 网站 CNAME 发布、记录修复、按线路发布（电信/联通/移动/境外）：按 `list_records` 读取现状后增删改，并回读确认。
- 不支持记录权重（`开启IP权重` 对该服务商不生效）。
