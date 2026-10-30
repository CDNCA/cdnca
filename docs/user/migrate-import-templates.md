# 迁移导入：通用 CSV/JSON 模板与字段对照

适用：系统设置 → 迁移导入（官方插件 `module.migrate.import`）。设计见 `docs/adr/0016-migration-import.md`。

## 1. 来源与适配器

| 来源 | 方式 | 能导入 | 只列报告不导入 |
|---|---|---|---|
| cdnfly v6 | 管理员 API（api-key/api-secret） | 用户、套餐、用户套餐、证书、网站、DNS API、余额、订单 | 用户流量包 |
| GoEdge | 只读 MySQL 账号 | 同上（密码为无盐 MD5，按源哈希方案 B 迁移） | 四层转发（tcpProxy/udpProxy）、流量包 |
| FlexCDN | 同 GoEdge（同一组 edge* 表） | 同 GoEdge；缺失的表/列整段或逐列进报告，不中断 | 同 GoEdge |
| Cloudflare | API Token，只发 GET | 站点（zone 与 custom hostname），custom hostname 的 `custom_origin_server` 作源站 | 证书（API 不返回私钥）、zone 源站（API 不提供，需手填） |
| Bunny CDN | AccessKey，只发 GET `/pullzone` | 站点（自定义 Hostnames，去掉 `*.b-cdn.net`），`OriginUrl` 作源站 | 证书（私钥不可读） |
| 其他 | 通用 CSV / JSON（本文） | 按模板列 | — |

凭据只在读取任务的内存里，读完即清零，不写库、不进日志与审计。Cloudflare/Bunny 没有账号体系，站点全部归到导入页选择的默认用户。

## 2. 通用 JSON

上传 `cdnca.migrate/v1` 包（可只含部分段），结构即 `internal/migrateimport/bundle/model.go` 的 `Bundle`：`format`、`source{system,instance}`、`users`、`packages`、`user_packages`、`sites`、`certs`、`dns`、`balances`、`orders`。金额一律为分（`*_minor`）。证书私钥、DNS 凭据、密码哈希在入库前密封，任务结束后清除。

## 3. 通用 CSV（每段一个文件）

模板可在导入页下载（`GET /v1/admin/migrate-import-templates/{section}.csv`）。表头大小写不敏感，常见别名自动识别（如 `用户名`/`login` → `username`，`余额`/`money` → 元自动换算为分）；未识别的列在页面手工对列。

| 段 | 列 |
|---|---|
| users | source_id, username, email, phone, display_name, remark, qq, enabled, created_at |
| packages | source_id, name, description, monthly_traffic_bytes, bandwidth_bps, domains, root_domains, http_ports, stream_ports, monthly_minor, quarterly_minor, yearly_minor, source_node_group, enabled |
| user_packages | source_id, user, package, name, starts_at, ends_at, enabled |
| sites | source_id, user, user_package, domains（`;` 分隔）, enabled, http_ports, https_ports, force_https, origins（`host:port[:weight]`，`;` 分隔）, origin_protocol, origin_host, source_node_group |
| balances | user, balance_minor, frozen_minor |
| orders | source_id, user, type, description, amount_minor, paid_minor, status, pay_method, merchant_order_no, transaction_no, created_at, paid_at |

时间默认按 Asia/Shanghai 解析。CSV 不含密码哈希，导入用户一律首次登录前须找回密码（迁移通知含找回入口）。

## 4. 其他系统字段对照

只列有公开资料可依据的字段；其余列按导出文件手工对列。

### 4.1 Apache Traffic Control（Traffic Ops API，Delivery Service）

依据：[delivery_services.rst](https://github.com/apache/trafficcontrol/blob/master/docs/source/overview/delivery_services.rst)。

| ATC 字段 | 中间格式 | 说明 |
|---|---|---|
| `xml_id` | sites.source_id | 唯一键 |
| `orgServerFqdn` | sites.origins / origin_protocol | 含 scheme 的源站基础 URL，拆成协议与 host:port |
| Delivery Service URLs（Traffic Ops 派生） | sites.domains | 只读派生值；自有域名需按实际 CNAME 填 |
| `tenant` / `TenantID` | sites.user | 租户映射到 cdnca 用户（先导 users） |
| `active`（v5：ACTIVE/PRIMED/INACTIVE） | sites.enabled | ACTIVE → true |
| `protocol`（0 HTTP、1 HTTPS、2 两者、3 HTTP 跳 HTTPS） | http_ports / https_ports / force_https | 3 → force_https=true |

ATC 无余额、订单、套餐概念，不导。

### 4.2 OpenResty Edge（Admin Python SDK）

依据：[Python SDK 手册](https://doc.openresty.com/en/edge/edge-sdk/python-sdk-manual/)。

| Edge 字段 | 中间格式 | 说明 |
|---|---|---|
| app `domains` | sites.domains | |
| app `label` | sites.source_id（或备注） | |
| app `http_ports` / `https_ports`（`put_app`） | sites.http_ports / https_ports | |
| upstream `servers[].domain` / `ip`、`port`、`weight` | sites.origins（`host:port:weight`） | domain 与 ip 至少一个 |
| upstream `ssl` | sites.origin_protocol=https | |

证书与用户的 SDK 参数在手册中未完整给出：证书请导出 PEM 后用通用 JSON 的 `certs`，用户按导出列手工对列。

### 4.3 LeCDN、FunCDN

无可依据的公开接口或表结构资料，按各自后台导出的 CSV 在页面手工对列到 §3 模板。CDNBest、星盾、ZCDN、魔方、SuperCDN 同理，不列对照。

## 5. 导入行为要点

- dry-run 先给报告：将创建 / 合并 / 改名 / 跳过 / 冲突 / 不支持，以及流量包、四层转发"只列出"。确认时重算，与所看报告不一致须重新确认。
- 幂等：同一来源（系统 + 实例）的每条数据导入后永久记映射，重复导入不会再建。
- 余额只迁最终余额，生成待审入账单；平台管理员一次二次验证整批审批（可自审，审计标"自审"）。
- 历史订单进只读归档，不入账、不可改删。
- 源哈希（方案 B）：MD5/bcrypt 首次登录校验通过即转为 argon2id；默认保留 90 天，可在导入页设 7–180 天。MD5 为弱算法，建议缩短期限；运营页可一键清除全部源哈希。
