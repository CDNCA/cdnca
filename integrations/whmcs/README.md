# CDNCA CDN —— WHMCS 对接模块

让 WHMCS 在下单、续费、停用、升降级、终止时自动操作 CDNCA 主控上的 CDN 服务，客户在 WHMCS 客户区一键免密登录 CDN 控制台，并每天同步流量用量。对应 ADR 0019（BB-07）。

## 要求

- WHMCS 8.x（PHP 7.4 ～ 8.3），PHP 扩展 `curl`、`json`。
- CDNCA 主控已启用「财务对接」插件，并在「财务对接」页生成了对接密钥：
  - 代理商模式（A）：用户后台 → 代理商 → 财务对接；
  - 自建主控（B）：管理后台 → 系统 → 财务对接。
- 生成密钥时把 WHMCS 服务器的出口 IP 加进 IP 白名单；WHMCS 服务器时间误差须在 ±300 秒内（建议开 NTP）。

## 安装

1. 解压 `cdnca-whmcs.zip` 到 WHMCS 根目录，得到 `modules/servers/cdnca/`（含 `cdnca.php`、`lib/`、`templates/`）。
2. WHMCS 后台 → 系统设置 → 服务器 → 添加新服务器：
   | 字段 | 填写 |
   |---|---|
   | 模块 | CDNCA CDN |
   | Hostname | 控制台域名，如 `cdn.example.com`（也可填完整 `https://cdn.example.com`） |
   | Username | 对接密钥 key_id（`cbb_` 开头） |
   | Password | 对接密钥 secret（`cbs_` 开头，WHMCS 加密保存） |
   | Secure | 勾选（走 HTTPS，端口 443） |
   点「测试连接」，显示成功即可。
3. 产品/服务 → 新建产品 → 模块设置：模块选 CDNCA CDN，「CDN 套餐」下拉选择主控上已上架的套餐（下拉拉取失败时可直接填套餐 ID），选择自动开通时机。
4. 产品价格只开放下表中支持的计费周期。

同时用 A、B 两种模式时，在 WHMCS 里配两个服务器（分别填两把密钥、两个域名），各自建产品即可，模块代码相同。

## 计费周期映射

| WHMCS billingcycle | 主控 period |
|---|---|
| Monthly | `month` |
| Quarterly | `quarter` |
| Annually | `year` |
| Semi-Annually | 不支持（主控暂无半年周期），开通时报错 |
| 其他（Free、One Time、Biennially、Triennially） | 不支持，报错 |

## 模块行为

| WHMCS 动作 | 门面接口 | 说明 |
|---|---|---|
| 测试连接 | `GET /ping` | 插件未启用时提示 |
| 套餐下拉 | `GET /products` | |
| 开通 | `POST /services` | `external_system=whmcs`、`external_service_id`=服务 ID、`external_client_id`=客户 ID；同一服务重复开通返回同一服务，不会重复开户。开通后 CDN 用户名写回服务的 Username 字段 |
| 暂停 / 解除暂停 | `POST .../suspend`、`/unsuspend` | 只停这一个服务的站点，配置保留 |
| 终止 | `POST .../terminate` | 客户名下没有其他有效服务时，CDN 账号被停用（数据保留） |
| 续费 | `POST .../renew` | 幂等键以下次到期日为参照，同一次续费重试不会重复续期 |
| 升降级 | `POST .../change` | 主控按新旧价格自动判断升/降级 |
| 登录 CDN 控制台 | `POST .../sso` | 一次性链接，60 秒有效 |
| 每日用量同步 | `GET /usage` | 每 100 个服务一批，写 `tblhosting.bwusage`（MB）与 `lastupdate`；CDN 无磁盘用量，`diskusage` 不写 |
| 客户区 | `GET /services/whmcs/{id}` + `/usage` | 套餐、状态、到期、本周期流量、登录按钮 |
| 后台服务页 | `GET /services/whmcs/{id}` | CDN 用户名、外部映射、最近同步 |

所有调用写入 WHMCS 模块日志（系统 → 日志 → 模块日志），签名头显示为 `***`，secret 由 WHMCS 自动替换。

## 常见错误

| 错误码 | 含义与处理 |
|---|---|
| `unauthorized` / `bridge_unauthenticated`（401） | 鉴权失败：key_id/secret 填错、密钥已吊销或过期、WHMCS 出口 IP 不在白名单、服务器时间偏差超过 300 秒 |
| `entitlement_feature_denied`（403） | 主控未启用财务对接插件 |
| `bridge_service_not_found`（404） | CDN 侧没有这个服务（尚未开通，或不属于这把密钥） |
| `bridge_product_not_found`（404） | 套餐不存在或已下架，重新选择产品的 CDN 套餐 |
| `bridge_service_conflict`（409） | 该服务已用不同参数开通过 |
| `bridge_service_terminated`（409） | 服务已终止，不能再操作 |
| `reseller_change_irreversible`（409） | 代理商升降级订单不可退款/作废 |
| `reseller_prepaid_insufficient`（422） | 代理商预付余额不足，先在 CDN 平台充值 |
| `reseller_wholesale_unpriced`（422） | 该套餐此周期没有批发价，联系 CDN 平台 |
| `bridge_validation_error`（400） | 请求参数不合法 |
| `network_error` | 连不上主控：域名/端口/HTTPS 证书/防火墙 |
| `invalid_response` | 主控返回非预期内容（如反代错误页） |
| `client_invalid_argument` | 本地配置错误，如未选 CDN 套餐、不支持的计费周期 |

错误文本末尾带 `request_id`，反馈给 CDN 平台时请附上。

## 升级

覆盖解压新版 zip 到 WHMCS 根目录即可（只替换 `modules/servers/cdnca/`），服务器与产品配置保留。无数据库迁移。

## 开发与测试

```bash
# 签名向量 + 单元断言（vectors.json 由 Go 端 credential.go 生成）
php integrations/php-sdk/tests/run.php
# mock 服务端冒烟：SDK 与 WHMCS 模块走 create → suspend → sso 等全流程
php integrations/php-sdk/tests/smoke.php
# 打包
integrations/build.sh   # → integrations/dist/cdnca-whmcs.zip
```

## 待真实 WHMCS 核对

已按官方开发文档（developers.whmcs.com：Supported Functions、Module Parameters、Meta Data、Config Options、Loader Functions、Single Sign-On、Usage Update、Client Area Output、Module Logging）与官方示例模块核对：

- `ServiceSingleSignOn` 返回 `success` / `redirectTo` / `errorMsg`：与文档一致。
- 客户区登录按钮链接 `clientarea.php?action=productdetails&id=…&dosinglesignon=1`：与文档一致（模板用 POST + `token`，同一入口）。
- `UsageUpdate` 每台服务器每日由 cron 调用，入参含 `serverid`，写 `tblhosting.bwusage`、`lastupdate`：与文档一致。CDN 没有磁盘概念，`diskusage`/`disklimit` 不写。
- `Loader` 失败时抛异常，WHMCS 显示异常信息：与文档一致（`SimpleMode` 下显示下拉，高级模式仍是文本框，可手填 `product_id`）。
- `logModuleCall` 的 `replaceVars` 传明文 secret，WHMCS 在日志里替换；签名头由 SDK 写成 `***`：与文档建议一致。
- `ClientArea` 已改为 `tabOverviewModuleOutputTemplate`（追加在原生概览下方）。官方示例说明 `tabOverviewReplacementTemplate` 会整页替换，价格、账单等原生信息需要模块自己显示，所以不用。

仍需真机确认（文档未写明）：

- `bwusage` 的单位。文档示例未写单位，WHMCS 惯例为 MB，模块按 MB 写入。
- `Renew` / `CreateAccount` 时 `$params` 是否直接带 `billingcycle`、`regdate`、`nextduedate`。文档参数表未列这几项，模块依次读 `$params`、`$params['model']`，最后查 `tblhosting`。
