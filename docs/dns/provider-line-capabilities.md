# DNS 服务商分线路能力表

核对日期：2026-10-17，2026-10-20 复核华为云与 DNS.COM，2026-10-21 DNS.COM 按套餐档位开放，2026-10-22 新增 name.com。只依据下列官方文档，未用真实账号调用任何写接口。

统一线路枚举沿用 DNSPod 线路名（`dnsproviderremote` 现有口径，市场 `dnssync.go` 的 `dnsLine` 也用这套）：

| 统一值 | 含义 | 市场口径（`05-scheduling-quality.md`、`dnsLine`） |
| --- | --- | --- |
| `默认`（也接受空串、`default`） | 未命中其他线路的访客 | 每个节点都写一份 |
| `电信` / `联通` / `移动` | 国内三网 | region=cn 且 carrier=telecom/unicom/mobile |
| `境外` | 中国内地以外 | region≠cn |

## 结论

| 服务商 | 按线路写记录 | 线路取值（统一值 → 厂商值） | 权重与线路同用 | 适配器 `Line` |
| --- | --- | --- | --- | --- |
| DNSPod | 支持，`record_line`（中文名）或 `record_line_id` | 原样使用线路名 | 支持，`weight` 0–100，与 `record_line` 同一请求 | true（原有） |
| 阿里云 | 支持，`AddDomainRecord`/`UpdateDomainRecord` 的 `Line` | `default` `telecom` `unicom` `mobile` `oversea` | 支持但要另调 `SetDNSSLBStatus`（按子域名+线路开关）和 `UpdateDNSSLBWeight`（1–100），不能随写记录一起提交 | true；`Weight` 仍 false |
| 华为云 | 支持，v2.1 记录集 `line`（线路 ID）；线路创建后不可改 | `default_view` `Dianxin` `Liantong` `Yidong` `Abroad` | 支持，记录集 `weight` 0–1000，与 `line` 同一请求；但权重在记录集上，不是每个 IP 一个 | true；`Weight` 仍 false |
| Cloudflare | 普通 DNS 记录不支持按运营商/地区应答 | 无 | 无 | false |
| name.com | 不支持，记录字段只有 host/type/answer/ttl/priority | 无（只写默认线路） | 无 | false；TTL 下限 300 |
| DNS.COM | 支持，`view_id`（线路 ID） | 运行时按域名调 `getView`，按线路名匹配 ID（不硬编码），缓存 1 小时；默认线路不传 `view_id` | 文档写 `mx` 字段对非 MX 记录是权重（1–55） | true，按凭据里的套餐档位开放（见下）；`Weight` false |
| DNSLA | 支持，`lineId` | 默认为空串；`电信` 84613316902921216（tele）、`联通` 84613316923892736（unic）、`移动` 84613316953252864（mobi）、`境外` 84613317016167424（abr，海外） | 支持，`weight` 1–10，与 `lineId` 同一请求 | true；`Weight` 仍 false |
| 自定义 HTTP 接口（custom_http） | 支持，记录的 `line` 字段 | 原样传统一值（`默认`/`电信`/`联通`/`移动`/`境外`），由对接方映射（[协议](custom-http-provider.md)） | 不支持 | true；`Weight` false |

`Weight` 只有 DNSPod 为 true：阿里云要额外的非原子调用，华为云权重粒度是记录集，DNSLA 范围 1–10，都与我们“每个 IP 0–100”的模型不一致，本次不做。

不支持分线路的服务商（Cloudflare、name.com）按 ADR 0008 §6.4 只做全局主备：只接受默认线路，带线路的写入在发请求前返回 `dns_provider_remote_unsupported`。

## 各家依据

### DNSPod

- [添加记录 Record.Create](https://docs.dnspod.cn/api/add-record/)：`record_line`（中文，如“默认”）或 `record_line_id`（如 `10=1`），`weight` 0–100，“0 表示关闭”。
- [记录列表 Record.List](https://docs.dnspod.cn/api/record-list/)：返回 `line`、`line_id`、`weight`。
- [按分类获取线路 Record.Line.Category](https://docs.dnspod.cn/api/record_line_categor/)。
- [智能解析线路说明](https://cloud.tencent.com/document/product/302/8643)：默认、电信、联通、移动、教育网、境内、境外等基本线路免费版可用；“境外”含港澳台及中国以外。

### 阿里云

- [解析线路枚举](https://help.aliyun.com/zh/dns/pubz-resolve-line-enumeration/)：一级线路 `default` `telecom` `unicom` `mobile` `edu` … `oversea`（地域线路-境外）`internal`（地域线路-中国内地）。
- [AddDomainRecord](https://help.aliyun.com/zh/dns/api-alidns-2015-01-09-adddomainrecord)、[UpdateDomainRecord](https://help.aliyun.com/zh/dns/api-alidns-2015-01-09-updatedomainrecord)：`Line` 可选，默认 `default`；请求里没有权重字段。
- [DescribeDomainRecords](https://help.aliyun.com/zh/dns/api-alidns-2015-01-09-describedomainrecords)、[DescribeDomainRecordInfo](https://help.aliyun.com/zh/dns/api-alidns-2015-01-09-describedomainrecordinfo)：返回 `Line`；列表还返回 `Weight`。列表的 `Line` 过滤只在 `SearchMode` 为 ADVANCED/COMBINATION 时有效，适配器不改查询参数，按返回的 `Line` 在本地过滤。
- [SetDNSSLBStatus](https://help.aliyun.com/zh/dns/api-alidns-2015-01-09-setdnsslbstatus)（`SubDomain`+`Line` 开关权重）、[UpdateDNSSLBWeight](https://help.aliyun.com/zh/dns/api-alidns-2015-01-09-updatednsslbweight)（`RecordId`+`Weight` 1–100）。

### 华为云

- [官方解析线路表](https://support.huaweicloud.com/api-dns/zh-cn_topic_0085546214.html)（10-20 经 WebFetch 读取；curl/无头浏览器仍被 EdgeOne 人机验证拦截）：基础线路 9 条 `default_view` 全网默认、`Dianxin` 电信、`Liantong` 联通、`Yidong` 移动、`Jiaoyuwang` 教育网、`Tietong` 铁通、`Pengboshi` 鹏博士、`CN` 中国大陆、`Abroad` 境外；另有 运营商_大区/省（如 `Dianxin_Shanxi`）、中国大陆_省/大区（如 `Beijing`、`Huabei`）、全球大洲 `AP` `OA` `EU` `NA` `LA` `AF` 与国家/地区码（港澳台为 `HK` `MO` `TW`，归在亚太）。
- 页面未写线路与套餐等级的关系，也未界定 `Abroad` 的子线路；按“境外”与“中国大陆”并列、港澳台列在亚太下，映射 `境外` → `Abroad`。账号控制台的套餐可用性未核实（本次没有可用的浏览器插件读取登录态）。
- [官方 Go SDK `CreateRecordSetWithLineRequestBody`](https://github.com/huaweicloud/huaweicloud-sdk-go-v3/blob/master/services/dns/v2/model/model_create_record_set_with_line_request_body.go)：`line`“解析线路ID”，`weight`“0~1000，公网记录集默认为1”。
- [官方 SDK `UpdateRecordSetsReq`](https://github.com/huaweicloud/huaweicloud-sdk-go-v3/blob/master/services/dns/v2/model/model_update_record_sets_req.go)：`PUT /v2.1/zones/{zone_id}/recordsets/{recordset_id}` 只有 name/type/ttl/records/weight/description，没有 `line`。
- [官方 Terraform `huaweicloud_dns_recordset`](https://github.com/huaweicloud/terraform-provider-huaweicloud/blob/master/docs/resources/dns_recordset.md)：`line_id` 为 ForceNew（改线路就是重建记录集），示例 `Dianxin_Shanxi`，线路表链接到 [Resolution Lines](https://support.huaweicloud.com/intl/en-us/api-dns/en-us_topic_0085546214.html)（即被拦截的页面）。
- 线路 ID 取值：互相独立的开源实现一致——[RuYi-Panel](https://github.com/lybbn/RuYi-Panel/blob/main/apps/sysdomain/dns_providers/huaweicloud.py)、宝塔——都用 `default_view`（全网默认）、`Dianxin`、`Liantong`、`Yidong`。
- 10-17 曾按开源实现把 `Abroad` 理解为“全球（含 CN）”而不映射 `境外`；10-20 读到官方线路表后改为映射。
- 线路不可修改：适配器对“线路变化的 update”在发请求前返回 `unsupported`；改线路要由上层改成“删除 + 新建”。

### Cloudflare

- [DNS 记录创建 API](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/)：记录字段为 type/name/content/ttl/proxied/comment/tags/settings 等，没有线路或地域字段。
- 按地域应答只有付费的 [Load Balancing Geo steering](https://developers.cloudflare.com/load-balancing/understand-basics/traffic-steering/steering-policies/geo-steering/)（按 Cloudflare 13 个地理区域/国家，数据中心粒度仅企业版），不是普通 DNS 记录能力，也没有按国内运营商的线路。结论：不支持。

### name.com

- 依据：name.com Core API OpenAPI 规范 [namecom.api.yaml](https://namedotcom-cdn.name.tools/api-info/namecom.api.yaml)（`info.version` 1.36.0，2026-10-22 取回；文档入口 [docs.name.com](https://docs.name.com)）。旧版 [v4 API](https://www.name.com/api-docs/dns) 已标 Deprecated，适配器用新版 `/core/v1`。
- 认证：HTTP Basic，账号用户名 + API Token（沙箱用户名加 `-test`、地址 `api.dev.name.com`）；生产 `api.name.com`。凭据字段 `username`、`api_token`，走既有凭据加密。
- 记录：`GET/POST /core/v1/domains/{domain}/records`，`GET/PUT/DELETE …/records/{id}`（`id` 为 int32，PUT 整条替换，DELETE 成功 204）；字段 `host`/`type`/`answer`/`ttl`/`priority`，没有线路或地域字段。结论：不支持分线路，适配器 `Line` false，只接受默认线路；带线路的写入在发请求前返回 `dns_provider_remote_unsupported`。主控 DNS 配置页、添加服务商弹窗和线路解析页提示“该服务商不支持按运营商分线路”，并禁用 IP 权重开关与运营商线路选择。
- 分页：`perPage`（默认 500，上限 1000）/`page`，响应 `totalCount`/`from`/`to`/`nextPage`/`lastPage`；列表没有 host/type 过滤，适配器每次整区分页（每页 100，最多 100 页），本地按名称过滤。
- TTL：规范写明“name.com allows a minimum TTL of 300”。低于 300 的请求（攻击自动升级 D 级黑洞 60 秒，`cnameallocation.BlackholeTTL`）按 300 写入，读回比对也用 300，不会每轮判定不一致；`dnsproviderremote.EffectiveTTL(provider, ttl)` 返回实际 TTL 与 `ttl_clamped`，供上层在状态里注明。平台 DNS 配置 TTL 下限也是 300。
- 错误：体为 `{message, details}`（不保留原文）；401/403 → `credentials_rejected`，429 → `rate_limited`（重试时间取 `Retry-After`，没有则用 `X-RateLimit-Reset` Unix 秒），5xx → `unavailable`；单条读/删的 404 视为记录不存在（删除幂等）。限流 20 次/秒。
- 凭据校验：`GET /core/v1/hello`，返回的 `username` 须与凭据一致。
- 未核实：没有真实账号，未调用 name.com 接口；全部用按规范写的假服务器测试。

### DNS.COM

- [添加解析](https://www.dns.com/docs/12/15)、[修改解析](https://www.dns.com/docs/12/16)、[解析列表](https://www.dns.com/docs/12/14)：`view_id`“线路ID，选填，默认为默认线路”；`mx`“当 type 为 MX 时为优先值，其他为权重值（1–55）”。
- [获取域名线路](https://www.dns.com/docs/7/11)：`/api/domain/getView/` 按域名返回 `id`、`parent_id`、`view_name`、`view_name_en`。
- 官方没有公布 `view_id` 取值，默认线路 ID 在开源实现间也不一致（kldns 用 `0`，LaochenDNS 用 `1`）；10-21 再查文档与 GitHub 仍无取值。所以适配器不硬编码 ID：写非默认线路前调 `getView`，只取 `enable` 非 0 的项，按 `view_name`（默认/电信/中国电信/联通/中国联通/移动/中国移动/境外/海外/国外）或 `view_name_en`（default/telecom/china telecom/…/overseas/abroad）匹配；同一统一线路匹配到两个 ID 时拒绝（不猜）。结果按账号+域名缓存 1 小时（`dnscom_lines.go`）。默认线路写入不传 `view_id`（文档：默认为默认线路）；读回 `view_id` 为空，或 getView 未列默认项时为 `0`，视为默认线路；其余未匹配的 ID 读回 `dns_com:<id>`。
- 套餐（依据官网套餐）：免费版智能线路只有三大运营商；企业版加拓展/区域/大洲；旗舰版加海外；定制版按需。凭据增加可选字段 `plan`（`free`/`enterprise`/`flagship`，缺省 `free`，随凭据加密保存、回显为标识字段，无迁移）。线路开放：免费 = 默认+电信+联通+移动；企业 = 再加拓展（教育网、铁通、鹏博士、广电网）、区域（华北/华东/华南/华中/西北/西南/东北）、大洲（亚洲/欧洲/北美洲/南美洲/非洲/大洋洲），这些线路不是统一线路（分线路 worker 仍只写五条统一线路），对账操作按线路名写入，`view_id` 同样按 `getView` 名称匹配（`dnscom_lines.go` `dnsComEnterpriseLines`）；旗舰 = 企业全部再加境外。档位不含的线路在发请求前返回 `dns_provider_remote_line_not_in_plan`。
- 账号实际不支持时以 API 为准：档位允许但 `getView` 没列出该线路，或写入返回 `code≠0`，同样归为 `line_not_in_plan`。分线路 worker（`cnamelines`、`aggregatededge`）把它记为 `dns_line_not_in_plan`、10 分钟后重试，不当作服务商故障；该线路没有记录，访客落到默认线路。DNS配置页“DNS错误”显示“分线路解析：套餐不支持该线路，已按默认线路解析”。
- 未核实：没有凭据，未调用真实接口；线路名匹配表依据官网线路叫法与 getView 字段说明，用按文档结构写的假服务器测试。需用真实账号核对一次 `getView` 返回的 `view_name`（含企业版拓展/区域/大洲线路名，见 BACKLOG-1035 C19）；账号未列出的名称按 `line_not_in_plan` 拒绝，不会写到别的线路。

### DNSLA

- [API 文档](https://www.dns.la/docs/ApiDoc)：添加/修改解析 `lineId`“线路id，参考线路文档”，`weight`“A CNAME AAAA URL转发 记录有效，1~10”；解析列表返回 `lineId`、`lineCode`、`lineName`，默认线路的三者为空串。
- 获取所有线路 `GET https://api.dns.la/api/allLineList`（无需认证，2026-10-17 取回）：顶级线路 电信 `tele`、联通 `unic`、移动 `mobi`、国内 `dom`、海外 `abr`、搜索引擎 `spi`、其它 `min`。
- 差异：DNSLA 把“港澳台”放在“国内”下，“海外”只含六大洲。所以 DNSLA 的 `境外` 不覆盖港澳台，这部分访客走默认线路（市场每个节点都写默认线路，仍能解析）。

## 适配器实现（`services/control-api/internal/dnsproviderremote`）

- 统一枚举与映射：`lines.go`（`providerLineCodes`、`SupportedLines`）。能力矩阵：`model.go` 的 `ProviderCapabilityMatrix`。
- 写：新建/修改带映射后的线路码；不可映射的线路（如“教育网”或带厂商前缀的外来线路）在发请求前返回 `unsupported`。删除不校验线路，可删外来线路上的记录。
- 读：厂商线路码映射回统一值；映射不到的保留为 `<provider>:<code>`（如 `aliyun:cn_telecom_anhui`、`huawei:Dianxin_Shanxi`、`dns_la:cnshhdgtele`），与任何统一值都不相等，视为独立线路。
- 新建时只在同一线路内判定“已存在/冲突”，其他线路上的同名同类型记录互不影响。
- DNSPod 不变：线路名原样透传（含“广东电信”等细分线路），仍是唯一 `Weight: true` 的厂商。
- 前端 节点管理 > DNS配置 在服务商下拉下方显示该厂商的分线路支持情况（`dnsProviderSpecs.ts` 的 `lines`，需与 `SupportedLines` 保持一致）。

## 测试

单元测试用 httptest 模拟厂商 API，逐字段断言签名、动作参数、请求体和分页：

```sh
go -C services/control-api test -count=1 -run 'Line|SupportedLines|ProviderCapability' ./internal/dnsproviderremote/
```

真实账号验收（本次未执行，没有凭据）：

- `cmd/dns-provider-propagation-live`（`scripts/dns-provider-propagation-live.sh`，手册 `docs/runbooks/dns-provider-live-propagation.md`）只验 TXT 在默认线路上的写入与传播；`cmd/dns-reconcile-live` 只支持 Cloudflare。两者都不覆盖分线路。
- 分线路的真实验收需要从不同运营商出口查询权威 DNS（例如电信/联通/移动各一个拨测点，加一个境外点），比对同一 owner 在各线路的应答；在没有这类拨测点之前，只能在厂商控制台或列表接口核对记录的线路字段。

