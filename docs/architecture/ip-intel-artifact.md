# IP 情报库制品格式（ip-intel，schema v2）

给 G3-b（主控同步与节点下发）、G3-c（节点查表与 WAF/L4 匹配）、G3-d（页面）用。格式和签名的唯一实现在 `libs/entitlement/ipintel`（只依赖 Go 标准库），本文与代码不一致时以代码和它的测试为准。

## 1. 组成

一次构建产生两样东西：

| 名称 | 内容 | 谁签 |
|---|---|---|
| 制品（artifact） | 二进制区间表，单文件，节点直接 mmap | 不单独签，由发布信封的 sha256 绑定 |
| 发布信封（SignedRelease） | 描述制品的 JSON（revision、sha256、大小、条目数、能力版本）+ Ed25519 签名 | 授权端现有在线签名 key（`entitlement.Signer`，`signing_keys` 表里 status=active 那把） |

能力：`IP_INTEL`（proto 能力号 35），能力版本 `2`（`ipintel.CapabilityVersion`，对应 `FormatVersion = 2`）。节点声明 `IP_INTEL >= 2` 才能收标签/省市规则；格式升级不兼容时同时提升 `FormatVersion` 和能力版本。v1 从未发布，不做兼容。

## 2. 制品二进制布局

全部整数小端；地址按网络序（大端）原样存储，所以可以直接和 `ngx.var.binary_remote_addr` 做 `memcmp`。各段起点 8 字节对齐。

### 2.1 头部（64 字节）

| 偏移 | 类型 | 字段 | 说明 |
|---|---|---|---|
| 0 | char[8] | magic | `CDNIPI01` |
| 8 | u16 | format_version | 2 |
| 10 | u16 | header_size | 64 |
| 12 | u32 | attr_count | 属性字典条数（>0） |
| 16 | u32 | v4_count | IPv4 区间数 |
| 20 | u32 | v6_count | IPv6 区间数（v4+v6>0） |
| 24 | u64 | revision | 与元数据、发布信封一致 |
| 32 | u32 | attr_off | = 64 |
| 36 | u32 | v4_off | = attr_off + attr_count×24 |
| 40 | u32 | v6_off | = v4_off + align8(v4_count×12) |
| 44 | u32 | meta_off | = v6_off + align8(v6_count×36) |
| 48 | u32 | meta_len | 元数据 JSON 长度；meta_off+meta_len = 文件长度 |
| 52 | u8[12] | reserved | 必须全 0 |

对齐填充字节必须是 0。文件上限 256 MiB（`MaxArtifactBytes`）。

### 2.2 属性字典（每条 24 字节）

| 偏移 | 类型 | 字段 |
|---|---|---|
| 0 | u64 | tags（标签位图，见第 3 节） |
| 8 | u32 | asn（0 = 未知） |
| 12 | char[2] | country（ISO 3166-1 alpha-2 大写；`\0\0` = 未知） |
| 14 | u8[2] | reserved（0） |
| 16 | u32 | province（GB/T 2260 六位码，如 440000；0 = 未知） |
| 20 | u32 | city（GB/T 2260 六位码，如 440300；0 = 未知） |

tags/asn/country 不会同时为空。province 非 0 时 country 必须非空且 province 是 `xx0000`；city 非 0 时 province 必须非 0 且 city 的前两位与 province 相同。目前只有 CN 有省市。直辖市的 city 是 `xx0100`，省直辖县级市（仙桃 429004 等）用它自己的 6 位码。代码对应的名称在元数据 `regions` 里（字典里出现的每个代码都有名称）。

字典按 (tags, asn, country, province, city) 排序、去重；区间用下标引用。

### 2.3 区间表

- IPv4 记录 12 字节：`start[4] last[4] attr_index:u32`
- IPv6 记录 36 字节：`start[16] last[16] attr_index:u32`

`start <= last`，闭区间。记录按 start 严格递增，区间之间不重叠（前一条的 last < 后一条的 start），中间可以有空洞（空洞 = 库里没有这个地址）。相邻且属性相同的区间在构建时已合并。

### 2.4 元数据（文件末尾 JSON）

`ipintel.Metadata`，字段顺序固定：`schema`（`cdnca.ip-intel.artifact/v2`）、`format_version`、`capability`、`capability_version`、`revision`、`build_id`、`generated_at`（RFC3339 UTC 秒）、`data_updated_at`（上游数据最后变化时间）、`stale_after`（过期时间，见第 6.1 节）、`source_release`（上游快照 id，即 dnspup release）、`data_sha256`、`counts{attrs,ipv4_ranges,ipv6_ranges}`、`tags`（第 3 节的位表）、`regions`（`{"440300":"深圳市",...}`，字典用到的全部省市代码）、`sources`（数据源清单：id、name、url、license（SPDX）、attribution、ref（版本）、role、files（可省略））、`notice`（随制品分发的许可证与署名原文，≤64 KiB）。

`data_sha256` = sha256(文件[64 : meta_off])，即字典 + 两张区间表（含填充），只取决于数据本身，不随 revision、时间、数据源清单变化。主控可以用它判断"内容是否真的变了"。

## 3. 标签位（已冻结）

| 位 | 名称（规则里引用） | 显示 |
|---|---|---|
| 0 | `carrier:cn-telecom` | 中国电信 |
| 1 | `carrier:cn-unicom` | 中国联通 |
| 2 | `carrier:cn-mobile` | 中国移动 |
| 3 | `carrier:cn-cernet` | 教育网 |
| 4 | `carrier:cn-cstnet` | 科技网 |
| 5 | `carrier:cn-drpeng` | 鹏博士 |
| 6 | `carrier:cn-cbn` | 中国广电（v2 新增） |
| 7–15 | 保留给运营商 | |
| 16 | `idc:cn` | 国内 IDC |
| 17 | `idc:global` | 境外 IDC |
| 18–62 | 保留 | |
| 63 | （构建专用，不入库） | `TagIDCByCountry`：来源只知道"是 IDC"时用它，构建时按最终国家落成 `idc:cn`（country=CN）或 `idc:global`（其他或未知） |

- `CarrierMask = 0xFFFF`。运营商位不互斥（一个前缀可能同时被多家宣告），日志里只显示一个运营商时取最低的已置位。
- 位一经发布不改含义；新增标签用新位，删除的位留空不复用。读端遇到不认识的位要忽略，不能报错。
- ASN、国家、省市不占位：规则写 `asn:13335`、`country:US`、`province:440000`、`city:440300`，节点比对字典里的对应字段。
- Go 侧：`ipintel.TagByName`、`TagNames`、`TagDefinitions`。

## 4. 查表算法（节点必须与此一致）

1. IPv4-mapped IPv6（`::ffff:a.b.c.d`）先转成 IPv4 再查 v4 表。
2. 在对应表里二分查找最后一条 `start <= addr` 的记录（等价于"第一条 start > addr"的前一条）。
3. 找不到，或者 `addr > last`：未命中。
4. 命中则返回 `attrs[attr_index]`。

时间复杂度 O(log n)，n ≈ 30–40 万时约 19 次比较。参考实现 `(*Table).Lookup`，边界用例见 `libs/entitlement/ipintel/format_test.go` 的 `TestBuildLookupBoundaries`（包括 0.255.255.255、255.255.255.255、ffff…ffff、区间首尾、空洞）。G3-c 的 Lua 实现建议直接复用这组地址做对拍。

构建时的合并语义（只影响授权端，节点不用实现）：国家、省、市作为一组"地理声明"一起合并，不会拆开拼接。嵌套前缀扁平化时，tags 取并集，asn 取最具体前缀上的非 0 值，地理声明按来源优先级（rank 越小越权威，同级取更具体的前缀）；同一前缀多条记录时 tags 并集、asn 取最小非 0、地理声明取 rank 最小者，同级时依次比较国家（字典序小者）、省（非 0 优先）、市（非 0 优先），保证确定性。`TagIDCByCountry` 在最终合并后才按国家落位。

## 5. 发布信封与签名

```json
{"release":{"artifact_bytes":6853809,"artifact_sha256":"<hex>","build_id":"ipintel-20261017-000007",
  "capability":"IP_INTEL","capability_version":2,"counts":{"attrs":62644,"ipv4_ranges":283157,"ipv6_ranges":68048},
  "data_sha256":"<hex>","data_updated_at":1792195200,"domain":"cdnca-ip-intel-release-signature/v1","format_version":2,
  "generated_at":1792206000,"key_id":"<授权端签名 key_id>","revision":7,
  "schema":"cdnca.ip-intel.release/v2","signed_at":1792206060,"source_release":"ipx-<24 hex>","stale_after":1794787200},
 "signature":"<base64url 无填充，64 字节 Ed25519>"}
```

- 签名内容 = `json.Marshal(release)`（字段已按字母序，`ipintel.CanonicalRelease`）。`domain` 在被签内容里，把它与同一把 key 签的租约、规则目录等文档隔开。
- 线上只接受规范编码：`DecodeSignedRelease` 拒绝未知字段、重复键、空白、多个文档（编码后必须与输入逐字节相同）。
- 验签不看过期：节点/主控一直保留最后一个验过的库（LKG），直到更高 revision 验签通过；是否"就绪"由 `stale_after` 判断（第 6.1 节）。key 轮换后授权端用新 key 重签同一个 revision（signed_at、key_id 变，制品不变；随发布接口实现）。
- 授权端签名 key 就是租约和安全规则目录用的那把，主控已有对应信任（`entitlementguard.TrustStore`），不新增密钥、不新增信任根。

## 6. 消费方校验顺序（G3-b）

1. `DecodeSignedRelease(bytes)`。
2. `ipintel.Verify(signed, trustStore, now)`：形状、signed_at 不超前 5 分钟、`TrustStore.VerifyDetached(key_id, payload, sig, signed_at, now)`（key 窗口由信任库判断）。
3. revision 必须大于当前已应用的；等于时只在 artifact_sha256 相同的情况下视为重复（重签），否则拒绝。
4. 下载制品后 `ipintel.VerifyArtifact(signed.Release, data)`：长度、sha256、完整 `Open`（布局、排序、data_sha256、元数据与信封一致）。
5. 原子替换（写临时文件 → fsync → rename），失败保留 LKG。

节点侧是否再验一遍授权端签名，还是只验主控的节点制品签名，由 G3-b 决定：制品本身不含签名，两种方式都不需要改格式。

### 6.1 就绪 / 版本 / 过期（拒绝发布规则用）

用户已拍板：节点库未就绪时拒绝发布运营商/IDC/省市规则（返回 422 并列出节点），就绪后自动重新发布。判断用到的字段都在被签名的发布信封里（制品元数据里有同样的值，`VerifyArtifact` 校验两者一致）：

| 字段 | 含义 |
|---|---|
| `revision` | 库版本，单调递增；节点上报"当前已应用 revision" |
| `capability_version` | 节点必须声明 `IP_INTEL >= 该值` |
| `data_updated_at` | 上游数据最后变化时间（Unix 秒） |
| `stale_after` | 过期时间（Unix 秒）= `data_updated_at` + 最长数据年龄（默认 30 天，`ipintel.DefaultMaxDataAge`） |
| `source_release` | 上游快照 id（dnspup release），用于排查 |

"就绪" = 节点声明了 `IP_INTEL >= capability_version`，且已验签应用了某个 revision，即为就绪。库不按时间过期（新库替换旧库即可），构建时 `stale_after` 固定写格式上限 `9999-12-31T23:59:59Z`，上游数据再旧也照常构建；`Release.Fresh` 因此恒为真，仅保留格式字段。

## 7. 体积参考

- dnspup 测试夹具（`libs/entitlement/ipintel/builder/testdata/dnspup-snapshot.ndjson.gz`，161 行，由 dnspup 导出程序在对拍测试里生成）：6,855 字节 gzip。
- 合成上限：50 万 IPv4 + 15 万 IPv6 区间、属性几乎各不相同（最坏情况，54 万条属性）时制品约 24.3 MB，构建 9.7 秒。真实数据属性重复度高，会明显更小。
- 真实 dnspup 全量还没实测（本地没有 dnspup 数据库），首次对接时补测。

## 8. 授权端构建（G3-a）

- 数据来源是可插拔的 `Source` 接口（`libs/entitlement/ipintel/builder/source.go`）：`Collect(ctx)` 返回数据源清单、许可证说明、省市名称表、上游数据时间、上游 release 和前缀事实。
- 生产数据源 `FileSource`（`dnspup.go`，`NewFileSource(path string, maxBytes int64) (*FileSource, error)`）：读管理员上传的 dnspup 导出文件 `dnspup-ipintel-<release>.ndjson.gz`（dnspup 仓库 `backend/cmd/ipintel-export`，说明见其 `docs/ip-intel-export.md`）。文件内容是 dnspup 线上 ip-info 对每个地址的结果，已展平成互不重叠的前缀（与 ip-info 对拍一致）。每次 `Collect` 都重新读取并严格校验；文件名仍是 `dnspup-ipintel-<release>` 形式时 release 必须与文件内容一致；`maxBytes<=0` 用默认 512 MiB。上传入口与存放位置由发布接口（G3-b）负责。
- dnspup 行到事实的映射：每行一个合并后的答案（`source_id` 为 `dnspup-ip-library`）→ 国家/省/市（rank 0）、ASN、`carrier:*`（`cn-telecom/unicom/mobile/cernet/cstnet/drpeng/cbn`）、`idc` → `TagIDCByCountry`。所以国内云厂商段（国家 CN）落 `idc:cn`，其余落 `idc:global`。
- 解析严格：未知字段、非规范前缀、未列出的 source_id、缺 end 行或行数不符、gzip 截断、超出大小都整份拒绝，上一个库继续服务。
- 许可证双保险：dnspup 只导出允许的来源；授权端 `CheckRedistributable` 在解析和 `Compile` 时再拦一次——许可证必须是 SPDX 白名单（CC-BY-4.0、CC0-1.0、MIT、PDDL-1.0、Unlicense、WTFPL），或是用户 2026-10-17 确认可分发的 dnspup 自有来源且许可证标识完全对应：`ip2region-v4`=`LicenseRef-ip2region-commercial`、`supplemental-0701`=`LicenseRef-dnspup-supplemental-0701`、`manual-corrections`=`LicenseRef-dnspup-manual`、`dnspup-ip-library`=`LicenseRef-dnspup`；其他 `LicenseRef-*` 一律拒绝。需要署名的（除 CC0/PDDL/Unlicense/WTFPL）必须带 attribution，`itdog*` 这些 id 无论标什么许可证都拒绝。
- 2026-10-17 用户确认 RIPE RIS（`ripe-ris`）、PeeringDB（`peeringdb`）、Tor 出口列表（`tor-exitlist`）可随节点制品分发，各自只认对应的 `LicenseRef-*` 且必须带署名（`source.go` licensedSources）。
- 测试和预发用 `FixtureSource`（静态 JSON，schema `cdnca.ip-intel.fixture/v1`，支持 province/city/regions/data_updated_at）。原 ipverse/china-operator-ip 下载器已删除（d96f978f 可取回）。
- `Fingerprint(collection)` 与事实顺序、revision、时间无关；`Compile` 是纯函数：同一份 collection + 同一个 (revision, build_id, generated_at) 输出逐字节相同。

## 9. 署名展示要求（G3-d）

CC BY 4.0（DB-IP、RouteViews）要求署名，MIT（X4BNet）要求附版权与许可声明。运营后台"IP 情报库"页必须显示：当前 revision、`source_release`、生成时间、`data_updated_at`、`stale_after`（过期标红），以及 `sources` 里每个来源的名称、链接、许可证（SPDX）、版本和 `attribution` 原文；`notice` 全文提供"查看许可证"展开。主控页面同样展示（客户在自己的主控里能看到数据来源）。节点不需要展示，但制品里保留 `notice`，随制品一起分发即满足 MIT 的附带声明要求。

## 10. 发布、同步与节点下发（G3-b，2026-10-17）

已定：库**不按时间过期**（不再用 `stale_after`/`Release.Fresh` 判断就绪，字段删除由 g3a 处理）；不做定时构建，改为运营者在授权端手动上传 dnspup 导出；主控从授权端同步，节点从主控拉。

### 10.1 授权端（license-service，迁移 900 占位）

- 运营后台“IP 情报库”页（`/ip-intel`，权限 `licensing.ip_intel.view`；上传需 `licensing.ip_intel.manage` + 近期重新验证）：上传 `dnspup-ipintel-<release>.ndjson.gz`（`POST /operator/v1/ip-intel/uploads`，multipart 单个 `file` 部分，≤512 MiB）。文件名里的 release 必须与快照 meta 行一致。
- 解析用 g3a 的 `ParseDnspupSnapshot`（`uploadedSource` 适配；g3a 的 FileSource 合入后替换）。指纹（`Fingerprint`）与当前 revision 相同返回 `unchanged`，不出新版本；与更早某个 revision 相同则拒绝（不允许回滚）。
- 签名：授权端在线签名 key（`signing_keys` active，`entitlement.Signer`），签前查 key 状态、签后用登记公钥自检。没有使用离线“平台发布密钥”：那把 key 只能人工离线签，与“上传即发布”冲突；主控用已有 `entitlementguard.TrustStore` 验签（§5）。
- key 轮换：主控 resolve 时若当前 revision 的签名 key 已不是 active key，授权端原地重签（同 revision、同制品，`key_id/signed_at` 变）后返回。
- 保留最近 3 个 revision 的制品字节，更旧的只留信封。失败（文件名、gzip/格式、许可证白名单、签名 key 不可用）记 `ip_intel_build_state`，页面显示，现有库继续下发。
- 安装端接口（安装私钥证明，同安全规则目录）：`POST /installation/v1/ip-intel-releases:resolve`（返回 canonical SignedRelease 或 not_modified；未发布 404 `ip_intel_unavailable`）、`POST /installation/v1/ip-intel-artifacts:fetch`（返回 `application/vnd.cdnca.ip-intel-artifact` 原始字节）。协议常量在 `libs/entitlement/ipintel/protocol.go`。

### 10.1a 授权端自动拉取（迁移 079；迁移 085）

改为：授权端**定时从 dnspup 拉取**，不再要求管理员去 dnspup 机器导出上传；手动上传保留为兜底。同日再定：拉取走 dnspup **现有客户 API**（`api_key` + `api_secret`），运营页填写 API Key 与 Secret；不用内部 Bearer token，也不用用户名密码。

- dnspup 客户 API 工具 `GET/HEAD /v1/tools/ip-intel-snapshot`（dnspup 分支 `feat/ip-intel-export`，`docs/ip-intel-export.md`、`docs/customer-api-v1.md`）：请求头 `X-API-Key` / `X-API-Secret`；Key 由 dnspup 管理员签发给 cdnca 运营方，**来源模式 IP（授权端出口公网 IP）**，工具只开通 `ip-intel-snapshot`；内容与 `cmd/ipintel-export` 导出文件逐字节相同；`If-None-Match: "<release>"` 未变返回 304；生成中 503 + `Retry-After` + `X-IP-Intel-Status: generating`。dnspup 计量：只有发送文件（200/206）扣一次月配额，HEAD、304、各种失败不扣。错误码在 JSON `error.code` 与响应头 `X-API-Error-Code`。
- 域名绑定的 Key（需 `X-API-Source-Domain/Timestamp/Nonce/Signature` 签名）本次**不支持**：dnspup 返回 401 `signature_required` 等时，页面显示 `key_domain_bound`，要求改发 IP 绑定的 Key。
- `ipintel.HTTPSource`：只允许 https（loopback 可 http，测试用），不跟随重定向；200 用 `ParseDnspupSnapshot`（含 `CheckRedistributable`）解析，ETag 必须等于快照 release；体积上限复用上传上限 `LICENSE_IP_INTEL_MAX_UPLOAD_BYTES`。`Probe` 发 HEAD（测试连接，不耗配额）。错误文本不含 Key/Secret。
- `If-None-Match` 带**最新已发布 revision 的 source_release**（不是上次下载到的 release），所以一次失败不会被后续 304 掩盖。
- 新 release 走与上传相同的 `publishIPIntelCollection`（指纹不变 `unchanged`、旧快照不重发、同一审计 `ip_intel.publish`，actor 为 `system/ip-intel-puller`）。`source_id='dnspup-pull'`，`uploaded_by_operator_id` 为空（迁移 079 只对该 source_id 放开）。拉取额外拒绝 `data_updated_at` 早于当前库的快照（`snapshot_older`），避免 dnspup 多实例短暂不一致时回退；dnspup 侧若删掉最新的人工纠错导致 `data_updated_at` 变早，会一直报 `snapshot_older`，此时用手动上传兜底（上传不做这条检查）。
- 调度 `RunIPIntelPull`（PA-29，基础库只拉一次）：每分钟看一次 `ip_intel_pull_state`。首次成功（发布/未变/304）前，到期（启用后立即、失败重试时间到）的实例用租约 `running_until` 抢占后执行，失败重试 = max(Retry-After, 15 分钟)，生成中 = max(Retry-After, 1 分钟)；首次成功写 `base_pulled_at`（迁移 085）并清空 `next_check_at`，**之后不再定时拉取**，只有运营“立即检查”会再拉一次（失败也不排重试）。以后的更新走主控插件 `module.ipintel.dnspup`（§10.4）。
- 错误码（页面可见）：`credentials_rejected`（401）、`key_domain_bound`、`source_ip_forbidden`（403 source_forbidden）、`tool_not_allowed`、`quota_exceeded`（429 quota_exceeded）、`credential_unavailable`（已存 Secret 解不开）、`snapshot_too_large`、`source_pending`（503 / 429 限流或并发满）、`source_unreachable`、`timeout`、`snapshot_invalid`、`license_not_allowed`、`snapshot_older`、`upload_rejected`、`signer_unavailable`、`release_invalid`、`build_failed`。任何失败都保留当前库（LKG）。
- 凭证存储（迁移 085，守卫 084，`ip_intel_pull_config` 单行）：`url`、`api_key` 明文；Secret 用授权端统一 AES-256-GCM 密钥环（`LICENSE_TOTP_KEY_ID` + `LICENSE_TOTP_KEYS_JSON`，与 TOTP/支付密钥同一 `identity.AESGCMSecretCipher`）加密为 `secret_key_id` + `secret_ciphertext`，明文前缀 `cdnca-ip-intel-pull-secret/v1\0` 绑定用途；`secret_fingerprint` 是带域分隔 sha256 的前 16 位（不是 dnspup 用作签名密钥的 sha256(secret)）。密钥环轮换后旧 Secret 若解不开报 `credential_unavailable`，重新填写即可。
- 运营后台（`licensing.ip_intel.manage`）：
  - `GET /operator/v1/ip-intel` 的 `pull`：`enabled`、`url`、`api_key`、`secret_configured`、`secret_fingerprint`、`settings_updated_at`、`base_pulled_at`（基础库首次拉取时间）、上次检查/结果/release/HTTP 状态/错误、下次检查、是否在运行。**Secret 永不返回**。
  - `PUT /operator/v1/ip-intel/pull-settings`（同源、近期重认证、`Idempotency-Key`、审计 `ip_intel.pull_settings`，审计只记 enabled/url/api_key/secret=unchanged|replaced|cleared）：body `{enabled,url,api_key,api_secret?}`；`api_secret` 省略=沿用，`""`=清除，其他=替换。沿用已存 Secret 只允许同一 API Key 且 URL 同 scheme+host，否则 422 `ip_intel_pull_secret_required`（防止把已存 Secret 发往别的主机）。启用需三项齐全；基础库尚未拉到时，启用或更换 URL/Key/Secret 后立即排一次检查。URL 不允许 query。
  - `POST /operator/v1/ip-intel/pull-tests`（同上门控，审计 `ip_intel.pull_test`）：用表单值（或按同样规则沿用已存 Secret）对 dnspup 发 HEAD，返回 200 `{ok,http_status,release,state,error_code,source_error_code}`。
  - `POST /operator/v1/ip-intel/pull-checks`（同源、`Idempotency-Key`，202）立即检查；未启用 409 `ip_intel_pull_disabled`。
- 配置：URL 与凭证**只在运营页配置**（不再有环境变量默认值，单一来源）；`LICENSE_IP_INTEL_PULL_TIMEOUT`（默认 10m，1m–2h）。旧的 `LICENSE_IP_INTEL_PULL_URL` / `_TOKEN` / `_TOKEN_FILE` / `_INTERVAL` 已删除，配置了会拒绝启动并提示改到运营页（间隔改由主控插件设置）。
- Tor：dnspup 快照 prefix 行的 `tor` 字段解析时接受，**暂不进制品**（格式 v2 没有 Tor 标签位；要用需要新增标签位并升级节点读取，另行决定）。

### 10.2 主控（control-api，迁移 315）

- `internal/ipintelsync`：每 6 小时 resolve；`DecodeSignedRelease` → `Verify`（TrustStore）→ 下载 → `VerifyArtifact` → 写 `ip_intel_library`（单行 LKG）。只接受更高 revision，或同 revision 同制品的重签信封（不重新下载）；触发器禁止回退和删除。所有拒绝（`not_published/invalid_release/invalid_signature/unknown_signing_key/revision_out_of_order/artifact_mismatch/...`）记在 `ip_intel_sync_state`，LKG 不动。
- 读出 LKG 时重新解码信封并 `VerifyArtifact`，库里的行被改坏不会被下发。

### 10.3 主控 → 节点：节点侧制品部署

> PA-01（迁移 349）起，IP 库作为节点制品集条目 `ipintel/base` 下发，传输、回执与门控以 ADR 0007 §4.3/§4.5 为准：ip-intel 清单/分段 media type、`internal/ipinteldist`、`ip_intel_node_distributions` 与 `isIPIntelCommand` 已删除；本节的写入方式（`CreateNodeArtifactRolloutTx`）、`node_artifact` 状态域与“其他读者”核对结论仍然适用（判定改为制品集的集合/段 media type）。下文保留作历史记录。

**判定**：配置里的制品 media type 是 ip-intel 清单/分段（`NodeManifestMediaType`/`NodePartMediaType`）的部署就是“节点侧制品”部署。迁移 326 的触发器保证：这两种 media type 只能出现在平台 access scope（`kind='platform'`）的配置里，且不能和其他 media type 混在同一个配置。没用“平台 scope 不进 node_config_state”做判定，因为现有测试夹具大量把平台 scope 当节点 scope 使用，加这条约束会改变现有行为。

**写入**（`edgedeployment.CreateNodeArtifactRolloutTx`，新函数，不改现有 `CreateRolloutTx` 行为）：
- 不读不写 `node_config_state`（不认领、不受 reconciliation 门影响、`previous_config_version_id` 为空）；
- `queued_per_scope=true`：不进 `node_deployments_one_active_unqueued_per_node_291_idx`，只受 `(node, scope)` 唯一活跃约束（同一节点同一时刻最多一个 ip-intel 下发）；
- 站点发布的“节点有活跃部署”检查（`edgepublish/target.go`、`nodescheduler`）本来就是 `scope=$本租户 OR NOT queued_per_scope`，所以 ip-intel 下发不阻塞站点发布；非多租户 agent 自己串行执行，ip-intel 只是排在队列里。

**状态**（`edgestatus`）：`deriveArtifactDomain` 新增第三个域 `node_artifact`（部署绑定的制品全是 ip-intel media type）。该域：不做 `requireTerminalConfigConvergence`、不允许带运行配置身份、不做 `rollback_failed` 调和、不调 `updateRunningConfig`、不发 tenant 领域事件；其余（锁、绑定校验、去重、序号、状态机 `validAdvance`、rollout 推进）与现有完全相同。

**其他读者**（逐个核对过）：
| 读者 | 影响 | 处理 |
|---|---|---|
| `nodeserving/configsync_store.go` | 按 (node, scope) 最新部署失败会挂节点服务暂停 | 排除含 ip-intel 清单制品的部署（IP 库下载失败不能停节点服务） |
| `edgepublish/cross_scope.go` | 在途 apply 会被当成别的租户配置去解码 | 同上排除 |
| `nodepresence/store.go` 身份绑定 | 只处理带身份的活跃部署；ip-intel 不带身份 | 不变 |
| `nodepresence/capability_regression.go` | 平台 scope 最新 healthy 部署要求 IP_INTEL，agent 回退后能提示 | 不变（预期行为） |
| `nodeidentity` 遥测候选 | 只看 node_config_state 和 healthy 部署的版本，ip-intel 版本无站点 | 不变 |
| `ja4block`、`analyticslog`、按 rollout_id 的各发布读者 | 只看自己的 rollout 或把在途部署当“未就绪” | 不变 |

**回归测试**：现有 `edgestatus`、`edgedeployment` 全部集成测试原样通过；新增测试证明节点侧部署不写 `node_config_state`、不阻塞同节点站点发布、失败不挂服务暂停、状态走到 healthy。

**节点侧**：gatewayclient 对 `isIPIntelCommand`（制品 1 为清单、其余为分段，均 configuration/明文/ed25519）单独执行：逐个制品 FetchArtifact 拼进同一个 durable 文件，按描述符大小切分、逐个验主控签名，交给 `internal/ipintel` 安装，回 STAGED→PRECHECKED→ACTIVATED→HEALTHY（不带运行配置身份）。配置了 `ip_intel` 时声明 `IP_INTEL` v2。

**分发**（`internal/ipinteldist`）：LKG 变化或每 10 分钟扫描：会话声明 `IP_INTEL>=2`、在线、没有该 revision 的 healthy 部署、没有在途部署、上次失败超过退避的节点，逐节点建 rollout。配置版本按 revision 一次生成（清单 + zstd 分段，主控边缘发布 key 签名），`ip_intel_node_distributions` 记 config_version → revision。

**门控**：`validateFeatureCapabilityTargets` 在要求 `IP_INTEL` 时，额外要求每个目标节点已 healthy 应用某个 revision，否则返回 `TargetCapabilityError`（422，列出全部节点，复用 g11 的 capability hold）。节点首次就绪时分发器调 `edgeautopublish.RequestCapabilityRepublicationsTx`（g11 的同一入口）补发等待中的 scope。

### 10.4 节点文件约定（给 G3-c）

目录：`<deployment_root>/ip-intel/`（OpenResty 原生单元可读，0644 文件 / 0755 目录）。

| 文件 | 内容 |
|---|---|
| `current.ipi` | 当前库（§2 格式，`CDNIPI01`），只通过 rename 替换，不原地写 |
| `previous.ipi` | 被替换的上一版（LKG，硬链接） |
| `state.json` | `{"schema":"cdnca.edge.ip-intel-state/v1","revision":N,"artifact_sha256":"…","artifact_bytes":…,"capability_version":2,"source_release":"…","data_updated_at":…,"previous_revision":…,"installed_at":…}`，rename 写入 |

Lua 侧：master/init_worker 里 `open(current.ipi)` + mmap（PROT_READ, MAP_SHARED），整个文件只读共享，不拷进 lua table；定时（如 30 s）读 `state.json` 的 revision，变化时重新 open+mmap 新文件、旧映射在无引用后 munmap。因为替换是 rename，已有映射始终看到完整的旧文件，不会读到半个新文件。`state.json` 与 `current.ipi` 短暂不一致（崩溃于两次 rename 之间）时，以 `current.ipi` 头部的 revision 为准。http 与 stream 子系统共用同一文件。库缺失时运营商/IDC/ASN/省市匹配按“未命中”处理并上报，不静默放行也不误拦。

### 10.4 主控插件 module.ipintel.dnspup（PA-16，control 迁移 367）

- 主控「系统 → IP 库实时更新」（`/sys/ip-intel-updates`，权限 `system.ip_intel_updates.manage`，菜单只在租约含 `module.ipintel.dnspup` 时出现）：填 dnspup 客户 API 地址、Key、Secret（主控 DNS 凭据密钥环 AES-GCM 加密，明文前缀 `cdnca-ip-intel-update-secret/v1\0`，只写不回显，显示 16 位指纹）、拉取间隔（1–720 小时）与对齐时间+时区（默认每天 04:00 Asia/Shanghai）。拉取时刻 = 2026-01-01 对齐时间起每隔一个间隔。
- 接口 `GET/PUT /v1/admin/ip-intel-updates`、`POST .../tests`（HEAD，dnspup 不计费）、`POST .../checks`（立即拉取，202）；写操作 `Idempotency-Key`（按会话）；启用/测试/立即拉取需租约含模块（否则 403 `entitlement_feature_denied`）；已存 Secret 只发往同 Key+同 scheme/host（否则 422 `ip_intel_update_secret_required`）。
- 拉取 worker（`internal/ipintelupdate`，每分钟检查，租约 `running_until` 防多实例并发）：用 `libs/entitlement/ipintel/builder`（自授权端下沉）下载并解析快照，`If-None-Match` 带本地库的 release；只接受数据时间晚于本地库的快照（同数据 `unchanged`，更早 `snapshot_older`）；本地 `Compile` 后写为本地制品 `ipintel/local`（`artifact_catalog_entries.origin='local'`，`requires_feature=module.ipintel.dnspup`，目录同步不撤回、不覆盖），审计 `plugin.artifact.build`；失败保留本地库，重试 = max(Retry-After, 15 分钟)，不晚于下一个计划时刻。
- 下发（`artifactsetdist`）：制品集只放一份 IP 库——`ipintel/base` 与 `ipintel/local` 中 `data_updated_at` 较新的；相同取基础库；本地库打不开取基础库。租约没有该模块时 artifactsync 不列出 `ipintel/local`，自动回落基础库。节点安装器按制品分别要求修订号递增，两者之间切换不受对方修订号限制（`state.json` 记录 `artifact_id`），回执照常列出所用制品。
- 审计：`system.ip_intel_update.settings`（changes 记改前→改后，Secret 只记 replaced/cleared）、`.test`、`.check`、`.pull`（非发布结果），失败也记（reason_code）。
