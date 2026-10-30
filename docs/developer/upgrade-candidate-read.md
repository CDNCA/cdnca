# 安装实例升级候选只读协议

契约版本：2026-09-29，cdnca.upgrade.candidate-snapshot/v1。入口为
POST /activation/v1/installations/{installation_id}/upgrade-candidates:resolve。
完整接口见 api/license-upgrade-candidates.openapi.yaml；主许可 OpenAPI 引用同一份定义。

## 权威来源与读取边界

当前主控版本由运行中 control-api 二进制内嵌的 controlVersion 提供，不从节点计划、Web 发布编号或配置值推断。主控以自己的安装身份读取授权服务，浏览器不接触安装私钥或 operator 会话。

授权服务在 REPEATABLE READ、READ ONLY 事务内验证安装 PoP，再调用与 PrepareUpgradeGrant、CommitUpgradeGrant 共用的 loadUpgradeTargetEligibility。事务不写入 grant、bundle、plan、任务、审计账本或幂等记录，也不主动下载或探测制品。签名快照是查询响应，不是可执行升级授权。每次刷新重新读取；启动升级仍需重新申请并校验正式授权。

解析严格保留已有语义：无实例覆盖时 follow_channel；存在 pinned 时仍要求通道有当前目标，且 pinned 制品属于获准通道。安装、客户、许可证与通道状态、许可版本范围、协议范围、published 状态、原制品签名、V2 文件大小证明、仓库验证回执及签名密钥窗口均须满足。检查 horizon 仍是 min(now + 15 分钟, 许可证截止)，不因预览放宽。

## 请求认证与响应验签

请求体固定顺序为 schema、component、current_version、protocol_version。使用 CanonicalUpgradeCandidateRequest 编码；未知字段、额外空白、重复字段、大小写变体、查询参数及 Content-Encoding 均拒绝。请求体最多 4096 字节。

请求头 X-CDNCA-Installation-ID、X-Request-ID、X-CDNCA-Requested-At、X-CDNCA-Proof 必须各出现一次。安装 UUID 与路径一致；请求 ID 使用每次新生成的 UUID；时间为 Unix 秒且与服务端相差不超过 300 秒。调用 UpgradeCandidateRequestProofMessage 后用安装 Ed25519 私钥签名，编码为无填充 base64url。独立 PoP 域绑定 POST、精确路径、请求 ID、安装、时间与完整请求体摘要，不能挪用 grant/bundle 的证明。

HTTP 200 直接返回 canonical SignedUpgradeCandidate JSON，无包装和末尾换行，Cache-Control: no-store。response.request_sha256 是整个 PoP 消息摘要的 base64url；不能拿仅请求体 SHA-256 比对。

主控须：

1. DecodeUpgradeCandidate 严格解码，限制响应为 64 KiB。
2. UpgradeCandidateSigningMessage + TrustStore.VerifyDetached 检查外层签名与密钥时间窗。
3. 有 candidate 时，以 UpgradeCandidateArtifactSigningMessage 和 AttestedAt 检查 V2 大小证明的签名密钥时间窗。
4. KeyRing.VerifyUpgradeCandidate 验证两层签名、安装/请求/组件/当前版本/协议绑定，以及快照有效期和状态一致性。

快照最多 60 秒；允许 issued_at 最多超前客户端 5 秒，now >= expires_at 即过期。禁止离线延长。无法取得有效快照时应显示无法确认候选，不能显示“已是最新”。浏览器只拿版本、状态、时间等安全投影，不暴露下载地址、签名或完整授权信息。

## 状态与证明

| status | reason | 含义 |
| --- | --- | --- |
| available | upgrade_available | 目标版本高于当前版本 |
| up_to_date | same_version | 当前授权目标与运行版本相同 |
| rollback_required | target_is_older | 运营指定目标低于运行版本；不是自动降级许可 |
| unavailable | 固定原因码 | 当前无符合全部规则的目标 |

unavailable 原因包括 target_unset、license_inactive、customer_inactive、channel_inactive、target_not_allowed、artifact_unavailable、artifact_unverified、protocol_incompatible、version_not_allowed、signing_key_unavailable。负面快照省略 authority 与 candidate，不能补零或虚造制品/修订。

正面快照包含真实许可 revision、VersionRange、通道 revision、目标模式和可选实例 target revision。隐式 follow_channel 没有数据库 target revision，必须省略。制品使用真实已签名 V2 manifest，包含 artifact_size_bytes；外层另绑定制品 revision、published_at、attested_at、仓库已验签 receipt bytes 的 SHA-256、repository_verified_at 和 verified_until。已有大小/仓库证明只在 draft 阶段创建，发布后不允许替换；原幂等请求可重放历史事实。

未知安装与无效 PoP 都返回 401 invalid_proof；签名时间过旧/超前返回 401 request_expired；有效身份但安装停用返回 403 installation_denied。格式错误返回 400 invalid_request，数据库/签名器故障返回 503 upgrade_candidate_unavailable，不透传英文内部错误。

## 验证

共享协议用固定时钟覆盖所有状态、失效边界、外层/制品签名、未知密钥、跨安装/请求/版本/协议篡改、非 canonical 输入及不可作为执行授权。License 服务测试使用真实隔离 PostgreSQL schema，覆盖四种状态、全部负面原因、pinned 成员关系、许可证与通道变更、证据有效窗口、发布后替换拒绝、撤回后刷新及正式 grant 重验；重复读取前后比较所有表记录数，同时 READ ONLY 事务强制禁止更新。HTTP 测试覆盖安装 PoP、operator 不能替代身份、格式/头/时间边界和 canonical 响应。

本地隔离测试不代替云端最终验收；发布前须在云端验证主控真实版本、安装身份读取、授权服务不可用与目标变更后的页面结果。
