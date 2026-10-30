# ADR-0004：Signer Revocation Bootstrap Checkpoint v2

- 状态：已接受，包含确定性 wire、离线导入、版本化 transport 与 control LKG projection
- 日期：2026-07-23
- 关联：`services/license-service/internal/signercheckpoint`、`services/control-api/internal/signercheckpoint`

## 决策

冷启动不跳过 v1 head，也不把历史 v1 过期视为可忽略。授权中心使用新版本
`cdnca.signer-revocation-checkpoint/v2`，在一个 checkpoint 中完整携带
`1..head` 的原始 `SignedSignerRevocationManifest` v1 链和完整 canonical
`cdnca.signing-keyset/v2`。checkpoint 固定字段为：

`schema`、`revision`、`previous_revision`、`previous_checkpoint_sha256`、
`keyset`、`keyset_sha256`、`head_sequence`、`head_manifest_sha256`、
`manifests`、`issued_at`、`expires_at`。

外层对象仍是 `checkpoint`、`envelope`、`signature`。envelope 固定使用
`cdnca.signer-revocation-checkpoint-envelope/v2`、`Ed25519` 和
`authority_kind=offline_root`，绑定 authority key id/generation 及
`checkpoint_sha256`。签名输入是 envelope 的 exact canonical JSON bytes，
不再套一层应用级 hash。摘要和签名均为无 padding base64url。

checkpoint 的 `revision` 严格递增；revision 1 的两个 previous 字段必须为
`null`，后续 revision 必须指向上一 checkpoint 摘要。`head_sequence=0` 时
manifests 必须为空且 head digest 为空；否则必须完整包含升序的 1..head，
每条 v1 manifest 的 canonical digest、signature、authority、时间和 previous
chain 均独立验证，最后一条 digest 必须等于 `head_manifest_sha256`。

## 接受规则

control 侧先验证 outer 的 offline-root pin、canonical、digest、签名、issued/
expiry 和可注入 TTL 上限，再验证 keyset 的 canonical digest 和完整 rotation
chain，最后逐条验证 inner。只有 outer 当前新鲜时，历史 inner 的 expiry 才被
豁免；inner 的 canonical、digest、signature、authority、future issued、
effective 时间、previous chain 和完整 prefix 永不豁免。

lineage manifest 的签发时间窗口是 `NotBefore <= manifest.IssuedAt < SignUntil`；
边界分别包含和不包含。`VerifyUntil` 是当前 outer 接受时点的验证窗口：若存在，
必须满足 `now < VerifyUntil`，`nil` 表示不设验证截止；fresh outer 对 inner expiry
的豁免不改变这两个 key window 规则。

已有 LKG 不要求逐个取得历史 outer checkpoint。相同 revision 只有 exact signed
bytes 才是 replay；相同 revision 的其他 bytes 和较低 revision 均拒绝。较高的
任意 revision 可以作为 full-state catch-up，但仍必须完整验证 fresh outer、keyset
不回滚、head 不下降、已有 inner prefix 逐字节一致以及候选完整 `1..head` chain；
不能证明已有 prefix 是 exact extension 时拒绝。fresh consumer 同样可以直接接受
当前任意较高 revision 的完整 checkpoint。这样长期离线或冷启动 consumer 不需要
取得已经超过 15 分钟 outer TTL 的中间 checkpoint。相同 head 的 renewal 和只扩展
keyset 的较高 revision 可以接受。

## 不变量与风险边界

- signer 只接受离线 root authority，私钥留在调用方注入的 signer/KMS 中。
- license builder 只消费调用方提供的原子 `Snapshot`，不读取数据库。
- control verifier 的 keyset pins 和 offline root 必须来自独立部署配置；候选
  checkpoint 不能增加信任锚点。
- size bounds、strict JSON、固定时间和无 padding base64url 是 wire 不变量。
- License 端只验证并发布外部 offline signer/KMS 产生的 bytes；在线进程只配置
  public pin，绝不持有 offline-root private key。
- Installation PoP 和 durable delivery attempt 绑定请求 installation；全局 signed
  checkpoint 不按 installation 重签，且不扩大任何 installation 权限。
- Control package 提供原子 projection、恢复和 runtime coordinator；共享
  `control-api` composition root 的正式挂载仍是独立后续工作，不能据此声称生产完成。

## 后续唯一 owner 清单

1. **License 014**：原子保存预签 checkpoint、完整 source identity、operator
   import/audit 和 installation delivery attempt；GET 对 fresh consumer 或任一已确认
   ancestor 直接返回最新 fresh full checkpoint，不逐级返回历史 outer。
2. **Control 077**：先完整验证 outer、keyset 和全部 inner，再在一个 transaction
   保存完整 projection；commit 后才整体 `Runtime.Replace`，恢复使用持久
   `accepted_at` 重验 LKG，不能因 transport outer 后续过期而删除已接受事实。
3. `control-api` 共享 main/server 挂载不在本切片 ownership 内，仍需后续集成和独立
   生产验收。
