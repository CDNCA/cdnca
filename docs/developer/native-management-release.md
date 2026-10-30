# 原生主控完整包与独立执行器

`native-standalone` 是独立执行目标，不是把单机伪装成原有 `systemd` HA。原有严格多数和至少两个副本约束不变。此模式不改变节点数据面，也不访问授权中心数据库。

## 包格式与事实

签名仍使用既有 `UpgradePlanArtifactBundle` 和受信任授权公钥。forward/rollback 中制品的大小、SHA-256 和版本覆盖**未压缩完整 tar**；tar 摘要不是 Control API 可执行文件摘要。

版本只接受与构建器、Control API 编译版本一致的三段稳定版本：每段为 `0` 或非零开头的至多 9 位十进制数字。拒绝 `v` 前缀、预发布后缀、构建元数据、前导零、缺失段和超长数字段；同一边界也用于执行器状态读取。

tar 包含 `release.manifest.json`，结构如下。`files` 按路径递增排列，列出除 manifest 自身以外的全部文件。

```json
{
  "schema": "cdnca.native-management.release/v1",
  "version": "2026.10.8",
  "built_at": "2026-10-08T01:00:00Z",
  "source": {
    "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "tree": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "previous_commit": "cccccccccccccccccccccccccccccccccccccccc"
  },
  "platform": {"os": "linux", "arch": "amd64"},
  "files": [
    {"path": "bin/agent-gateway", "sha256": "<64 lowercase hex>", "bytes": 123, "mode": 493},
    {"path": "bin/control-api", "sha256": "<64 lowercase hex>", "bytes": 123, "mode": 493},
    {"path": "migrations/001.up.sql", "sha256": "<64 lowercase hex>", "bytes": 123, "mode": 420},
    {"path": "static/web/index.html", "sha256": "<64 lowercase hex>", "bytes": 123, "mode": 420}
  ]
}
```

示例摘要是占位符，不能作为制品发布。仅接受 regular 文件，模式为 `0644`/`0755`，拒绝路径穿越、重复成员、链接、设备、PAX 扩展、未列出文件、未知 JSON 字段和重复 JSON 键。必须有 Control/Gateway 二进制、Web index 和至少一个迁移 SQL。二进制必须为本机架构的 Linux ELF。

完整包上限 1 GiB、manifest 上限 8 MiB、最多 65535 个内容文件。运行目录的 manifest、逐文件大小、权限、所有者和 SHA-256 都必须与原 tar 一致，不能只验证压缩包曾经成功下载。

### 无源码 v2

`cdnca.native-management.release/v2` 保留上面的字段并增加 `key_id`。`release.manifest.sig` 为普通 0644 文件，不在 `files` 内；内容是标准 Base64 编码的 64 字节 Ed25519 签名，最多 128 字节、仅可附加一个末尾换行。签名消息是 UTF-8 `cdnca.native-management.release/v2\n` 与原始 manifest 字节的拼接，不能解析后重编码再验签。

`ValidateNativeReleaseArchive` 是 v1 专用入口；`ValidateSignedNativeReleaseArchive` 是带独立公钥映射的 v2 专用入口。`DecodeNativeArtifactTrust` 只接受 `{"version":1,"keys":[{"key_id":"...","public_key_pem":"..."}]}`，最多 32 个非重复 Ed25519 key，拒绝空集合、未知字段和重复 JSON 键。不得从候选 tar 读取信任根。

`NativeStandaloneConfig.ArtifactPublicKeys` 及 `CDNCA_NATIVE_UPGRADE_ARTIFACT_TRUST_FILE` 提供制品信任，独立于短时执行计划的授权信任。当前目录、archive、预检、Probe、健康、回滚和崩溃恢复都必须验证实际原始签名；执行计划过期不能令已安装合法版本的只读 Probe 失效，也不能被用来绕过新升级授权。详见 [ADR 0005](../adr/0005-native-sourcefree-artifacts.md)。

## 布局与部署前置条件

```text
<release-root>/
  artifacts/<tar-sha256>.tar
  releases/<tar-sha256>/release.manifest.json
  releases/<tar-sha256>/bin/{control-api,agent-gateway}
  releases/<tar-sha256>/static/web/...
  releases/<tar-sha256>/migrations/...
  current -> <absolute release path>
  previous -> <pre-switch current release path>
```

独立 runner 必须在 Linux 以 root 运行。所有路径是规范绝对路径，目录和可信文件由 root 持有，不允许组/其他用户写入；root-owned sticky 临时目录仅作为父目录被允许。生产建议使用专属 `/run` 状态目录和 `/run/lock/cdnca-management-release.lock`。root runner 的有效组或状态目录 setgid 应保证 API 仅有状态文件的读权限，不得给 API 写入 release、维护状态或 runner 私有状态的能力。

Control/Gateway 的实际 `systemctl show ExecStart` 必须分别使用 `<release-root>/current/bin/control-api` 和 `.../bin/agent-gateway`；健康检查还验证 MainPID 的实际 `/proc/PID/exe` 哈希、active/running、自动重启计数和 Web index 实际响应哈希。服务名和本机健康 URL 必须明确配置。`/usr/local/...` 固定二进制加 Web-only release 的混合布局不能启用本执行器，必须由独占发布负责人先完成可回滚的正式 bootstrap。

v1 源提交必须存在于独立 root-owned 可信 Git object repository 中。运行时以 `git --no-replace-objects` 验证两个 commit 对应 tree、候选为当前 source commit 的严格后代，不能仅凭 manifest 的 `previous_commit` 相等作出祖先结论。v2 将完整 Git/fsck/祖先、精确源码迁移集合验证留在发布端，客户验证独立制品签名；不交付 Git 历史，也不让 runner 自行 fetch。v2 升级回 v1 被拒绝；v1 迁往 v2 前先受控更新 runner/trust，并保留旧 Git 以验证 v1 previous 回滚。

### 业务权限与 root 执行边界

管理端的 `platform.admin` 是平台最高业务权限，等价覆盖 `control.upgrades.check` 与 `control.upgrades.manage`；维护升级页面和 API 不要求管理员登录 root，也不向管理员索取或分发 root helper。浏览器只上传授权端签发的签名计划，服务端完成权限、签名、版本和执行条件校验。

root 仅是主控服务器上的基础设施边界：独立 runner 由 systemd 以 root 运行，用于停止/排空服务、原子切换 `current`/`previous`、校验进程证据和失败回滚。它不是 RBAC 角色，也不是管理员操作的二次审批。离线发布器的 root-only 和哈希固定 helper 校验属于发布负责人构建候选包的供应链门禁；缺少原始 helper 时必须停止发布，不能以管理员权限绕过或替换成未审查脚本。

## 执行与恢复

1. 构造时独占私有状态目录的 `runner.lock`；不自动清除已有 draining 状态。
2. 每次 Run 先验签，再独占发布锁；锁冲突不更改 current 或计划。
3. Expand 验当前完整包、服务布局、目标完整包、源码祖先和保留文件。候选必须保留全部已有路径及旧 hashed Web assets；仅 `bin/control-api`、`bin/agent-gateway` 和 `static/web/` 归属本次升级，其他已有文件必须保持完全一致，也不能新增归属之外的路径。
4. 迁移只允许追加（`nativeAppendedMigrations`）：已有迁移文件内容/大小/模式不变，新增版本紧接当前头连续、成对 up/down；其他变化按血缘拒绝。有追加时 Preflight 检查数据库凭据、工具版本、账本头、对象归属和备份空间，Drain 后依次 `control_stopped` → `database_backed_up`（`pg_dump -Fc` 到状态目录）→ `database_migrated`（候选 `control-api migrate up`），每步持久检查点；有备份后的任何回滚先 `pg_restore` 还原再切回旧包。详见 runbook「数据库迁移（只允许追加）」。
5. 从完整当前 release 克隆到新的同文件系统暂存目录，再写候选文件；完整验证、文件 fsync、所有子目录由深到浅 fsync 后重命名为不可变新 release。任何持久化失败停止切换。旧 release 永不覆盖，失败暂存保留审计。
6. 维护 Gate 只默认放行 GET/HEAD/OPTIONS。写请求持共享文件锁到请求结束；Drain 获取独占锁，等待已有管理写完成，再原子写 draining。未知内部 POST 不享有旁路。损坏、错安装身份、错权限的维护状态对写操作 fail closed。
7. 原子设置 previous/current，重启 Control/Gateway，轮询进程、健康 URL 和实际 Web index。Control/Gateway 必须返回严格 JSON `{"status":"ready"}`，空/HTML/其他状态的 HTTP 200 不能作为就绪证据；任何切换后失败恢复旧完整包并重新验证健康。
8. 健康确认后恢复 active，持久化最终 receipt。重复签名计划仅重放 receipt；已切换但尚未记账、已 resume 但尚未写完成状态的崩溃窗口均可幂等恢复。

已启用 Gate 但没有预置合法状态会拒绝写入。bootstrap 应创建 `cdnca.native-management.maintenance/v1` 的 active 状态，带准确 `installation_id`、空 `plan_id` 和 RFC3339 `observed_at`，并创建同目录 `<maintenance-file>.lock`；首次启动不能凭缺失文件猜测 active。

## 活性与 API 投影

`NativeStandaloneRunner.Probe` / `PublishStatus` 不被长时间 Run mutex 阻塞。status 为 `cdnca.native-management.runner-status/v1`，含版本、tar 摘要、source commit/tree、安装身份、协议、artifact format、observed_at、busy/phase，以及仅供本机校验的 PID、进程启动标识和 runner exe 摘要。只有 `ready=true`、`busy=false`、`phase=idle` 可提交新计划。完整包、服务或健康检查失败不会谎报 ready。传输层还必须提供 `PlanSourceReady func() bool` 来确认最近成功的认证计划读取；nil/false 保持执行器未确认，该回调只能进一步收紧就绪状态，不能绕过包、进程、源码或服务检查。

`ReadNativeStandaloneStatus` 要求 root-owned、`0600`/`0640`、不超过 30 秒的文件，并重新校验真实 `/proc` 的 root PID、boot ID + 启动 tick 和可执行文件摘要，防止时间戳伪活、PID 复用或旧二进制。系统 `/proc` 权限不允许 API 校验时保持未确认，不能放宽成仅信时间戳。

`PublishStatus(path)` 同时输出 `path.state.json` 的 root-owned `0640` 只读 receipt 快照。API 用 `ReadNativeStandaloneState` 读取，必须再与本安装的最新 publication 的 PlanID、BundleSHA256 及 native target 绑定。原 FileStore 目录仍是 `0700`，state 仍是 `0600`。HTTP 响应不得暴露 PID、本机路径、签名包、下载授权或其他凭据。

## 已有验证与边界

库测试覆盖真实临时 Git 祖先、完整包验签/验哈希、迁移拒绝、混合布局拒绝、双锁、维护写排空、进程证据失败、整体回滚、重放与崩溃恢复。服务命令和 HTTP 健康由隔离 fixture 提供，不等同于生产部署或真实浏览器验收。Linux/root 的 `/proc` 专项测试仅检查测试进程自身；macOS 跳过并明确报告。生产启用仍需正式制品、bootstrap、服务组权限、可信 Git 对象和真实认证升级路径验收。
