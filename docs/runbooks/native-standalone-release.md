# 单主控原生完整版本发布

本流程仅适用于 Linux 单主控的管理面完整版本。它会造成短时管理维护，不提供 HA 零停机承诺，不重启边缘节点，也不让边缘请求依赖授权中心在线。

## 首次安装、迁移和升级不能混用

- 空白机首次安装：仅支持固定 Ubuntu 24.04 amd64 单主控 profile；使用已推送精确提交构建的完整 native baseline、独立 runner 和同提交节点包。主安装器在激活前验证全部签名、版本、源码、依赖和空数据库，不覆盖已有安装、保留角色或业务库。部分失败须保留现场，不能删除状态后盲目重跑。
- 首次迁移：已有 `current` 只有 Web、后端仍位于固定安装路径时，必须先由单一发布负责人执行完整联版迁移，保存实际二进制、Web、迁移账本、环境及 systemd 回滚证据。不能重跑安装器，不能将旧 Web 包当作完整原生版本。
- 后续升级：从已验收的完整原生版本构建新包，由授权运营端签发计划，管理员确认短时维护后上传签名 JSON，由独立 `native-standalone` 执行器验签、预检、切换、健康确认或回滚。

Kubernetes/systemd HA 执行器原有的副本和 quorum 要求保持不变；禁止把副本数改为 1 来冒充单机支持。新 native 模式与旧 HA writer 互斥。

### 单一身份与版本链（1.0.33 起）

每个主控版本只有一个内包身份：外层首装包嵌入的 `native-management.tar`，就是授权端注册表登记、runner 升级下载的同一个已签名内包（`downloads/control-api/<版本>/native-management.tar`），不再另出首装血缘的内包。授权端按（组件, 当前版本）选回滚制品，runner 要求 current 摘要等于回滚摘要，同版本两种摘要会让首装主机无法再经控制台升级。

- 版本链起点为 1.0.29（commit `f074efdff8c32d8d6f77095e9e9e5ea7af960089`，内包 `c986cc87…`）。1.0.33 由 `native-release-package.mjs --previous-release <1.0.29 已签目录>` 构建，`previous_commit=f074efdf`；1.0.34 的 previous 为 1.0.33 的 commit，依此类推，每版只以上一版已验收的已签目录为基线。
- 外层 `prepare` 接受两种内包：`first-native-baseline` 初版（自带 runner），或不带首装标记、不带 runner 的已签 v2 版本链内包；后者的 runner 由 prepare 从已验证的源码 bundle 以 `GOWORK=off`、`-mod=readonly`、`-ldflags=-s -w` 编译，并照常二次复现比对。签名、来源 tree、祖先、迁移集合、Go 归档校验均不变；半带标记、自报 runner、未签名的版本链内包一律拒绝。
- 版本链构建器同首装构建器一样设置 `VITE_RELEASE=<commit>`、`VITE_API_BASE_URL=''`，并用本次源码刷新 `static/web/downloads/install-node.sh`（runner owned content）。`runtime-config.js` 和旧 hashed 资源仍按上文保留上一版。
- 限制：装着 1.0.31/1.0.32 等初版（`previous_commit=8b26d834`）内包的主机不在版本链上，不能经控制台升级到链上版本；目前没有这类主机，不为它们出升级包。注册表中 1.0.29–1.0.32 的 control-api 制品保持原样。
- `scripts/native-initial-release-package.mjs` 仅保留给历史/测试用途，正式发布不再使用。

首次包原先使用 `scripts/native-initial-release-package.mjs`；固定前驱 `8b26d83421351b96a715fefa1d7f4fcdbb94ed1a` 仅表示已发布源码血缘，不表示空白机曾运行该版本。按照 [ADR 0005](../adr/0005-native-sourcefree-artifacts.md)，公开客户包使用 v2：`--key-id` 生成待签名内包，`scripts/native-release-signature.mjs` 验证外部签名后生成最终 tar，再由 `scripts/native-control-install-package.mjs` prepare/finalize 将同提交依赖工具、完整内包和 runner 打入域分离签名外包。私钥不进入构建器或浏览器，私有 Git 只在发布端校验。

NATS 服务端必须随该签名外包交付，不能再由安装器下载旧官方版本。先从精确已推送源码归档中的 `build-nats-backport.sh` 构建，再给 `prepare` 提供 `--nats-build-dir /绝对路径/该构建输出`；目录须包含 `nats-server-2.12.15-cdnca.1` 与 `NATS-LICENSE`。prepare/finalize 独立核对归档源码 profile 内的固定字节数和 SHA-256，并将二者列入签名库存；正式安装器先验整包签名、ELF 平台和全部库存，随后再次校验 NATS hash、版本及文件属性。固定载荷由32增为34，旧支持包不能搭配新安装器。已有不同 NATS 二进制会被拒绝，不能借首次安装器覆盖现有依赖。

**历史 v1 支持包仍仅允许私下 SSH 测试交付。** `source.bundle` 包含可达私有源码历史，输出标记 `private-ssh-test-only`，禁止匿名公开。v2 固定 34 文件库存以 `release.manifest.sig` 替换 `source.bundle`，标记 `public-signed-no-source`，发布端仍使用私有完整 Git 对象校验，不向客户交付它。主安装器的配对 `--native-package-file` / `--native-trust-file` 用于已授权测试机，独立 trust 文件必须为 root 私有文件。格式实现不等于公开下载已更新；公开入口、首次安装和浏览器证据以对应发布记录为准。

首次环境包括 PG、Redis、固定 NATS 17 个 stream / 7 个 durable、CH 16 个迁移和最小角色、ClamAV 实际扫描、RustFS 本机 TLS/版本化对象、68 项运行配置，以及独立 mTLS 计划源。公网 `/v1/internal` 必须拒绝。必须使用系统信任的公网 Web 证书；局部 `curl --cacert` 成功不代替 runner 的系统 CA 检查。

## 完整制品

普通 tar，根文件 `release.manifest.json`。旧 schema 为 `cdnca.native-management.release/v1`；公开无源码包使用 v2 并增加 `key_id`。清单记录规范版本、UTC 构建时间、完整 source commit/tree/previous_commit、Linux 架构及所有文件的路径、SHA-256、字节数和模式。清单不列自身，也不列 v2 的独立 `release.manifest.sig`；必需内容文件为：

```text
bin/control-api
bin/agent-gateway
static/web/index.html
migrations/*.sql
```

拒绝软/硬链接、路径逃逸、重复成员、额外成员、清单/hash/大小不一致及非 0644/0755 模式。包 SHA 与 Control 二进制 SHA 是不同身份，不得互换。

### 数据库迁移（只允许追加）

候选迁移集合必须是当前集合的严格超集：已有 `migrations/*.sql` 的内容、大小和模式完全不变；新增文件编号紧接当前最高版本连续递增，每个版本都有同名 `up` 与 `down`，模式 0644、非空。删除、修改、跳号、插入到旧版本之下、缺 `down` 或命名不配对，构建器（`assertAppendOnlyMigrations`）和 runner 都按血缘拒绝，计划终态失败（`expand_failed`），不触碰现网。

迁移只在 Drain 之后、Activate 之前执行，每一步都有持久检查点，runner 崩溃重启后从检查点续跑：

1. Preflight（Drain 前）：从 `systemctl show <control unit>` 的 `EnvironmentFiles` 读取 control-api 自己的 `DATABASE_URL`（不另存第二份凭据）；`pg_dump/pg_restore/psql` 主版本不低于服务器；账本 `schema_migrations` 恰好等于当前包的迁移头；库内 schema/表/函数/类型全部归连接角色所有且无扩展（否则无法完整还原）；备份目录剩余空间 ≥ 库大小 + 256MiB。空间不足记 `database_backup_space_insufficient`，其他记 `database_preflight_failed`，均为 Drain 前可重试失败，释放空间后同一计划会自动重试。
2. `control_stopped`：只停 control-api（唯一数据库客户端），确认 `ActiveState=inactive|failed` 且 `MainPID=0`；gateway 不连库，保持边缘会话。
3. `database_backed_up`：`pg_dump -Fc` 写入 runner 状态目录 `<STATE_DIR>/database-backups/<计划ID>.dump`（目录 0700、文件 0600），fsync 后用 `pg_restore --file=/dev/null` 读完整个归档校验，再原子改名并记录路径、字节数、SHA-256、耗时。只保留最近 3 份已完成备份。
4. `database_migrated`：用候选包的 `bin/control-api migrate up`（同一 `DATABASE_URL`）执行，再核对账本到达候选迁移头。
5. 之后照常 Activate、健康检查、恢复 active。

失败回滚选择「从本次备份还原」而不是逐个执行 `down`：`down` 很少被生产验证、可能有损，也无法撤销部分执行的迁移和候选在健康失败前写入的数据；还原则精确回到备份时刻。只要检查点里已有备份，迁移失败、激活失败、健康失败、resume 失败以及崩溃后续跑的回滚都会先停 control-api、核对备份 SHA-256 与大小、按批删除连接角色名下全部对象并重建 `public`，再 `pg_restore --exit-on-error`，核对账本回到迁移前，持久记 `restored` 后才切回旧 release 并做健康检查；已记 `restored` 的计划重启后不会再次还原，避免覆盖旧版本已写入的数据。备份失败（数据库未动）只切回旧包。代价：从备份时刻到回滚之间对数据库的写入会丢失（维护闸门期间只有候选启动和健康检查窗口）。

还原失败记 `database_restore_failed` 终态，维护保持 draining、不切 release。人工恢复：停 control-api，以 control 角色执行同一清空脚本后 `pg_restore --exit-on-error --dbname=<库> <回执 migration.backup_path>`，核对 `schema_migrations` 头，再切回 previous 并启动。

回执、`state.json` 与 history 中的 `migration` 字段记录本次执行的迁移、备份路径/字节数/SHA-256 及备份、迁移、还原耗时；控制台升级日志据此显示。可选环境：`CDNCA_NATIVE_UPGRADE_DATABASE_TOOLS_DIR`（默认 `/usr/bin`）、`CDNCA_NATIVE_UPGRADE_DATABASE_TIMEOUT`（单次备份/迁移/还原上限，默认 30m，最大 1h）。注意 `control-api migrate` 自身有 2 分钟超时，单条迁移不得超过它。

发布顺序：控制台读取 state/history/回执是严格解码，带迁移字段的结果只能被本版本及之后的 control-api/Web 读出。因此本 runner 与读取端须先随一个「迁移集合不变」的版本（1.0.33）上线，下一版（1.0.34）才可追加迁移；否则 1.0.34 回滚到旧版后控制台会把回滚结果显示为未确认。

构建工具只使用已推送且等于远端分支 tip 的精确 commit，前后两次核对远端。它从 `git archive` 构建，不使用共享工作区的源码或遗留 dist。上一完整版本先验证清单，再复制为临时构建基线；只替换本次管理组件，保留未归属文件、旧 hashed Web 资源及新构建未包含的运行配置等公共路径。旧入口已引用 `runtime-config.js` 而新入口未集成时拒绝打包，不能默默断开现有配置。

```sh
node scripts/native-release-package.mjs \
  --source-commit <完整40位远端提交> \
  --remote-ref refs/heads/<已核实的发布分支> \
  --previous-release /绝对路径/已验证的原生完整版本 \
  --output-dir /绝对路径/尚不存在的制品目录 \
  --version 2026.10.8 --arch amd64 \
  --turnstile-site-key <公开站点标识>
```

未配置 Turnstile 的部署必须显式使用 `--allow-empty-turnstile-site-key`，不能不知情地丢失既有配置。旧版本参数必须是规范真实目录，不接受 `current`、`previous` 或任一父目录的软链接别名。输出父目录必须已存在；构建器解析其真实路径，拒绝直接或通过别名写入旧版本内部，并在任何替换前重新验证复制目录的完整清单及无链接属性。输出包括 `native-management.tar`、`release.manifest.json`、`build.json`；`signing_required=true` 明确表示它们尚不是已授权升级计划。构建器不签名、不部署、不更新独立 runner 自身；已装主控的 runner 需单独受控更新（以签名外层包清单中的 `control-upgrade-runner` SHA 为准，替换后核对 `/proc/<pid>/exe` 与 `verify-native-upgrade`）。

### v2 两层签名顺序

1. 首次或升级构建增加 `--key-id <制品key-id>`。输出为 `native-management.unsigned.tar`、manifest、`release.signing-data` 和私有中间 `payload`，不是可安装包。从 v2 current 构建还必须传入 `--previous-artifact-public-key <独立可信PEM>`，禁止降回 v1。
2. 在受控签名端对 `release.signing-data` 执行 Ed25519 原始签名，将标准 Base64 签名带回；私钥不离开签名端。运行 `node scripts/native-release-signature.mjs --build-dir <待签目录> --remote-ref <精确远端分支> --signature <签名文件> --public-key <独立可信PEM> --output-dir <新目录>`。
3. finalizer 重验精确远端提交、私有 Git 完整性/祖先、SQL 集合和字节、全部 payload、独立签名及真实 Go archive 校验。只有内层 tar 已包含签名后才输出 `signed-build/v2` 和最终 SHA-256。执行计划只能绑定这个最终摘要。
4. 首装再将该目录（版本链内包的已签目录）作为外层 prepare 的 `--initial-build-dir`，并传入 `--artifact-public-key`。外层签名后 finalize 同样需要 `--artifact-public-key` 与自己的 `--public-key`。两者可受同一受控密钥签署，但签名域不能互换。禁止公开中间构建目录或 v1 外包。
5. 客户在任何激活、执行与安装写入前校验外层、内层和全部库存。独立信任文件持久保存在 `/var/lib/cdnca-upgrade/artifact-trust.json`，runner 通过 `CDNCA_NATIVE_UPGRADE_ARTIFACT_TRUST_FILE` 加载。v2 首装不建立 `source.git`。

### 降级门禁事实（1.0.35 起）

升级构建的 `build.json` 带 `schema_gate`：`control_schema_head` 取包内 `migrations/` 的最高编号；只有发布者确认本版本相对某个旧版本的迁移全部向后兼容时，才用 `--rollback-min-version <旧版本>` 写入 `rollback_min_version`（必须低于本版本）。登记 control-api 制品时把这两个字段原样带给授权端 `POST /operator/v1/release-artifacts`（或 upload/import 的 metadata）；登记后不可修改。缺 `control_schema_head` 的版本一律视为不可回退：授权端不会签出跨 schema 的降级授权，运营也不能把主控 pin 到比其上报版本 schema 更旧的版本。

发布端 Git 操作禁用 replacement；归档后逐文件比对真实 tree blob 和 mode，拒绝 `export-ignore/subst` 改写。独立 runner 使用模块目录、`GOWORK=off`、固定 Go 环境与 flags 重编译，不能只接受 `build.json` 的自报摘要。finalize 在最终输出复制后再次核对 tar 摘要，成功记录最后写入；保留的部分失败输出不是可发布制品。

## 运行与授权边界

1. runner 使用独立受保护状态目录、进程锁及 `/run/lock/cdnca-management-release.lock`。正式发布、回滚和其他管理部署共用后者；锁不可用立即停止。
2. 有效 Control/Gateway `ExecStart` 必须跟随同一 `current/bin`；混合固定路径或无法确认的布局拒绝升级。`current`、`previous` 和 `releases/<包SHA>` 均在同一受保护 release root 下。
3. v1 仍要求 root-owned 本地 Git 对象库证明候选 commit 是当前 commit 后代，并核对 tree；没有对象证明不能跳过 v1 门禁。v2 由发布端完成此验证并签署来源，客户用独立制品公钥验签；两种格式都要求 `source.previous_commit` 精确匹配 current，并保留严格递增版本、迁移只追加和文件兼容校验。
4. 授权端通过现有签名计划流程提供 forward/rollback bundle；安装 ID、协议、当前/目标版本、渠道修订、序列、有效期及包 digest 均由服务端验证。浏览器不持有签名私钥，不填写 root 密码，不修改上传的原始签名 JSON。
5. 管理写入冻结由持久维护状态控制；缺失、损坏或不匹配时拒绝写入，不能在重启时自动解除未完成的维护。健康读取及明确允许的只读入口不进入边缘流量路径。
6. 独立 goroutine 更新可信活性，核对 root ownership、权限、30 秒新鲜度、PID 启动标识及 `/proc` 中真实可执行文件 SHA。文件存在不等于 runner 就绪；busy/draining 不接受新计划。
7. 管理端只读查询真实发布修订、发布回执和执行结果。发布成功与执行成功分开；回执不确定时只允许原 body/revision/幂等键重试，禁止自动生成新请求。

runner 安装器创建 boot-only、create-only tmpfiles 规则恢复 `/run` 状态目录和同 inode 发布锁；不会覆盖既有内容或修正不安全权限。只读 `ExecStartPre` 拒绝不安全路径。Control/Gateway 清空 capabilities；Control 显式加入 `clamav` 补充组。安装后必须通过真实 mTLS 正反例，再启用 runner，并使用 `control-api verify-native-upgrade` 核对安装 ID、版本、source commit/tree、包 SHA 和 runner SHA，以及安全进程状态；轮询和单次调用均有时限。

旧 v1 首次导入的 Git 对象不含未来提交，不能让 runner 联网 fetch 或静默跳过祖先门禁。迁往 v2 必须先受控更新独立 runner、可信配置并保留 v1 previous 需要的 Git；只更新 Web 或签名包不能替代这一迁移。v2 签名证明来源，不单独证明全局最新；浏览器升级仍需真实计划、回执和失败回滚验收。

状态投影不代替 runner 的 durable state。API 不得通过打开 FileStore 去创建目录或 chmod；只读投影必须与当前 publication 的 plan、bundle 和 sequence 匹配，否则显示未确认。

## 发布与恢复核验

切换前完整核对文件、ELF 平台、迁移集合（只追加）、Git 祖先、有效服务和回滚包；有追加迁移时先停 control-api、备份并迁移数据库，再原子保存旧 `current` 为 `previous` 并切换。启动等待有上限；逐个核对实际 `/proc/<pid>/exe`、二进制 hash、Control/Gateway readiness、Web index 和静态资源。目标失败时（有备份则先还原数据库）恢复整包并验证旧服务健康；保留失败制品、状态和回执供审计。

发布负责人必须分别记录：远端 SHA、source tree、包和组件 SHA、current/previous、有效 ExecStart、PID、NRestarts、内外入口、近期错误及浏览器证据。授权运营端的静态变更属于另一信任域，必须在同一联版批次单独构建与验收，不能塞入客户主控包。

自动化测试中的临时 Git、签名样例、假 systemctl、localhost HTTP 和临时链接只证明对应代码路径；不能将它们写成生产升级、真实服务回滚或验收通过。没有生产签名计划及真实执行回执时，执行证明仍为 `UNKNOWN`。

只在最新版完整验收后，精确列出无 current/previous/进程/下载引用的旧目录并可恢复归档。不得删除唯一回滚点、数据库备份、源码历史或其他任务资源。

## 空统计代际的受控恢复

`cmd/analytics-empty-generation-recover` 是操作员一次性工具，不接入主控正常启动或首次安装。仅支持固定单机 profile、268 迁移头、指定安装及旧代际、真实 broker 新创建时间严格大于旧值、零消息/投递/ACK/删除历史及六类零事实。禁止放宽主控 epoch 比较、重建消费者、删除 KV、改写旧不可变身份或虚构历史恢复标记。其他情形停止并保留现场。

恢复前停止 Control、Gateway、native runner，确认无计划和其他 NATS 客户端，在发布/持久维护同 inode 锁内完成 PostgreSQL dump、停止 NATS 后的完整 store 备份及配置/unit 备份。私有 plan 绑定 current/source/version/env SHA、stream/consumer 精确创建时间与原配置 SHA、KV 原 revision1/2；`check` 不写日志或数据。`apply` 先独占创建并 fsync 私有 prepared 日志及目录，在 READ COMMITTED 事务内锁定六类事实表和代际表，重新检查后只退休原记录并新增真实代际。PG 提交后重新锁表检查，再将唯一 consumer_created 键以原 revision CAS 更新；不改其他键或 broker 配置。

PG 与 KV 不能原子提交。任何失败都保持服务停止，仅允许同一 plan 和 prepared 日志 `resume` 向前完成；不反向删除新代际、不取消旧代际退休。恢复成功回执落盘后仍须独立核对数据库、KV、队列身份和依赖版本，再启动、重启及浏览器验收。plan、journal 及备份不得进入公开制品。

NATS 2.11.4 的首次 API/磁盘创建时间不同，2.12.15 仍有恢复后更新配置时的身份持久化问题。`2.12.15-cdnca.1` 是明确标记的自建回移版本，基于官方源码 commit `8460a428cf3b27c8627595d630f1ccad55786d13`，只回移上游 [stream 修复](https://github.com/nats-io/nats-server/pull/8471) 与 [consumer 修复](https://github.com/nats-io/nats-server/pull/8621)，不冒充官方二进制。`build-nats-backport.sh` 拒绝非固定 SHA 源码压缩包，固定 Go1.27.3（与 go.work 的 toolchain 一致）、静态 Linux/amd64、模块校验和版本后缀；正式使用须从已推送提交重建并验证。管理测试机依赖恢复、安装器源码接线与完整新包发布是三个独立证据，不能互相代替；容器/HA profile 不在本次 native 依赖改动范围内。
