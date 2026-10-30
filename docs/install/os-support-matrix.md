# 主控与节点操作系统支持矩阵

更新：2026-10-17（r135-osmatrix）。分级在代码里只有一个真源：`scripts/lib/install-preflight.sh` 的 `preflight_os_tier`。主控 `install-control.sh` 和节点 `install-node.sh` 都逐字嵌入同一份检测，嵌入由 `node scripts/sync-install-preflight.mjs` 同步。改分级时，本文、该函数、节点包 `agents/edge-agent/packaging/scripts/lib.sh` 的 `validate_supported_host_facts`，以及四个签名辅助脚本的主机白名单都要一起改。`tests/install-preflight.test.mjs` 会校验这些地方保持一致。

## 1. 结论

- 正式支持：整机安装和升级都在实机上验收过。
- 兼容支持：依赖安装和服务启动都在 systemd 容器里（systemd 为 PID 1）实测过，整机安装还没在实机上验收。安装前检测对这类系统给出“警告”，需要用户确认，或加 `--yes` 跳过确认。
- 不支持：安装前检测直接判“不通过”，并说明原因。

| 系统 | 主控 | 节点 | 依赖来源 / 说明 |
| --- | --- | --- | --- |
| Ubuntu 24.04 | 正式 | 正式 | PGDG 17.11、发行版 ClamAV/Redis/nginx |
| Ubuntu 22.04 | 兼容 | 兼容 | 同上 |
| Ubuntu 20.04 | 兼容 | 兼容 | 可移植 PostgreSQL 17.11 与 ClamAV 1.4.6（见 4.3）；节点要求内核 5.4（GA 内核即可） |
| Debian 12 / 13 | 兼容 | 兼容 | PGDG 17.11、发行版 ClamAV |
| Debian 10 / 11 | 兼容 | 兼容（内核见右） | 可移植 PostgreSQL 与 ClamAV。软件源必须已经指向 archive.debian.org（安装器不改宿主的 apt 源）。节点：Debian 11 的 5.10 内核可直接用；Debian 10 的 4.19 内核没有 pidfd，需要 backports 内核 |
| Rocky / AlmaLinux / RHEL 8 | 兼容 | 兼容（内核见 2） | PGDG 17.11、EPEL8 ClamAV 1.4.6、AppStream 的 nginx:1.24、redis:6 模块流 |
| Rocky / AlmaLinux / RHEL 9 | 兼容 | 兼容 | PGDG、EPEL9、AppStream Redis |
| Rocky / AlmaLinux / RHEL 10 | 兼容 | 兼容 | PGDG、EPEL10、Valkey；CPU 需支持 x86-64-v3 |
| Ubuntu 18.04 | 不支持 | 兼容（内核见右） | 主控见第 5 节（ClamAV，glibc 2.27）。节点：安装器自动装 `setpriv` 包（18.04 上它不在 util-linux 里）；GA 内核 4.15 没有 pidfd，需要 HWE 内核（`linux-generic-hwe-18.04`，5.4） |
| Ubuntu 16.04 / Debian 9 | 不支持 | 不支持 | 见第 5 节：Python 3.5 |
| CentOS 7 | 不支持 | 不支持 | 见第 5 节：ClamAV（glibc 2.17）、内核 3.10 没有 pidfd、yum 分支 |

只提供 x86_64（amd64）。主控的 CPU 还需要支持 SSE4.2（ClickHouse 的要求）。

## 2. 决定下限的真实依赖（已按代码核实）

| 依赖 | 用在哪里 | 要求 | 现状 |
| --- | --- | --- | --- |
| Ed25519 签名与验签 | 激活证明、整包与节点包验签、节点回执 | 不依赖系统 openssl | 安装器自带静态 Go 工具 `tools/ed25519-tool`，随签名包下发，使用前比对写在安装器里的 sha256（`docs/install/ed25519-tool-security.md`） |
| X.509（自签 CA、回环证书） | `install-control.sh` `generate_ca`、`install-rustfs.py` `create_tls`、`configure-native-upgrade.py` | OpenSSL 1.0.2 及以上 | 统一用 CSR + `x509 -req -extfile` 或配置文件写扩展，verify 的隔离参数按版本添加。OpenSSL 1.0.2 不支持 IP 名称约束，在这个版本上 RustFS CA 只约束 DNS:localhost |
| systemd | 全部服务单元 | 219 及以上 | 低于发行版下限时，由 `scripts/lib/systemd-compat.sh` 生成兼容 drop-in（不改单元本体）。安装前检测提示“沙箱加固降级”，并列出被忽略的指令 |
| 内核 pidfd（只有节点需要） | Agent 只通过 `pidfd_open`/`pidfd_send_signal` 给 OpenResty 发信号，刻意没有 kill(2) 回退，避免 PID 复用 | 5.3 及以上，或带回移植的内核（用 perl syscall 434 实测） | 5.3–5.9 给警告；cgroup v1 给警告（Agent 能读两种层级） |
| Python | 主控签名辅助脚本、两个安装器里的内嵌脚本 | 3.6 及以上 | Python 3.6–3.13 在容器里跑过单测（见第 6 节）。3.5 没有 f-string，16.04 和 Debian 9 因此不支持 |
| PostgreSQL 17.11 | 主控本机数据库 | 有 PGDG 包就用包，否则用可移植构建 | `scripts/native-runtime/build-portable-postgresql.sh`：在 manylinux2014（glibc 2.17）里从源码构建，只依赖 glibc 和 zlib，可复现构建，sha256 `e58f3452…` |
| ClamAV 1.x | control-api 扫描错误页上传 | 1.0 及以上（病毒库 CDN 拒绝 0.103：实测 freshclam 报 "Blocked by CDN"，按 UA 实测 0.103.x 返回 403、1.0.9/1.4.6/1.5.4 返回 206） | 发行版自带的版本够用就用发行版的，否则用 `build-portable-clamav.sh`：把官方 1.4.6 LTS rpm 原样重新打包，可复现构建，sha256 `a1cecce7…`。官方构建需要 glibc 2.28 |
| Redis | 节点会话、在线租约（Lua 脚本里用 HSET 多字段、PEXPIREAT） | 4.0 及以上 | 20.04 是 5.0.7，Debian 10 是 5.0.14，Debian 11 是 6.0.16，EL8 是 6.2.24 |
| nginx | 管理端与升级 plan-source | 链接的 OpenSSL 要 1.1.1 及以上（TLS 1.3） | 20.04 是 1.18，Debian 10 是 1.14.2，Debian 11 是 1.18，EL8 是 1.24。四个版本都在容器里做过 `nginx -t` |
| RustFS 1.0.1 | 主控对象存储 | 无 | 官方 static-pie musl 构建，centos:7 到 debian:13 都能运行；旧的 gnu 回执仍然认 |
| ClickHouse 25.3.6.56 | 主控分析库 | 与发行版无关的 deb/rpm 源 | rpm 里的二进制在 centos:7 上能运行 |

以下组件不受发行版影响：节点的 OpenResty 运行时自带 musl 加载器；edge-agent、helper、control-api、Gateway、runner、NATS 都是 `CGO_ENABLED=0` 的静态二进制。

EL8 的 4.18 内核是否带 pidfd 回移植，以安装前检测的实测为准：容器里看到的是宿主内核，所以没有在 EL8 实机内核上验证过。

## 3. 安装前检测

两个安装器在提问、下载、修改任何东西之前先做检测。每一项输出“通过”“警告”或“不通过”。有“不通过”时只打印修复建议，然后退出，不改动本机。只有“警告”时，交互终端会询问是否继续；加 `-y/--yes` 直接继续；没有 TTY 时打印提示后继续。

| 检查项 | 主控 | 节点 | 阈值与依据 |
| --- | --- | --- | --- |
| root、x86_64 | 必须 | 必须 | 安装包只有 amd64；主控还要求 SSE4.2 |
| 操作系统 | 第 1 节 | 第 1 节 | `preflight_os_tier` |
| 内核 | 低于 4.18 警告 | 低于 5.3 时实测 pidfd：支持则警告，不支持则不通过；5.3–5.9 警告；cgroup v1 警告 | 第 2 节 |
| systemd | 必须是 PID 1；低于 219 不通过；低于该发行版的下限警告“沙箱加固降级”并列出缺少的指令 | 同左 | 下限：24.04 为 255，22.04 为 249，20.04 为 245，18.04 为 237，Debian 10/11/12/13 为 241/247/252/257，EL8/9/10 为 239/252/257 |
| CPU 核数 | 少于 4 核警告 | 少于 4 核警告 | 推荐配置：主控至少 4 核 16G、规模大 8 核 32G；节点 4 核 8G 起、大缓存或高并发 4 核 16G |
| 内存 | 低于 3.5G 不通过，低于 14.7G（推荐 16G）警告 | 低于 0.9G 不通过（内存加 Swap 达到 2.8G 时改为警告），低于 7.3G（推荐 8G）警告 | 最低值不变，只上调推荐提示。按标称值的约 90% 判断（内核会保留一部分） |
| 磁盘 | 低于 10G 不通过，低于 40G 警告 | 低于 2G 不通过，低于 10G 警告 | PG+ClickHouse+病毒库；节点按 5 个版本 × 272 MiB + 512 MiB 计算 |
| 端口 | 管理端端口和依赖端口 | 80、443、18080、18443 | 从 `/proc/net/tcp{,6}` 读取 |
| 必需命令 | bash、awk、sed、grep、df、uname、id、apt-get 或 dnf | 同左 | 其余命令自动安装 |
| 连通性、时间偏差 | 授权端可连接；时间偏差超过 300 秒不通过，超过 60 秒警告 | 主控可连接；Gateway 端口不通只警告 | 授权端证明的时间窗是 ±5 分钟 |
| SELinux、防火墙 | Enforcing 或防火墙启用时警告，并给出放行命令 | 同左 | 安装器不修改防火墙 |
| 主控与节点共存 | 不通过 | 不通过 | 两者都要用 80/443 |

## 4. 各系统的实现

### 4.1 Debian/Ubuntu（apt）

`scripts/native-runtime/install-ubuntu-dependencies.sh` 按 `/etc/os-release` 的 ID、VERSION_ID、VERSION_CODENAME 三元组精确匹配 profile。noble、jammy、bookworm、trixie 用 PGDG 套件，并固定到 17.11。ClickHouse 用与发行版无关的 deb 源。所有仓库密钥都按主指纹固定；GnuPG 低于 2.2.8 时导入到临时 keyring 再比对指纹。

### 4.2 RHEL 系（dnf）

EL8/9/10 共用一套 dnf 流程，安装 PGDG `postgresql17-server`、ClickHouse rpm、EPEL `clamd@scan`（socket 是 `/run/clamd.scan/clamd.sock`，组为 virusgroup），EL8/9 用 Redis，EL10 用 Valkey。EL8 会先关闭 AppStream 的 postgresql 模块（否则 PGDG 包会被屏蔽），再启用 nginx:1.24 和 redis:6。SELinux 启用时，安装器为非标准端口打 `http_port_t` 标签，并设置文件上下文。EPEL 密钥按主指纹固定（EL8 `94E279EB…D6A1`、EL9 `FF8AD134…467C`、EL10 `7D8D15CB…D158`），与 fedoraproject.org/security 核对过。

### 4.3 可移植运行时（Ubuntu 20.04、Debian 10/11）

- `install-ubuntu-dependencies.sh requirements` 列出主机需要的归档名和固定 sha256。install-control 从 `${LICENSING_SERVER}/downloads/control-native/runtime/` 下载（可用 `RUNTIME_ARCHIVE_URL` 覆盖，下载失败时试备用地址），再以 `--postgresql-archive`、`--clamav-archive` 传给依赖脚本。依赖脚本在解压前先比对 sha256。
- PostgreSQL 解压到 `/opt/cdnca-postgresql-17`，数据目录 `/var/lib/pgsql/17/data`（initdb 参数：本机 peer、回环 scram-sha-256、只监听 127.0.0.1），systemd 单元为 `postgresql-17.service`，工具链接放在 `/usr/bin`（升级 runner 从 `/usr/bin` 找 pg_dump/pg_restore/psql）。编译期的 socket 目录改为 `/run/postgresql`，因为默认的 `/tmp` 可以被本机任意用户抢占。
- ClamAV 解压到 `/opt/cdnca-clamav-1.4`，沿用 Debian 包的布局：clamav 账户、`/etc/clamav`、`/var/run/clamav/clamd.ctl`（660，属主 clamav:clamav）、`clamav-daemon` 和 `clamav-freshclam` 单元。所以 install-control 和 control-api 不用区分主机。官方构建内置的 libcurl 找的是 EL 的 CA 路径，freshclam 通过 `CURL_CA_BUNDLE` 改用 Debian 的 bundle。
- 安装器有一个版本、两个归档，都要在发布时放到授权端的 `/downloads/control-native/runtime/`：
  - `postgresql-17.11-portable-linux-amd64.tar.gz`（`e58f34528c56ff3557ecaa6164ab45ebc7dcce26f23cf92d596183cd8b816cb0`）
  - `clamav-1.4.6-portable-linux-amd64.tar.gz`（`a1cecce72db46a424393046ee351f2d23bc7e249a810fbdbe7e246c9752e35e8`）

  在任意 Docker 主机上运行 `scripts/native-runtime/build-portable-{postgresql,clamav}.sh OUT` 就能得到相同的字节。这一步完成之前，这三个系统的主控安装会在下载归档时失败，并给出清楚的报错。

## 5. 仍不支持的系统：原因与代价

| 系统 | 卡在哪里（已实测） | 怎样才能支持，代价是什么 |
| --- | --- | --- |
| Ubuntu 18.04 主控 | 官方 ClamAV 1.x 构建需要 glibc 2.28，18.04 只有 2.27，而发行版自带的 0.103 被 CDN 拒绝。主控其余依赖已在 systemd 237 容器里实测：控制端工具引导、nginx 1.14.0 `nginx -t`、Python 3.6.9 + OpenSSL 1.1.1 | 已写 `scripts/native-runtime/build-portable-clamav-musl.sh`：在固定 digest 的 alpine:3.22 里从官方 1.4.6 源码（sha256 `06dbc7ad…`）构建，自带 ld-musl 和全部依赖库，不加载宿主库。构建尚未跑完（Docker Desktop 中途重启），归档还没有固定 sha256，因此 18.04 主控仍判不通过。跑完后：固定 sha256、在依赖脚本加 bionic profile、放开分级与四个辅助脚本白名单、容器实测 EICAR。代价：要跟进 Alpine 里 OpenSSL、curl、libxml2 等库的安全更新。另：同一容器里 RustFS install 在模拟环境下三次失败（前两次是首次翻译 100MB 二进制和 update-ca-certificates 超时），第三次的原因还没查清 |
| Ubuntu 16.04、Debian 9 | Python 3.5：签名辅助脚本里大约 60 处 f-string（3.6 语法），还用了 3.6 的 `secrets` 模块 | 要么改写全部辅助脚本并在 3.5 上回归，要么随包附带一个固定 sha256 的可移植 CPython。另外 ClamAV 的问题同 18.04；Debian 9 的内核 4.9 也没有 pidfd |
| CentOS 7 | 主控：ClamAV 的问题同 18.04（glibc 2.17）；依赖脚本没有 yum 分支；官方源已经下线，vault.centos.org 返回 403（mirrors.aliyun.com/centos-vault 可用，构建镜像里已经在用，可通过 `CENTOS_VAULT_MIRROR` 配置）。节点：内核 3.10 没有 pidfd；nobody 的 UID 是 99 | 主控的代价同 18.04 的 ClamAV，再加 yum 分支和 vault/EPEL7 archive 源的接入。节点要么要求 ELRepo 新内核，要么给 Agent 加 kill(2) 回退，后者需要先做安全评审（有 PID 复用风险） |

已经核实可用的部分：可移植 PostgreSQL 17.11 在 centos:7、ubuntu:16.04、debian:9 上通过了 initdb、启动、170011、gen_random_uuid 和回环 scram 登录；centos:7 上的 OpenSSL 1.0.2k + Python 3.6.8 通过了 configure-native-upgrade 的全部单测，create_tls 生成的证书也能被 Python ssl 校验通过；RustFS musl 和 ClickHouse rpm 二进制都能在 centos:7 上运行。

## 6. 容器实测记录

环境：macOS arm64 宿主，Docker Desktop，镜像都加 `--platform linux/amd64`（Rosetta 模拟）。systemd 容器用 `--privileged --cgroupns=host`、挂载 `/sys/fs/cgroup`，以 `/sbin/init` 作为 PID 1。容器里 `LoadCredential` 不可用（Docker Desktop 的 tmpfs 不支持 POSIX ACL），所以 RustFS 走兼容凭据路径；真实 EL9 主机上的 LoadCredential 路径还没有验证。

| 系统（systemd） | 依赖脚本 install / check | 其他 |
| --- | --- | --- |
| rockylinux:9（252） | ready rocky=9：PGDG 17.11、ClickHouse、EPEL clamd，EICAR 能检出 | RustFS install/preflight 通过，update-ca-trust 锚点生效 |
| rockylinux:8（239） | ready rocky=8：PGDG 17.11、clamd 1.4.6（socket 660，clamscan:virusgroup）、redis 6.2.24、nginx 1.24 | RustFS 通过；7 组辅助脚本单测在 Python 3.6.8 + OpenSSL 1.1.1k 上全过 |
| ubuntu:18.04（237） | 主控依赖未测（ClamAV 未就绪） | 安装前检测：主控 OS 不通过、节点 OS 警告、systemd 237 通过；控制端工具引导通过；节点依赖安装（含 setpriv 2.31.1）和 require_commands 通过；nginx 1.14.0 对真实管理端配置 `nginx -t` 通过 |
| ubuntu:20.04（245） | ready ubuntu=20.04（可移植 PG 与 ClamAV），重复 install 幂等，EICAR 能检出 | prepare_database、RustFS 通过；7 组单测在 Python 3.8.10 + OpenSSL 1.1.1f 上全过；节点依赖、Ed25519 和节点包准入都通过 |
| debian:10（241） | ready debian=10（可移植 PG 与 ClamAV），重复 install 幂等，五个服务 active，clamd.ctl 660 clamav:clamav | prepare_database、RustFS install/preflight 通过（兼容凭据路径）；nginx 1.14.2 对真实管理端配置 `nginx -t` 通过 |
| debian:11（247） | ready debian=11，同上 | prepare_database 通过；RustFS 在修复 `%d`（systemd 248 起才有）后通过；nginx 1.18.0 `nginx -t` 通过 |

systemd 247 认得 `LoadCredential=` 但不认 `%d`，所以 RustFS 的“能否用 LoadCredential”按“认得该指令且版本 ≥ 248”判断（`install-rustfs.py` `systemd_credentials_usable`）。
