# L4-01 进程级启动驱动

本目录补齐 `tests/final-acceptance/run.sh` 所需的 L4-01 外部输入。驱动使用隔离的 PostgreSQL 17、NATS JetStream、Redis 和 Linux runner；runner 内运行真实 Control、Agent Gateway、固定版本 OpenResty，并由既有 `TestL401GatewayProcessE2E` 启动 Agent。

当前状态是 **static-only**：脚本结构、资源所有权、生产鉴权/发布路径和禁止伪造状态的静态契约已落盘，但真实 PG/NATS/Docker/OpenResty/Agent 进程 E2E 尚未执行。运行态验收必须由总集成批次统一启动，不能把本轮静态通过表述为生产通过。

驱动约束：

- Control 先执行真实迁移，再通过 `bootstrap-user` 和 `/v1/auth/login` 获取平台会话。
- 两个发布都调用 `/v1/admin/site-publications`，命令只由 Control publication/outbox 产生；脚本不直接发布 NATS 命令，也不直接写 rollout、deployment、status 或最终状态。
- 在 Agent 启动前读取 Control outbox 和 JetStream，确认旧/新命令严格有序、均未被 Agent consumer 领取或确认。
- bearer token、Agent 配置、私钥和信任文件均位于 owner-only 目录并使用 `0600`。
- 所有任务创建的容器和网络使用唯一 `l401` owner label；退出路径只清理该 label 的资源并断言残留为零。预取 runner 镜像属于外部只读输入，不会被本驱动删除。
- 驱动不在验收运行期执行 `apt-get` 或构建 runner。`L401_RUNNER_IMAGE` 必须是仓库内 `runner-image/build.sh` 生成并预先载入本机 Docker 的 `sha256:<64 hex>` 内容地址，或等价的 `repository@sha256:<64 hex>` 引用；驱动在创建临时目录、网络或容器前检查它，并以 `--pull=never` 使用，因而验收波次不会访问 Debian 镜像源或隐式拉取 runner。

## Runner 预取契约

runner 由本仓库 [runner-image](runner-image/README.md) 中的权威制品流程提前生成。该流程可以联网获取固定 Debian snapshot 的包，但交给本驱动的结果必须是内容寻址的镜像，并包含完整运行依赖（Go、OpenResty、`psql`、`jq`、OpenSSL、curl 和基础 POSIX 工具）。镜像必须带以下标签；Go 值必须与 `run.sh` 内固定的基础镜像完全一致，OpenResty 镜像和版本取自节点运行时唯一真源 `edge/openresty/runtime.env`（`OPENRESTY_IMAGE`、`OPENRESTY_VERSION`）：

```text
io.cdnca.l401.runner.contract=v1
io.cdnca.l401.runner.go-image=docker.io/library/golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5
io.cdnca.l401.runner.openresty-image=<runtime.env OPENRESTY_IMAGE>
io.cdnca.l401.runner.openresty-version=<runtime.env OPENRESTY_VERSION>
```

制品构建完成后直接读取本地内容地址：

```bash
output_dir="$(mktemp -d /tmp/cdnca-l401-runner.XXXXXX)"
bash tests/l401-process-e2e/runner-image/build.sh "$output_dir"
source "$output_dir/runner.env"
```

构建和 `docker load` 属于验收前的制品预取，不是 `run.sh` 的一部分。流程输出 archive 校验和、固定输入 provenance 和实际 Debian 包清单，无需猜测 registry 或凭据。`runner.env` 同时携带镜像内容 ID 和 provenance 输入哈希；驱动只执行本地 `docker image inspect` 并将二者与镜像标签绑定校验。缺少输入、引用不是内容地址、镜像未预取或标签不匹配时，会在任何任务资源创建前明确失败。容器启动后还会从实际二进制核对 Go `1.27.3` 和 runtime.env 中的 OpenResty 版本，不会仅凭标签冒充运行证据。预取镜像不是本任务创建的资源，清理阶段不会删除它。

静态检查：

```bash
bash -n tests/l401-process-e2e/run.sh tests/l401-process-e2e/contract_test.sh \
  tests/l401-process-e2e/runner-image/build.sh \
  tests/l401-process-e2e/runner-image/contract_test.sh
shellcheck tests/l401-process-e2e/run.sh tests/l401-process-e2e/contract_test.sh \
  tests/l401-process-e2e/runner-image/build.sh \
  tests/l401-process-e2e/runner-image/contract_test.sh
bash tests/l401-process-e2e/contract_test.sh
bash tests/l401-process-e2e/runner-image/contract_test.sh
```

真实运行（仅在总集成批次获准后）：

```bash
source "$output_dir/runner.env"
bash tests/l401-process-e2e/run.sh
```
