# L4-01 runner 制品

本目录是 `L401_RUNNER_IMAGE` 的仓库内权威生成流程。`inputs.lock.json` 固定 `linux/amd64` 目标平台、Go 基础镜像 digest（OpenResty 镜像与版本由 `build.sh` 从 `edge/openresty/runtime.env` 读取，不在本文件另存）、Debian snapshot、构建时间和包集合；Dockerfile 只通过 snapshot.debian.org 的 HTTPS 固定快照获取 Debian 包，并继续使用 Debian archive keyring 验证 Release 和包索引，不使用 `trusted=yes` 或未认证安装。历史 snapshot 的 `check-valid-until=no` 只关闭已过期 Release 的时效窗口，签名、索引哈希和包哈希验证仍然启用，且 snapshot 时间进入 provenance 和镜像标签。

在允许联网、且已经提供真实 `linux/amd64` Buildx 节点的制品构建阶段执行一次：

```bash
output_dir="$(mktemp -d /tmp/cdnca-l401-runner.XXXXXX)"
export L401_BUILDX_BUILDER='l401-amd64-remote'
docker buildx inspect --bootstrap "$L401_BUILDX_BUILDER" | sed -n '/^Platforms:/p'
bash tests/l401-process-e2e/runner-image/build.sh "$output_dir"
source "$output_dir/runner.env"
```

构建脚本不需要 registry、登录或推送，但要求 `L401_BUILDX_BUILDER` 已明确指向一个能实际执行 `linux/amd64` 的 builder；它会在创建输出文件前执行 `docker buildx inspect --bootstrap` 并检查 `Platforms:`，缺失时 fail closed，不把本机的架构仿真或标签声明当成 amd64 运行证据。它生成时间戳归一化的 `runner-image.tar`、Buildx metadata、带各输入 SHA-256 和 builder 名称/平台摘要的 `provenance-inputs.json`、archive 校验和、实际 Debian 包清单，并把 archive 载入本地 Docker。`runner.env` 同时给出本地 `L401_RUNNER_IMAGE=sha256:...` 内容地址和 `L401_RUNNER_PROVENANCE_INPUT_SHA256`，可直接交给上层 `run.sh`；预取到另一主机时先校验 `runner-image.tar.sha256` 和 `provenance-inputs.json.sha256`，再执行 `docker load --input runner-image.tar` 并使用加载结果的内容 ID。

当前机器若只有 Docker Desktop 的声明性多架构能力而没有已验证的远程/原生 amd64 builder，构建结果应保持 `BLOCKED`，不要重试或提交伪造的 runner 镜像。

```bash
(cd "$output_dir" && sha256sum -c runner-image.tar.sha256 provenance-inputs.json.sha256)
```

静态契约：

```bash
bash -n tests/l401-process-e2e/runner-image/build.sh \
  tests/l401-process-e2e/runner-image/contract_test.sh
shellcheck tests/l401-process-e2e/runner-image/build.sh \
  tests/l401-process-e2e/runner-image/contract_test.sh
bash tests/l401-process-e2e/runner-image/contract_test.sh
```
