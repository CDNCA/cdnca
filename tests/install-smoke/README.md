# 社区版主控全新安装容器冒烟

在 linux/amd64 特权 systemd 容器里，只走 `scripts/install-control.sh` 社区免激活路径
（`install_community` / `control-api install-community`）。不连生产服务；签名用本次生成的一次性测试密钥。
**不**起授权端、**不**走激活码、**不**依赖已删除的授权安装脚本或授权服务。

```sh
# 1. 构建产物（heavy/docker，本轮可继续标 BLOCKED）
bash tests/install-smoke/build-artifacts.sh <输出目录>
# 2. 静态发布站 + 主控安装（debian12 / rocky9 / ubuntu2404 / ubuntu2204）
bash tests/install-smoke/run.sh <输出目录> debian12
```

前提：

- 当前提交已推送且是 `--remote-ref` 指向的远端分支头（打包脚本用 `git ls-remote` 核对）；
  默认 `refs/heads/<当前分支>`，可用 `CDNCA_REMOTE_REF` 覆盖。
- 本机 Docker 能跑 linux/amd64（Apple Silicon 走 Rosetta）。容器 mask systemd-binfmt，不改宿主 binfmt。
- `node_modules` 已装（`pnpm install --frozen-lockfile`），或 `CDNCA_NODE_MODULES_REPO=<同 lockfile 且已安装的工作区>`。
- 节点运行时相关输入（ModSecurity 扩展、`STD_DIR`、NATS/OpenResty 归档）仍按 `build-artifacts.sh` 检查。

拓扑：专用 docker 网络；`release.cdnca.smoke` 解析到静态发布站容器（挂载产物 `downloads/`）；
主控以 `--release-server https://release.cdnca.smoke` 安装，免激活。

网络慢时可设 `CDNCA_SMOKE_APT_MIRROR=http://mirrors.aliyun.com`；构建可设 `CDNCA_APK_MIRROR=https://mirrors.aliyun.com`。
复跑提速：`CDNCA_SMOKE_PKG_CACHE=~/.cache/cdnca-install-smoke/pkg`。

本轮验收先看脚本静态依赖清零（无授权安装脚本/授权服务路径）；完整 docker 冒烟属 heavy，可另标 BLOCKED。
