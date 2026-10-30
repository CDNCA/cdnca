# Edge Agent 原生 APT 发布与安装

本目录定义 Debian 12 和 Ubuntu 24.04 的 Edge Agent 原生 `.deb`/APT 生产路径，
同时支持 `amd64` 与 `arm64`。节点只通过 APT 获取已签名包；不允许远程脚本管道、
默认凭据、关闭防火墙或直接覆盖当前 release。

## 发布门禁

1. 分别用 `scripts/edge-agent-release-build.sh` 生成两个架构的 ELF、SPDX 2.3
   SBOM 和 provenance。构建器镜像必须由 digest 固定。
2. 在隔离扫描任务中生成 `edge-agent.security.json`，使用独立 Ed25519 安全扫描
   密钥对原始 JSON 字节签名为 `edge-agent.security.sig`。报告必须绑定 artifact、
   SBOM、provenance、版本、架构和源码提交；扫描器镜像与漏洞库快照必须固定。
3. 报告中的上游公告只能是 `patched` 或 `not_affected`，并且必须带上游 HTTPS
   公告、修复版本、上游补丁 commit/HTTPS 引用、回归测试名和证据摘要。`http1`、`http2`、`http3`、
   `websocket`、`range206`、`rewrite` 与 `cache-refresh` 回归必须全部通过。
4. 使用经过评审的策略副本替换
   `security-policy.example.json` 中的示例扫描器地址，并从受信任变更记录取得策略
   SHA-256 和安全扫描公钥 SHA-256。摘要不能由同一未信任输入临时推导。
5. `scripts/edge-agent-deb-publish.sh` 先把所有输入复制到同文件系统私有暂存，逐个
   验签和准入，再调用冻结的 APT 构建器。任一输入失败时输出目录保持不存在；成功
   后仓库一次原子发布，并包含由 release key 签名的安全门禁 provenance。

安全报告的顶层 schema 为 `cdnca.edge.security-report/v1`。可用
`scripts/edge-agent-deb-contract-test.sh` 查看最小完整示例。私钥必须来自 CI secret
manager 或 KMS 临时挂载，不能写入仓库、构建日志或命令回显。

发布命令的生产形态如下；路径和摘要由发布系统注入：

```sh
scripts/edge-agent-deb-publish.sh \
  --config /release/repository.json \
  --output-dir /srv/cdnca-apt.next \
  --release-private-key /run/secrets/edge-release-private.pem \
  --release-public-key /etc/cdnca-release/edge-release-public.pem \
  --apt-homedir /run/secrets/apt-gnupg \
  --apt-key-id FULL_40_HEX_FINGERPRINT \
  --security-policy /etc/cdnca-release/edge-security-policy.json \
  --security-policy-sha256 PINNED_POLICY_SHA256 \
  --security-public-key /etc/cdnca-release/security-scanner.pem \
  --security-public-key-sha256 PINNED_SECURITY_KEY_SHA256
```

`repository.json` 使用冻结构建器的 `cdnca.edge.apt-repository/v1` schema；每个
release 的绝对目录除构建产物外还必须包含 `edge-agent.security.json` 和
`edge-agent.security.sig`。发布前策略与两类公钥必须经不同信任渠道固定。

## 节点安装与升级

先通过镜像、配置管理或离线介质下发 APT 公钥，不从待验证仓库下载自己的信任根：

```sh
sudo install -o root -g root -m 0444 cdnca-archive-keyring.gpg \
  /usr/share/keyrings/cdnca-archive-keyring.gpg
printf '%s\n' \
  'deb [signed-by=/usr/share/keyrings/cdnca-archive-keyring.gpg] https://packages.example.invalid/edge stable main' |
  sudo tee /etc/apt/sources.list.d/cdnca-edge.list >/dev/null
sudo apt-get update
apt-cache policy cdnca-edge-agent
sudo apt-get install cdnca-edge-agent=1.2.3-1
```

升级必须显式指定已批准版本，并在节点灰度编排中设置健康窗口：

```sh
sudo env CDNCA_EDGE_DEB_HEALTH_TIMEOUT=30 CDNCA_EDGE_DEB_HEALTH_STABLE=5 \
  apt-get install cdnca-edge-agent=1.2.4-1
systemctl is-active --quiet cdnca-edge-agent.service
```

包内 `postinst` 复用签名 manifest 安装器，执行配置预检、原子切换和稳定健康确认。
失败升级返回非零并恢复上一健康 release、Agent 状态和 systemd 服务。随后安装上一
`.deb` 恢复 dpkg 一致性，再调用受限回滚入口恢复与该 release 对应的状态：

```sh
sudo apt-get install --allow-downgrades cdnca-edge-agent=1.2.3-1
sudo /usr/libexec/cdnca-edge-agent/rollback.sh \
  --version 1.2.3 --health-timeout 30 --health-stable 5
```

回滚不会降低已接受的 `release_sequence`，不能用于重放旧的未批准发布。APT 的
OpenPGP 签名只保护仓库与 `.deb` 下载；包内独立 Ed25519 manifest 仍是节点运行时
安装权威，两者任一失败都必须 fail closed。
