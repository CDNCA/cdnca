# OPS-08 本地源输入 Bootstrap

`bootstrap-source-inputs.sh` 只负责 `tests/final-acceptance/input-contract.json`
中 `ops08.local_source_inputs` 的 21 项。它先读取并验证全部输入，再创建任务
专属 staging；最终以 `mv` 原子发布 owner-only material directory、manifest 和
环境文件。环境文件只包含路径、SHA-256 引用或版本，不写入密钥、凭据或制品内容。

```sh
UPGRADE_E2E_LICENSE_AUTHORITY_FIXTURE_SQL=/secure/fixtures/license.sql \
UPGRADE_E2E_CONTROL_AUTHORITY_FIXTURE_SQL=/secure/fixtures/control.sql \
CONTROL_ACTIVATION_CREDENTIAL_FILE=/secure/secrets/activation-code \
UPGRADE_E2E_INITIAL_ARTIFACT=/secure/releases/initial/edge-agent \
UPGRADE_E2E_INITIAL_SBOM=/secure/releases/initial/edge-agent.spdx.json \
UPGRADE_E2E_INITIAL_MANIFEST=/secure/releases/initial/manifest \
UPGRADE_E2E_INITIAL_SIGNATURE=/secure/releases/initial/manifest.sig \
UPGRADE_E2E_INITIAL_PUBLIC_KEY=/secure/releases/initial/public-key.pem \
UPGRADE_E2E_FORWARD_BUNDLE=/secure/releases/forward.bundle \
UPGRADE_E2E_ROLLBACK_BUNDLE=/secure/releases/rollback.bundle \
bash tests/upgrade-process-e2e/bootstrap-source-inputs.sh \
  --output /tmp/cdnca-upgrade-source.env
```

本地无需外部事实即可生成 11 项：Edge v2 配置、授权根公钥 pin、安装私钥、
Control command trust、Control/Edge 升级签名私钥、三项 Edge trust SHA 以及两个
版本。实际 trust 文件和私钥位于 `/tmp/cdnca-upgrade-source.env.inputs`，私钥与
凭据为 `0600`；manifest 为 `/tmp/cdnca-upgrade-source.env.manifest.json`。

仍需本地上游提供 10 项：License/Control authority fixture SQL、一次性 activation
credential、初始 artifact/SBOM/manifest/signature/public key，以及 forward/rollback
release bundle。正式 Edge bundle 必须由发布契约产生；本脚本不会在 Go toolchain 或
Docker 不满足发布契约时伪造它们。

脚本绝不生成或接受为本地事实的 GHCR OCI digest、GitHub OIDC identity、cosign
keyless signature、SLSA provenance 或 SPDX supply-chain attestation。缺少任一上游
输入、输出路径已存在、源文件为 symlink/非 owner-only 或校验失败时，在创建输出前
退出，`resources=0`。

唯一静态合同：

```sh
bash tests/upgrade-process-e2e/bootstrap-source-inputs.contract-test.sh
```
