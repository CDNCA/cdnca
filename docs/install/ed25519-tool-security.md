# 自带 Ed25519 签名/验签工具：安全说明

更新：2026-10-16（r135-osmatrix）。实现：`tools/ed25519-tool/`。

## 1. 为什么要做

主控和节点安装链路上所有 Ed25519 操作原来都调用系统 openssl：

| 位置 | 操作 | openssl 命令 |
| --- | --- | --- |
| `install-control.sh` `generate_identity` | 生成安装身份密钥、导出公钥 | `genpkey -algorithm ED25519`、`pkey -pubout` |
| `install-control.sh` `make_activation_proof` | 激活证明签名 | `pkeyutl -sign -rawin` |
| `install-control.sh` `publish_upgrade_trust` | 生成节点升级执行密钥 | `genpkey`、`pkey -pubout` |
| `install-control.sh` `verify_native_install_package` | 主控整包签名校验 | `pkeyutl -verify -rawin` |
| `install-native-baseline.py` | 管理端基线清单验签 | `pkeyutl -verify -rawin` |
| `configure-control-runtime.py` | 生成运行时发布密钥 | `genpkey`、`pkey -pubout -outform DER` |
| `install-node.sh` `verify_native_package` / `probe_packaging_helper` | 节点整包验签、helper 回执验签 | `pkeyutl -verify -rawin` |
| 节点包 `packaging/scripts/lib.sh` `verify_bundle` | 安装、升级、每次 Agent 启动前（`preflight.sh`）校验 manifest | `pkeyutl -verify -rawin` |

`pkeyutl -rawin` 只有 OpenSSL 3.0 才有，`genpkey -algorithm ED25519` 要 1.1.1 以上。实测 Ubuntu 16.04–20.04、Debian 9–11、CentOS 7、EL8 都做不了（`os-support-matrix.md` 6.1）。

## 2. 工具做什么、不做什么

`cdnca-ed25519` 是一个只用 Go 标准库（`crypto/ed25519`、`crypto/rand`、`encoding/pem`、`os`）写的静态二进制，`CGO_ENABLED=0`，不依赖 glibc 和 OpenSSL。子命令与被替换的 openssl 调用一一对应：

| 子命令 | 替换 | 输入/输出 |
| --- | --- | --- |
| `genkey OUT` | `openssl genpkey -algorithm ED25519 -out OUT` | 新建 0600 PKCS#8 PEM（`O_EXCL|O_NOFOLLOW`，不覆盖） |
| `pubkey KEY [--der]` | `openssl pkey -in KEY -pubout [-outform DER]` | 标准输出 SPKI PEM 或 DER |
| `sign KEY MESSAGE` | `openssl pkeyutl -sign -rawin -inkey KEY -in MESSAGE` | 标准输出 64 字节原始签名 |
| `verify PUB MESSAGE SIGNATURE` | `openssl pkeyutl -verify -pubin -inkey PUB -rawin -in MESSAGE -sigfile SIGNATURE` | 退出码 0 = 有效，1 = 无效或输入不合规 |
| `check-public PUB` | `openssl pkey -pubin -in PUB -text_pub` 中的 Ed25519 判断 | 退出码 |

格式与 openssl 完全一致：私钥是 `-----BEGIN PRIVATE KEY-----` 包裹的 48 字节 PKCS#8（前缀 `302e020100300506032b657004220420`），公钥是 44 字节 SPKI（前缀 `302a300506032b6570032100`）。已安装主机上 openssl 生成的密钥，工具可以直接读；工具生成的密钥，openssl 也能读。测试里双向校验。

工具不做的：不联网，不读环境变量，不读配置，不接受口令，不处理 RSA/EC，不做 X.509（证书仍由 openssl 生成和校验，见第 5 节）。所有输入文件都限制大小（PEM 4 KiB，消息 16 MiB，签名必须正好 64 字节），PEM 只接受单个块且块后不能有其他内容，解码出的 DER 必须与上述固定前缀逐字节相等，否则拒绝。Ed25519 验签使用 `ed25519.Verify`（RFC 8032 纯 Ed25519，与 `pkeyutl -rawin` 相同）。

## 3. 信任链

信任链不变：每一步要执行的工具，在执行前都由一个已经受信任的组件按固定 sha256 校验。

```
授权端 HTTPS 下发 install-control.sh（现有信任根，不变）
  └─ install-control.sh 内写死 CDNCA_ED25519_TOOL_SHA256
       └─ 主控签名整包成员 cdnca-ed25519：
          流式读取时就核对 sha256，先核对再落盘（0700 私有目录，0500），之后才执行它去验整包签名
            └─ 整包签名通过后，同一份工具安装到 /usr/local/libexec/cdnca/cdnca-ed25519
               （root、0555、单链接）；主控辅助脚本只调用这个固定路径
            └─ 主控把同一份工具发布到 /downloads/edge-agent/cdnca-ed25519
                 └─ install-node.sh（它本身是签名整包成员）写死同一个 sha256，
                    下载后先核对再执行，安装到 /usr/libexec/cdnca-ed25519（root、0555）
                      └─ 节点包 lib.sh 只调用这个固定路径；文件不存在时才退回系统 openssl
```

需要说明的几点：

- 整包签名覆盖这个成员（它在签名清单的 `files` 列表里），但验签时还不能信任它，所以执行它之前先用安装器内写死的 hash 校验。这样，被替换的工具会在执行前就被发现，不会用它去“验证”它自己所在的包。
- hash 固定写在两个安装器源码里（`CDNCA_ED25519_TOOL_SHA256`，当前 `82d8412f…7d17`）。主控整包构建器（`native-control-install-package.mjs`）用 `tools/ed25519-tool/build.sh`（`GOTOOLCHAIN=go1.27.3`，`-trimpath -buildvcs=false -ldflags='-s -w -buildid='`，`CGO_ENABLED=0`）从归档源码重编，产物必须等于 `install-node.sh` 里的 hash，否则不出包。实测 macOS 交叉编译与 `golang:1.27.3-bookworm` 容器内编译得到同一个 hash。`tests/ed25519-tool-pin.test.mjs` 在 CI 里重编比对，并检查两个安装器的 hash 相同、工具只引用标准库。
- 节点 lib.sh 运行在 helper 沙箱里；`/usr/libexec/cdnca-ed25519` 不在 helper 的 `ReadWritePaths` 中，被 `ProtectSystem=strict` 保护，升级事务改不了它。系统 openssl 本来也是按“root 拥有、不可写的系统路径”来信任的，这个工具的信任方式与它相同。
- 升级工具本身（换 Go 版本、修 bug）的步骤：改源码，重新生成 hash，同时更新三处固定值。旧版本节点上已经安装的工具继续可用（格式与命令不变）。

## 4. 威胁与对策

| 威胁 | 对策 |
| --- | --- |
| 下载被篡改的整包里换掉工具，让它对任何签名都返回成功 | 执行前按安装器内写死的 hash 校验；不一致时整包被拒，不会执行 |
| 工具文件在校验后、执行前被替换（TOCTOU） | 校验在流式读取时完成，写入新建的 0700 私有目录（`O_EXCL|O_NOFOLLOW`）；只有 root 能写这个目录 |
| 已安装工具被替换 | 固定路径在 root 拥有、不可写的目录中；与 /usr/bin/openssl 同等保护；helper 沙箱不可写 |
| 非规范或畸形密钥绕过检查 | DER 必须等于固定前缀加 32 字节，PEM 只能有一个块，块后不能有内容 |
| 私钥泄露 | `genkey` 只新建 0600 文件；私钥从不出现在参数或标准输出中；工具不打印输入内容 |
| 工具与 openssl 结果不一致 | 测试：工具签名用 openssl 验、openssl 签名用工具验、篡改一位必须失败（OpenSSL 3 主机上运行） |

## 5. 范围之外

- X.509（自签 CA、EC P-256 证书、链校验）仍用系统 openssl。这部分在 OpenSSL 1.1.1 上可以用；OpenSSL 1.0.2/1.1.0（CentOS 7、Ubuntu 16.04、Debian 9）缺 `-addext` 等参数，要在这些系统上用，需要另外改写证书生成，见 `os-support-matrix.md`。
- `openssl rand`、`openssl dgst -sha256` 在所有版本上都可用，不需要替换。
