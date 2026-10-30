# 安装指南（社区版）

## 概述

社区版免费，不需要激活码，也不连接授权服务：

- 社区授权内置在 control-api 里，基础功能和配额不限，商业模块不提供。
- 安装器只在本机写入安装记录（`control-api install-community --installation-id`）。
- 主控在安装后向官方匿名上报一次安装信息（安装 ID、版本、节点数、站点数），之后每 7 天一次；在 `/etc/cdnca-control/control.env` 里设 `COMMUNITY_REPORT_URL=off` 可关闭。
- 社区版没有在线升级，升级时换用新版本的程序包。

忘记主控管理员密码见 [platform-admin-recovery.md](runbooks/platform-admin-recovery.md)。

## 架构

```
┌─────────────────────┐
│     管理端           │  control-api + agent-gateway + web 控制台
│  (Control Plane)    │  - 内置社区授权，无需激活
└──────────┬──────────┘  - 生成节点注册密钥
           │
           │ 节点注册密钥（nrk1.…）
           ↓
┌─────────────────────┐
│      节点端          │  edge-agent + OpenResty
│   (Edge Nodes)      │  - 用注册密钥向管理端的 Gateway 注册
└─────────────────────┘
```

## 1. 管理端安装

### 1.1 准备程序包

安装器需要签名的主控整包（`cdnca-control-native.tar`）、配对的发布公钥清单，以及同一版本的节点包。两种方式二选一：

- 发布站：`--release-server https://<发布站>`。安装器从 `/downloads/control-native/latest/`、`/downloads/edge-agent/latest/` 下载并按 `SHA256SUMS` 和发布公钥校验。
- 本地文件：先把整包和公钥清单上传到目标机，再用 `--native-package-file <整包绝对路径> --native-trust-file <公钥清单绝对路径>`。

### 1.2 执行安装

在目标服务器上以 root 执行（`./install-control.sh --help` 查看全部参数）：

```bash
./install-control.sh --release-server "https://<发布站>" --master-host "<管理端域名>" --master-port 443
```

脚本会交互询问首个管理员用户名、密码和证书联系邮箱。非交互执行时，用 `--admin-username`、`--certificate-email`，以及 root 独占文件 `--admin-password-file`。密码不会写入服务环境、日志或安装输出。

Gateway 的注册端口和 mTLS 通道端口：不传 `--gateway-ports <注册>,<通道>` 时，安装器在 20000–29999 中随机选两个本机空闲端口，安装结束时打印，并写入 `/etc/cdnca-control/gateway.env`。防火墙和 CDN 回源按这两个实际端口配置。需要固定端口时显式传入，例如 `--gateway-ports 21443,21444`。

### 1.3 安装流程

1. 预检系统要求、公网端口与已有安装
2. 下载并校验主控整包、节点包与运行时依赖
3. 安装并配置 PostgreSQL、Redis、ClickHouse、NATS JetStream
4. 生成安装身份（Ed25519）、内部 PKI 与运行时密钥
5. 执行数据库迁移，写入社区版安装记录（`install-community`）
6. 创建首个管理员，初始化节点 CA 与系统配置
7. 启动 control-api、agent-gateway、Web，配置防火墙
8. 启用每日的社区身份刷新定时器（未注册时自动跳过）

### 1.4 接入节点市场 / 插件市场（可选）

社区版可以在节点市场、插件市场购买规则包、主题和插件。购买前先用免费的门户账号注册一次本机安装：

```bash
/data/cdnca-native-root/cdnca/current/bin/control-api community-register --account <门户账号> --password-stdin
```

口令从标准输入读取。注册时用本机安装私钥签名证明，拿到官方签发的社区身份（30 天有效，定时器每天刷新），同时签发访问市场用的 mTLS 客户端证书。默认官方服务地址是 `COMMUNITY_SERVICE_URL=https://auth.cdnca.com`。

## 2. 节点端安装

### 2.1 获取节点安装命令

**位置**：管理端 web 控制台 → "节点"页（"系统管理 → 维护升级"页显示同一条命令）

1. 登录管理端控制台，打开"节点"页
2. 页面显示一条对所有节点通用的安装命令，内含作用域级节点注册密钥（`nrk1.` 开头，可在页面重置），复制即可，不需要先创建节点
3. 在节点服务器上以 root 执行；节点自注册后出现在"待初始化"，在主控上初始化并绑定线路组

### 2.2 执行节点安装命令

页面复制的命令形如：

```bash
printf '%s\n' '<注册密钥>' | bash <(curl --proto '=https' -fsSL 'https://<管理端>/downloads/install-node.sh') \
  --control-plane 'https://<管理端>' --registration-key-stdin
```

注册密钥经 stdin 传入，不出现在进程参数里。升级信任摘要、Gateway 入口（含安装时选定的实际端口）和下载备用源由 `install-node.sh` 从 `https://<管理端>/downloads/node-install-defaults` 读取，命令里不需要写 `--gateway-address`、`--gateway-enrollment-address`；只有自定义入口时才追加这两个参数和 `--gateway-server-name`。

**安装流程**：
1. 检查系统要求
2. 下载并校验管理端发布的 edge-agent 制品、信任清单和 Gateway CA
3. 用注册密钥通过 Gateway TLS enrollment
4. 写入 mTLS 身份和配置，启动 systemd 服务
5. 节点进入管理端"待初始化"列表，初始化后即可绑定线路组、接收配置

## 3. 关键文件

| 文件 | 用途 |
|------|------|
| `scripts/install-control.sh` | 管理端安装脚本 |
| `scripts/install-node.sh` | 节点端安装脚本 |
| `services/control-api/cmd/control-api/install_community.go` | 社区版安装记录 |
| `services/control-api/cmd/control-api/community_register.go` | 社区注册与身份刷新 |
| `services/control-api/cmd/control-api/community_report_runtime.go` | 匿名安装信息上报 |
| `apps/web/src/pages/NodeInstallCommand.tsx` | 节点安装命令（节点页、维护升级页共用） |
| `api/openapi/v1/control.yaml` | 管理端 API |
| `proto/agent/v1/gateway_service.proto` | 节点 enrollment 与 mTLS 通信契约 |

## 4. 测试流程

### 4.1 管理端

1. 准备一台隔离的 Linux 测试服务器（x86_64，Ubuntu 24.04）
2. 用发布站或本地签名整包执行 `install-control.sh`
3. 验证数据库迁移、安装记录、管理员 bootstrap、`systemctl` 状态和 `/health/ready`

### 4.2 节点

1. 确认管理端 `/downloads/install-node.sh`、`/downloads/gateway-ca.pem` 可下载
2. 在"节点"页复制安装命令，确认注册密钥经 stdin 传入（`--registration-key-stdin`）
3. 在隔离节点服务器上执行，确认 Gateway 两个端口是主控安装结束时打印的实际值
4. 节点出现在"待初始化"，初始化并绑定线路组，验证心跳和 mTLS 长连接

## 5. 安全注意事项

1. **HTTPS 必需**：程序包与节点制品只经 HTTPS 下载，并校验 SHA-256 与发布公钥签名
2. **注册密钥保密**：节点注册密钥只经 stdin 传入；泄露后在"节点"页重置
3. **密钥安全**：安装 Ed25519 私钥只在管理端生成和保存，从不外传；社区注册与市场证书签发都只发送签名证明
4. **上报内容**：匿名上报只含安装 ID、版本、节点数、站点数，不含站点域名、用户或日志

## 6. 故障排查

### 6.1 管理端安装失败

1. 程序包校验失败：确认整包、`SHA256SUMS` 与公钥清单来自同一版本
2. 端口被占用：安装器不会改动已占用的公网端口，换端口或释放后重试
3. 依赖安装失败：查看安装器提示保留的日志路径

### 6.2 节点注册失败

1. 管理端 URL 是否正确
2. 注册密钥是否为当前值（页面重置后旧密钥失效）
3. 防火墙是否放行 Gateway 的两个实际端口
4. 管理端服务是否运行

### 6.3 社区注册失败

- `invalid_credentials`：门户账号或口令错误
- `installation_taken`：这台安装已被其他账号注册，或已换过安装密钥
- `request_expired`：本机时间与标准时间相差超过 5 分钟，校准时间后重试

## 7. 相关文档

- [架构设计](./architecture.md)
- [开发者入口](./developer/README.md)
- [协议契约](./protocol-contracts.md)
