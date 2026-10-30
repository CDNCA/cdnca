# 安装与配置

## 当前可交付边界

仓库提供本地基础设施 Compose、五个控制面工作负载的 Helm chart，以及 Edge
Agent 的 systemd 打包流程。它还没有五个控制面组件的生产镜像构建定义，Helm
默认镜像地址故意使用不可路由占位值；`license-service` 的生产 KMS/HSM signer
适配器也未完成。因此当前可以做本地开发和隔离集群集成，不能仅凭 Pod Ready
宣称生产部署完成。

## 本地基础设施

前置条件是 Docker Compose v2、GNU Make、Bash 和 curl。从仓库根运行：

```sh
make up
make status
make infra-test
```

该栈启动 PostgreSQL、Redis、ClickHouse 和 NATS JetStream。默认配置位于
[`infra/env/development.env`](../../infra/env/development.env)，仅绑定本地开发，
其中凭据不得复制到测试或生产。自定义本地值应放在未提交的独立环境文件中：

```sh
cp infra/env/development.env .env.local
make ENV_FILE=.env.local up
```

`make down` 保留命名卷。仓库故意不提供自动删除卷的目标。

## 服务启动顺序

1. 准备客户 PostgreSQL、Redis、NATS 和所需 CA/工作负载证书。
2. 对 `control-api` 显式执行 `migrate up`，再创建首个本地管理员。
3. 准备独立授权 PostgreSQL、Operator 身份 keyring、签名器和 SMTP。
4. 使用 `license-bootstrap` 创建首个平台 owner；数据库已有 Operator 后命令拒绝重复 bootstrap。
5. 启动 `license-service`，再让 `control-api` 激活或续租并缓存验签结果。
6. 启动 `control-api` 的 HTTP 和 ControlInternal mTLS listener。
7. 启动 `agent-gateway` 的 enrollment、Agent mTLS 和 Pod health 三个 listener。
8. 创建节点和一次性 enrollment token，再安装 Edge Agent。

开发命令、必需变量和迁移入口分别记录在
[`control-api README`](../../services/control-api/README.md)、
[`license-service README`](../../services/license-service/README.md) 和
[`agent-gateway README`](../../services/agent-gateway/README.md)。

## 配置与 Secret 边界

| 组件 | 必要配置类别 | 敏感项要求 |
| --- | --- | --- |
| `control-api` | 客户数据库、JWT、API key pepper、DNS 信封密钥、安装身份、授权根 pin、ControlInternal TLS、节点 CA、NATS/Redis、Edge publication signer | 私钥和密钥由 secret manager 或只读文件注入，不进入数据库、values、日志或命令参数；remote signer 的 CA、owner-only bearer 和公钥文件按 [`Edge publication signer`](../runbooks/edge-publication-signer.md) 配置 |
| `license-service` | 独立数据库、Operator Origin、TOTP/凭据/身份 token keyring、SMTP、当前 Ed25519 signer | keyring 必须保留仍被数据库引用的旧版本；生产 signer 应迁移至 KMS/HSM |
| `agent-gateway` | 三个监听地址、实例 UUID、TLS、Agent CA、ControlInternal 工作负载身份、Redis、NATS | Gateway 不得获得 PostgreSQL、节点 CA 私钥或安装私钥 |
| Edge Agent | 节点 ID、Gateway 地址和根 CA、证书/私钥路径、状态与 release 目录、OpenResty 命令和本地 health URL | 配置文件和身份目录必须为 root 所有且禁止 group/other 写入；私钥权限为 `0600` |

生产键名和挂载方式以
[`Kubernetes 运行手册`](../runbooks/kubernetes-control-plane.md) 与
[`infra/helm/cdnca/values.yaml`](../../infra/helm/cdnca/values.yaml) 为准。
不要把本文表格当作可直接填入真实值的模板。

## 健康端点与端口

| 组件 | 默认端口 | 健康检查 |
| --- | --- | --- |
| `control-api` | 8080 HTTP、9091 ControlInternal mTLS | `/health/live`、`/health/ready` |
| `agent-gateway` | 19443 enrollment TLS、19444 Agent mTLS、8082 health | health listener 的 `/health/live`、`/health/ready` |
| `license-service` | 8081 业务 HTTP、8083 health | health listener 的 `/health/live`、`/health/ready` |
| `web`、`operator-console` | chart 默认 8080 | `/` |

Readiness 会检查关键依赖和身份契约。不要为了让滚动发布继续而把失败的 readiness
改成 TCP 探针或固定成功响应。

## Kubernetes

Chart 位于 [`infra/helm/cdnca`](../../infra/helm/cdnca/)，要求 Kubernetes 1.27
或更高版本。它不安装 PostgreSQL、Redis、NATS、ClickHouse，不创建 Secret，也不
安装 Edge Agent。

隔离环境先执行：

```sh
helm lint infra/helm/cdnca -f values-production.yaml
helm template cdnca infra/helm/cdnca \
  --namespace cdnca \
  -f values-production.yaml > rendered.yaml
```

私有 values 只能保存镜像 digest、Secret 引用、入口和网络策略等非敏感配置。
生产前必须完成镜像扫描/签名、KMS/HSM signer、外部数据服务 HA、NetworkPolicy
收窄、备份恢复抽检和预生产迁移验证。完整步骤和回滚命令见
[`kubernetes-control-plane.md`](../runbooks/kubernetes-control-plane.md)。

## Edge Agent

Edge Agent 的构建、签名 manifest、安装、升级和回滚入口见
[`agents/edge-agent/packaging/README.md`](../../agents/edge-agent/packaging/README.md)
、[`Edge Agent 原生 APT 发布与安装`](../../infra/apt/README.md)
与 [`edge-agent-systemd.md`](../runbooks/edge-agent-systemd.md)。生产安装必须：

- 预置可信 Gateway 根，不从 Enrollment 响应静默引入信任根；
- 在 Agent 本机生成 mTLS 和 X25519 私钥，私钥不离开节点；
- 使用一次性、短时 enrollment token，成功后立即删除；
- 使用不可变 release、预检、原子切换、健康确认和明确回滚目标；
- 至少保留当前与前一健康版本，控制面失联时继续本地守护。
- Debian 12/Ubuntu 24.04 只从固定 `signed-by` keyring 的原生 APT 仓库安装；
  发布前同时验证包内 manifest 签名、SBOM/provenance 身份绑定、签名安全扫描报告、
  上游安全公告处置和 HTTP/1/2/3、WebSocket、Range、rewrite、刷新协议回归。

不要通过 SSH 或直接覆盖生效文件模拟配置发布。
