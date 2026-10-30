# ADR 0013：网关独立部署、套 CDN、多网关冗余与控制面故障时的节点韧性

- 状态：设计阶段，第四版（修订：套 CDN 时 CDN 对外 443、回源端口填网关端口，删除固定端口白名单与区间）。第三版（网关自己监听注册/通道端口，不经主控 nginx 中转）的通道设计保留。GW-03/04/05 与 GW-07 节点侧已实现（§9）；GW-01/02 另行实现。全部进 1.0.35，不做 1.0.34 及更早的兼容。
- 需求与决定要点见 §1。
- 关联：[ADR 0004](0004-signer-revocation-bootstrap-checkpoint.md)（离线 checkpoint）、[ADR 0010](0010-auto-defense.md) §1（节点自治）。
- PoC：[`tests/gateway-cdn-poc/`](../../tests/gateway-cdn-poc/)，结果见 §4.7。
- 行号基于集成头 `d7babee27`（第一版）与 `e43c78cef`（第二、三版新增的安装器事实，§2.1）。

各版变化：

| 项 | 第一版 | 第二版（已撤回） | 第三版 | 第四版（现行） |
|---|---|---|---|---|
| 默认通道 | 节点直连网关 19444，CDN 是可选入口 | 管理端同域名 443 `/agent/v1/tunnel`，经主控 nginx 反代本机网关 | **网关自己监听**注册端口与通道端口（端口见下行），不经主控 nginx；同一端口同时接受 gRPC mTLS 直连与 WebSocket 隧道 | 同第三版；隧道的两个路径（`/agent/v1/tunnel`、`/agent/v1/enroll`）在两个网关端口上都可用，CDN 只需回源一个端口（§4.2） |
| 注册 | 19443 | 并入 443 `/agent/v1/enroll` | 回到网关注册端口，同样同端口接受 gRPC 与隧道 | 直连走注册端口；经 CDN 走 `/agent/v1/enroll` 隧道路径 |
| 端口 | 写死 19443/19444 | 只用 443 | 端口白名单（已被替换） | **安装时在 20000–29999 内随机两个空闲端口并告知**；可用 `--gateway-ports` 指定 1024–65535，安装器做冲突检查并给推荐值（§3.5） |
| 套 CDN | gRPC 签名头或 WebSocket | 管理端域名套 CDN 即可 | 给网关名套 CDN，边缘端口 = 网关端口；须选 CDN 支持的低阶端口 | **节点连 CDN 的 443**（网关域名或主控域名，WebSocket），CDN 回源端口填网关端口；只要 CDN 支持 WebSocket 与自定义回源端口（§4.3） |
| 节点安装输入 | `--control-plane`，网关地址另读 | 只填 `--control-plane` | 只填 `--control-plane`；网关地址、端口、首选传输由主控 `node-install-defaults` 下发 | 同第三版；下发的端点为 {连接地址, SNI/Host, 传输 `ws`\|`grpc`}，可多个、按健康切换（§4.5） |
| 节点真实 IP | 只在直连会话确认 | 可信 CDN 回源段的转发头 + 节点自报网卡 + 网关回显 | 同第二版，改由网关进程自己按规则取（没有 nginx 了） | 同第三版；预置可信段只有 Cloudflare，其他 CDN 由管理员添加 |
| 制品下载 | 直连优先 | 走同一入口 | 同第二版：走当前会话所在网关地址 | 同第三版 |
| gRPC 经 CDN（签名头） | 可选模式 | 删除 | 删除 | 删除 |
| 证书 TTL / 自助恢复 | 待定 | 30 天 / 180 天 | 30 天 / 180 天 | 30 天 / 180 天 |

## 1. 目标与用户决定

用户原话要点（不改写）：

1. 安装脚本提供分开安装：一体（主控+网关同机）/只装主控/只装网关；装网关时填主控 IP 或域名，绑定主控。
2. 网关要能正常套 CDN。
3. 最好可装冗余网关。
4. 网关套 CDN 出意外时要能兜底。
5. 用户问：同类产品怎么做；主控/网关故障时节点能撑多久、租户受什么影响。

查实并按缺陷纳入：节点证书 24 小时有效，主控或网关不可用超过 24 小时后节点证书过期，需人工重新注册（§6.1）。

已定：证书过期自助恢复期限 180 天；节点证书有效期 30 天。（同条里"制品下载优先直连"已被第二版推翻，见下。）

需求要点（不改写）：

6. 要一条命令装好。
7. 网关与主控同机时，主域名一定会套 CDN（毋庸置疑），所以默认形态下节点必须能经 CDN 连上网关。
8. 节点真实 IP 用 CDN 加的头即可。
9. "直连不通才走 CDN"不合理：网关不通，CDN 也不通。

第二版定的"管理端同域名 443、经主控 nginx 反代本机网关"已被否决（见下）。第二版里仍然有效的：真实 IP 取可信 CDN 回源段的转发头 + 节点自报网卡 IP；制品走同一入口；多端点保留；Redis/NATS 在 `all` 模式本机，独立网关优先同机房/内网，跨公网时 TLS+每网关凭据+按 IP 放行（用户已同意）。

需求要点（不改写）：

10. 不要经主控 nginx 443 转给本机网关（"主控给了本机网关、网关再给你，跟传数据玩似的"），该用 19443/19444 就用，让用户独立开放这两个端口。

据此定（第三版）：网关直接监听 19443/19444（端口可配置，以便选 CDN 支持的端口），同一端口同时接受 gRPC mTLS 直连与 WebSocket 隧道；节点安装仍只填主控域名，网关地址由主控下发；撤回第二版的 443 方案。

需求要点（不改写）：

11. 指定节点通信端口，给区间，不让乱指定；低阶端口给几个固定的，高阶端口划分区间；不选择就用默认。

据此定（第三版，已被第四版替换）：默认 19443/19444；低阶固定可选 2053/2083/2087/2096/8443（CDN 可代理端口，独立网关机另可选 443）；高阶区间 20000–29999；其余拒绝；安装器校验不冲突。

需求要点（不改写）：

12. 同类产品只需要输入端口就可以，为什么我们这么多问题。

调研后据此定（第四版，来源见 §4.3）：第三版的固定端口白名单是按"CDN 边缘端口 = 网关端口"推出来的，这个前提不必要。国内外 CDN 对外基本只开 80/443，但回源端口大多可自定义，所以套 CDN 的标准做法是：节点连 CDN 的 443（网关域名或主控域名，WebSocket），CDN 回源端口填网关端口（安装时随机或自选的注册端口）。网关端口因此不再需要白名单；定为"20000–29999 随机分配并告知，可指定 1024–65535"（§3.5）。可信回源段默认只预置 Cloudflare（§4.4）。

本 ADR 回答五件事：部署形态、安装器与端口（§3）、节点通道与套 CDN（§4）、冗余（§5）、控制面故障韧性（§6）、任务拆分与待用户定（§7、§8）。

## 2. 现状（已核对代码）

### 2.1 部署与安装

| 事实 | 位置 |
|---|---|
| 主控安装器 `main` 固定顺序装 Redis/NATS/control-api/网关/web，没有模式参数，每个主控同机一个网关 | `scripts/install-control.sh:3072-3132`（`setup_gateway` 在 :3123） |
| 网关上游写死同机：`CDNCA_CONTROL_ADDRESS=127.0.0.1:9091`、`CDNCA_CONTROL_SERVER_NAME=localhost` | `install-control.sh:2293-2294` |
| 主控内部 gRPC 只监听回环：`CONTROL_INTERNAL_GRPC_ADDR=127.0.0.1:9091`；服务端证书只签 `localhost`/`127.0.0.1` | `install-control.sh:2025`、`:1244` |
| 网关→主控是 mTLS：网关客户端证书由 `gateway-client-ca` 签，URI SAN `spiffe://cdn-platform/gateway/control`，主控按这个 SAN 认网关 | `install-control.sh:1242,1250-1252,2028-2029`；`control-api/internal/controlinternal/service.go:31,96` |
| Redis/NATS 默认本机：`redis://127.0.0.1:6379/0`，NATS 监听 `127.0.0.1:4222`，无认证无 TLS | `install-control.sh:56,993,2236-2237` |
| 已有 `--gateway-host`（节点连网关用的地址，默认等于管理端地址），网关服务端证书按它签 | `install-control.sh:122,951-955,1246` |
| 节点安装只填 `--control-plane`，网关地址从 `/downloads/node-install-defaults` 读（`gateway_enrollment_address`/`gateway_address`/`gateway_server_name`，每项只有一个值） | `install-control.sh:1905-1918`；`install-node.sh:239-255` |
| 节点配置 `gateway` 只有一个 `address`+`server_name` | `agents/edge-agent/cmd/edge-agent/config.go:59-65`；`install-node.sh:2243` |
| 已有"网关端口迁移"机制：节点持久化当前端点，收到命令后探测新端点再切换（`errGatewayEndpointSwitched`），只支持单一活动端点 | `agents/edge-agent/internal/gatewayclient/port_transition.go:27-60,144-250` |
| 主控 nginx 只有一个 `server`：`listen ${MASTER_PORT} ssl http2`（默认 443）、`server_name _`，`/v1/` 反代 `127.0.0.1:8080`，其余是管理页静态文件；没有 `/agent/` 路径，没有 `real_ip` 配置，转发头一律写 `$remote_addr` | `install-control.sh:2399-2517`（`/v1/` 在 :2498-2505）；默认端口 :948,972 |
| `GATEWAY_HOST` 默认等于管理端地址 `MASTER_HOST`；`node-install-defaults` 与 `runtime-config.js` 写死 `${GATEWAY_HOST}:19443/19444` | `install-control.sh:953,974`；`:1891-1918` |
| 网关监听写死 `0.0.0.0:19443`/`0.0.0.0:19444`，`CDNCA_GATEWAY_AGENT_PUBLIC_ENDPOINT=${GATEWAY_HOST}:19444` | `install-control.sh:2291-2293` |
| 安装预检 `run_preflight` 的端口清单：管理端 HTTPS、80、19443、19444、4222、8222、8080、8082、9091、9445（升级源）、19000，装依赖时另加 5432、6379、8123、9000、9004、9005、9009；`preflight_check_ports` 按 `ss -ltn` 判占用；`preflight_check_firewall` 提示放行管理端口与 19443/19444 | `install-control.sh:907-933`（清单 :909-912，防火墙 :930）；`:597-608`；`:699-715` |
| 管理端端口另有保留表，命中即拒：`4222\|5432\|6379\|8080\|8082\|8123\|8222\|9000\|9004\|9005\|9009\|9091\|9445\|19000\|19443\|19444` | `install-control.sh:980-983` |
| 9445 已被"升级源"（私有套餐源 mTLS）占用 | `install-control.sh:910,2585-2598` |

### 2.2 节点身份与通道

| 事实 | 位置 |
|---|---|
| 网关两个监听：19443 注册（TLS，不要客户端证书）、19444 节点通道（TLS 1.3，`RequireAndVerifyClientCert`） | `services/agent-gateway/cmd/agent-gateway/tls.go:25-38`；`install-control.sh:2284-2285` |
| 节点身份只取自已验证 TLS 链的叶子证书：URI SAN `spiffe://cdn-platform/node/<uuid>`、序列号、证书 SHA-256；非测试代码 6 处调用 `authenticatedNode`，遥测另有 `validateTelemetryCertificate`（`telemetry.go:663-676`） | `services/agent-gateway/identity.go:25-65`；调用在 `gateway.go:326,356,563,615`、`node_inventory.go:31`、`telemetry.go:62` |
| 主控按节点 ID+证书序列号+SHA-256 判定授权与吊销 | `gateway.go:961-1000`；`control-api/internal/nodeidentity/service.go:321-333` |
| 节点私钥是 Ed25519，`client-key.pem` | `agents/edge-agent/internal/enrollment/enrollment.go:46,376` |
| 续签走 mTLS 通道：`RenewCertificate` 要求当前证书，校验 `CurrentSerialNumber` 等于 TLS 证书序列号 | `services/agent-gateway/registration.go:31-36`；`gateway.go:324-352` |
| 节点公网 IP 确认依赖 TCP 对端地址：网络清单里候选地址（节点默认出口网卡上的地址，`types.proto:237-242`）必须等于 `PeerIP`，否则 `peer_mismatch`；网关的 `PeerIP` 取自 gRPC peer，调用在 `gateway.go:287`、`node_inventory.go:45` | `gateway.go:3944-3955`；`control-api/internal/nodeidentity/network_inventory.go:120-122` |
| 制品端到端加密到节点（HPKE X25519 + AES-256-GCM），与传输层无关 | `agents/edge-agent/internal/gatewayclient/hpke.go:15-25` |

### 2.3 时间参数

| 参数 | 值 | 位置 |
|---|---|---|
| 心跳间隔 / 离线判定 | 15s / 45s | `services/agent-gateway/config.go:85-86` |
| 网关 gRPC keepalive | 30s，超时 10s；客户端 ping 最小间隔 10s | `config.go:87-89` |
| 节点重连退避 | 250ms→30s 指数，单次拨号受 `HandshakeTimeout` 约束 | `agents/edge-agent/internal/gatewayclient/config.go:72-73`；`client.go:1308-1370` |
| 节点判定网关失联 | 心跳 ack 超过 `OfflineAfter`（45s）未到 | `client.go:2283-2288` |
| 网关每次建连同步调主控 `GetNodeAuthorization`（超时 5s），会话中按快照到期一半刷新；刷新失败到离线截止即断会话 | `gateway.go:961-1000,2340-2360,3884-3886` |
| 授权快照 TTL | 1 分钟 | `control-api/internal/nodeidentity/service.go:34` |
| 节点证书 TTL / 续签窗口 | 24h；节点过半（12h）开始续签；主控配置上限 7 天 | `nodeidentity/service.go:32-33`；`validate.go:327`；`enrollment/renewal.go:101` |
| 节点 agent 启动时校验证书 `NotAfter`，过期即"load enrollment identity"失败退出 | `cmd/edge-agent/config.go:269-273`；`enrollment.go:649` |

### 2.4 网关状态（多网关的前提）

| 事实 | 位置 |
|---|---|
| 会话归属：Redis 哈希 `token/epoch/owner/inflight`，`INCR` 生成 epoch，TTL 45s，每 10s 续约；新会话只在 `inflight==0` 时接管（旧会话被围栏） | `services/agent-gateway/redis_sessions.go:98-150`；`cmd/agent-gateway/runtime.go:135-160` |
| 命令：JetStream 每节点一个 durable 消费者（`ConsumerPrefix_<nodeid>`，显式 ack，`MaxDeliver=-1`），与哪个网关进程无关 | `nats_commands.go:180-215` |
| 网关进程本地只有防重放窗口（每会话） | `replay.go:21`；`gateway.go:390` |
| `GatewayInstanceID` 取 `INSTALLATION_ID`（同机唯一） | `install-control.sh:2288` |

结论：会话与命令状态都在 Redis/NATS，多个网关进程共享同一 Redis/NATS 时设计上可以同时在线；目前没有多网关的集成测试（`redis_sessions_integration_test.go:24` 只测单协调器）。

### 2.5 节点失联时节点侧的事实

| 事实 | 位置 |
|---|---|
| OpenResty 主进程由 agent 的动态路由运行时拉起（开机由 agent 启动时 `dynroute.Recover` 拉起），agent 单元 `KillMode=process`，agent 退出不影响已加载配置；1.0.35 起不再安装 `cdnca-openresty-native.service` | `agents/edge-agent/internal/dynroute/recover.go:31`、`packaging/systemd/cdnca-edge-agent-root.service:23` |
| 节点自治：自动防御学习/判定/处置在节点本地，主控不在反应链路上 | `docs/adr/0010-auto-defense.md:11` |
| 内核封禁随封禁到期，由 agent 内的到期调度删除 | `agents/edge-agent/internal/firewall/kernel_bans.go:16-19` |
| 302 调度表无新表 120s 后停止重定向 | `libs/edgeconfig/sched302/sched302.go:70-72` |
| 遥测 spool：默认 1GiB 软 / 2GiB 硬，24h 软 / 168h 硬，背压模式 | `cmd/edge-agent/config.go:241-246` |
| 主控侧：一个作用域内所有节点都没有新监测报告时视为"上报链路故障"，不摘节点（fail open） | `control-api/internal/nodeserving/monitor.go:32-34,87-89` |

## 3. 部署形态与安装器

### 3.1 三种模式

`install-control.sh` 新增 `--mode all|control|gateway`，默认 `all`。三种模式都是一条命令装完，节点安装命令不变：只填 `--control-plane <管理端地址> --token <令牌>`。

| 模式 | 装什么 | 节点入口（公网） | 主控内部 gRPC | Redis/NATS |
|---|---|---|---|---|
| `all`（一体，默认） | 主控 + 本机网关 | 网关进程自己监听注册端口与通道端口（`0.0.0.0:<注册>`/`0.0.0.0:<通道>`，安装时按 §3.5 随机或指定），与管理端 nginx 无关；安装器提示放行这两个端口 | `127.0.0.1:9091` 不变；之后要加独立网关时，在"网关管理"页"开放网关接入"后加新监听（端口 GW-09 定，9445 已被升级源占用，§2.1） | 本机，回环 |
| `control`（只装主控） | 主控，不装网关 | 无 | 对网关开放 ControlInternal（mTLS，只认网关客户端证书） | 本机，对网关开放 4222/6379，强制 TLS+认证（§3.3） |
| `gateway`（只装网关） | agent-gateway 二进制与 systemd 单元 | 同 `all`：网关自己监听注册/通道端口（可选 443，§3.5） | 不涉及 | 不装，连主控上的 Redis/NATS |

`all` 模式下主控 nginx 不加任何 `/agent/` 路径，节点流量不经过它。管理端域名套不套 CDN 与节点通道无关；节点通道要不要套 CDN 是另一件事，看网关名怎么解析（§4.2）。

`gateway` 模式需要的输入：

```
printf '%s\n' '<一次性绑定令牌>' | bash install-control.sh --mode gateway \
  --control https://cdnca.example.com        # 主控管理端地址（IP 或域名，必须 HTTPS）
  --gateway-token-file -                     # 令牌从 stdin 读（不进进程参数），主控"网关管理"页生成
  --gateway-host gw2.example.com              # 本网关的公网名（域名或 IP）
  [--gateway-ports 21443,21444]               # 注册端口,通道端口；1024–65535 任选，不填 = 20000–29999 随机（§3.5）
```

`all` 模式同样接受 `--gateway-host`（已有，默认等于管理端地址）与 `--gateway-ports`。不要求填 Redis/NATS/主控内部地址：绑定成功后由主控下发（§3.2）。

网关服务端证书（节点直连 gRPC 与隧道外层共用同一张，§4.2）：
- 默认用 root CA 签（今天的做法，SAN = `--gateway-host`，`install-control.sh:1246`），节点用安装时校验过的 root CA 验证（`install-node.sh:314`）。直连不需要公网证书。
- 网关名套 CDN 时，CDN 回源可以验或不验源站证书：验时需要公网证书，安装器对域名复用 `issue_public_certificate`（`install-control.sh:2756`）签 Let's Encrypt，或由管理员给证书文件。此时节点直连同样能用（节点信任系统根 + root CA，§4.2）。

### 3.2 网关绑定流程（一次性令牌）

1. 管理员在主控"系统 → 网关管理"点"添加网关"，填名称、网关域名（`gateway-host`），主控生成一次性绑定令牌：随机 32 字节，库里只存 SHA-256，有效期 1 小时，只能用一次，带 `gateway_id`。页面给出完整安装命令。
2. 网关安装器在本机生成两把私钥（不出机器）：
   - 网关→主控 mTLS 客户端密钥（Ed25519）；
   - 节点通道服务端密钥（ECDSA P-256，兼容各家 CDN 回源校验）。
3. 安装器先拉 `https://<控制端>/downloads/gateway-ca.pem`（即安装 root CA）并按令牌里的 CA 指纹校验（令牌格式 `gwt1.<gateway_id>.<root_ca_sha256 前 16 字节 hex>.<secret>`，指纹防主控地址被劫持时把网关绑到假主控）。
4. 安装器带两份 CSR 调 `POST /v1/gateway-bindings/complete`（公网 HTTPS，令牌认证，限速；主控 nginx 只反代 `/v1/`，故不用 `/api/v1/`）。主控校验令牌后：
   - 用 `gateway-client-ca` 签客户端证书，URI SAN `spiffe://cdn-platform/gateway/<gateway_id>`（今天是固定 `.../gateway/control`，改为每网关一个，主控按前缀 `spiffe://cdn-platform/gateway/` 认网关并取出 `gateway_id`）；
   - 用 root CA 签网关服务端证书（直连 gRPC、隧道外层、隧道内层共用），SAN = `gateway-host`；网关名套 CDN 且 CDN 回源要验源站证书时，另按 §3.1 配公网证书；
   - 返回：两张证书、`root-ca.pem`、`node-ca.pem`（节点客户端 CA）、主控内部 gRPC 地址+ServerName、Redis/NATS 的 URL（1.0.35 含共享网关账号，§3.3）。
   - 身份（实现取舍）：nodeidentity 的会话与网络清单按 workload 绑定（`session_facts.go:96`），每网关 SAN 直传会让节点无法在网关间切换。所以 ControlInternal 认证后向下游统一传网关服务类身份 `spiffe://cdn-platform/gateway/control`，具体是哪台网关由 `gateway_instance_id` 区分；绑定网关的 `gateway_instance_id` 强制等于证书里的 `gateway_id`。
   - 网关程序包：网关机不从授权端下载（授权端按主控 IP 放行，网关机未登记），而是从主控 `/downloads/agent-gateway/` 拉；主控安装时用 root CA 私钥签 `manifest.json`（版本+SHA-256），网关安装器用第 3 步按指纹钉住的 root CA 验签与哈希。
5. 网关启动、连主控、通过健康检查后调一次 `ReportGatewayReady`（新 ControlInternal RPC），主控把网关状态从"待绑定"改为"在线"。令牌作废。

网关证书续签：网关自己用 mTLS 调 `RenewGatewayCertificate`（新 RPC），客户端证书 30 天、过半续签；服务端证书 90 天、过半续签。网关被删除/停用时主控吊销其客户端证书序列号（`ControlInternal` 拦截器按吊销表拒绝），并把它移出来源地址白名单（ControlInternal 远端监听与 nftables 同源）。

### 3.3 网关↔主控链路

| 链路 | 端口（主控侧） | 认证 | 说明 |
|---|---|---|---|
| ControlInternal gRPC | 9446/TCP（9445 是升级源） | mTLS，客户端证书 URI SAN 前缀 `spiffe://cdn-platform/gateway/` | 新监听 `CDNCA_CONTROL_INTERNAL_REMOTE_ADDR`；`all` 模式的同机网关继续用 127.0.0.1:9091 不变。`--mode control` 时主控内部服务端证书补签管理端域名（三条链路共用） |
| NATS（命令/心跳/遥测） | 4223/TCP，websocket（wss） | TLS 校验网关客户端证书 + 共享网关用户 `cdnca-gateway`（只允许 websocket 连接类型），发布/订阅限 `cdnca.>`/`cdnca.>`/`_INBOX.>`/`$JS.API.>`，拒删流/清流/删消费者 | 本机 4222 不变：本机进程经 `no_auth_user` 落到只允许 STANDARD 连接的 `local` 用户；远端 websocket 不带凭据会落到 `local` 并因连接类型被拒（nats-server `auth.go` 连接类型检查） |
| Redis（会话租约、隧道 nonce） | 6380/TCP，TLS | `tls-auth-clients yes`（网关客户端 CA）+ 共享 ACL 用户 `cdnca-gateway`，只允许 `~cdnca:agent-gateway*` 与 `PING/EVAL/EVALSHA/SET/GET/DEL/PEXPIRE/INCR/HGET/HSET/HINCRBY` | 本机 6379 仍只回环，`--mode control` 时 default 用户加口令（本机 `REDIS_URL` 带口令） |

账号：1.0.35 用安装器预置的**共享**网关账号（Redis ACL 用户 + NATS 用户，仅网关所需权限）；删除/停用网关靠证书吊销 + 来源 IP 白名单兜底（三条链路都要求网关客户端证书，白名单同时作用于 nftables）。**按网关单独账号留 1.0.36**：需要主控进程在绑定/删除时改写 Redis ACL 与 NATS 配置并热加载，权限与回滚设计另做。

网络位置：`all` 模式三者都在本机回环，上表不适用。独立网关优先与主控同机房/内网，上表三条链路走内网；只有跨公网时才必须 TLS + 每网关凭据 + 按 IP 放行。延迟影响：Redis 只在建连/续约（每 10s）时访问，NATS 是命令下发与心跳/遥测转发，跨城 30–50ms 只体现在命令下发延迟上，不影响网站访问（站点流量不经网关）。

为什么 Redis/NATS 放主控侧而不是网关侧：
- 命令由主控写入 JetStream（`nats_commands.go:180`），会话租约要在所有网关间全局唯一（`redis_sessions.go:98-107`），状态天然属于主控；放在某个网关上，那个网关宕机会连带所有网关失效。
- 网关因此是无状态的：任何一台网关宕机或删除，只影响连在它上面的节点重连（§5.3）。
- 代价：网关到主控之间要放行 9446/4223/6380 三个端口；防火墙只放已绑定网关的 IP：control-api 每 15s 把白名单写到 `/var/lib/cdnca-control/gateway-access/allowed-ips`（`CDNCA_GATEWAY_ACCESS_FILE`，与 ControlInternal 远端监听的来源过滤同一份数据），systemd path 单元触发 root 脚本同步到 nftables 表 `inet cdnca_gateway_access`（control-api 没有 CAP_NET_ADMIN），未绑定 IP 一律丢弃。

不选"网关反向代理 Redis/NATS 到主控一个端口"：需要自研多路复用协议，收益只是少开两个端口。

### 3.4 多网关列表管理页

主控"系统 → 网关管理"（新页面，权限码 `system.gateway.manage`）：

- 列表：名称、`gateway_id`、网关地址（`host:通道端口`，注册端口另列）、直连传输 `grpc`（网关地址本身就是直连入口）、版本、状态（待绑定/在线/离线/已停用）、当前连接节点数、最近心跳、证书到期。
- 入口：每个入口 = {连接地址, SNI/Host, 传输 `ws`|`grpc`, 优先级}（§4.5）。套 CDN 就加一个 `ws` 入口，连接地址填 CDN 域名:443（网关域名或主控域名）；不对应新网关，只是同一网关/同一组网关的另一条路径，进节点端点列表。页面提示：§3.5 的套 CDN 文案。
- 操作：添加（生成绑定令牌与命令）、停用（不再出现在节点端点列表，已连节点收到迁移命令后断开）、删除（吊销证书、删除 Redis/NATS 用户）、编辑入口（地址、传输、优先级）。端口在安装时选定（§3.5），页面只读显示；改端口走现有"网关端口迁移"（`port_transition.go`）。
- 系统设置"可信 CDN 回源 IP 段"（§4.4）也放在这一页。
- 数据：`agent_gateways`（含端口）、入口（地址、SNI/Host、传输、优先级）、`agent_gateway_binding_tokens` 表（GW-06，一个迁移，合入时编号）。
- 网关心跳：网关每 15s 写 `cdnca:agent-gateway:instance:<gateway_id>`（Redis，TTL 45s，内容含版本与连接数），主控读取展示。不另建 RPC。

节点端点列表来自这张表（§4.5、§5.2），不再只有安装时的单个 `gateway_address`。

### 3.5 网关端口选择（定为随机端口）

定：安装时在区间内**随机**分配网关两个端口，安装完成与网关管理页明确告诉用户端口号；套 CDN 时用户在 CDN 上把回源端口填这个端口即可。

- 默认：安装器在 20000–29999 内随机选两个不同且本机空闲的端口（注册、通道），避开 run_preflight 端口清单与本机已监听端口；不再固定 19443/19444（默认端口易被扫描探测）。
- 可指定：`--gateway-ports <注册>,<通道>` 手动指定，范围 1024–65535（`gateway` 模式另允许 443），校验同下。
- 可改：网关管理页提供"更换端口"，改后主控向全部节点下发新端点并保留旧端口一段宽限期（双端口并行，节点全部切换后关闭旧端口），避免节点断连。
- 为什么删掉第三版的白名单（2053/2083/2087/2096/8443 + 20000–29999）：白名单的前提是"CDN 边缘端口 = 网关端口"，所以只能挑 CDN 对外开放的端口。第四版里节点连 CDN 的 443，CDN 回源到网关端口（§4.2），回源端口各家都可自定义（§4.3），网关端口选什么与 CDN 无关，限制它已无依据。需求 11 的"给区间、不让乱指定"落成"默认随机区间 + 指定时范围校验与冲突检查"——乱填（被占用、与管理端相同、两端口相同、低于 1024、与本机原生服务端口相同）会被拒并给出推荐空闲端口对。

校验（GW-04 写进安装器，复用现有函数）：
0. 端口是 1024–65535 的整数（`gateway` 模式另允许 443），否则拒绝并给出推荐值。
1. 两个端口必须不同。
2. 不能与本机已占端口冲突：把选定端口放进 `run_preflight` 的端口清单（替换今天写死的 `19443:节点注册 19444:节点通道`，`install-control.sh:909`），由 `preflight_check_ports` 按 `ss -ltn` 判占用（`:597-608`）；`all` 模式还要不等于管理端端口 `MASTER_PORT`。
3. 管理端端口保留表（`install-control.sh:980-983`）里的 `19443|19444` 改为"本次选定的两个网关端口"。
4. `preflight_check_firewall` 的放行提示改为管理端端口 + 选定的两个网关端口（`:930`）；云安全组同样提示。
5. 写入 `CDNCA_GATEWAY_ENROLLMENT_ADDR`/`CDNCA_GATEWAY_AGENT_ADDR`（`:2291-2292`）与主控下发的网关地址（§4.5），节点不需要知道端口规则。

安装器完成提示与网关管理页统一文案（`<注册端口>` 用本次选定值替换）：

```
节点通道（网关）端口：注册 <注册端口>，通道 <通道端口>，请在防火墙/安全组放行。
不套 CDN：节点直连这两个端口，无需其他配置。
套 CDN：在 CDN 上添加网关域名，开启 WebSocket，回源协议 HTTPS，回源端口填 <注册端口>（或你设置的端口），
       不缓存、对 /agent/v1/* 关闭 WAF 挑战；然后在"网关管理"把该入口的传输改为 WebSocket，
       并把该 CDN 的回源 IP 段加入"可信 CDN 回源段"。
阿里云经典 CDN 不支持 WebSocket，不能用；百度云 CDN 须把回源超时调到 60 秒以上。
```

各家支持情况见 §4.3。

## 4. 节点通道与套 CDN

### 4.1 问题

七层 CDN 用自己的证书终结 TLS，再单独建一条连接回源。节点的 TLS 客户端证书只能到 CDN 边缘，到不了网关。今天节点身份只认"已验证 TLS 链的叶子证书"（§2.2），所以把 19444 放到 CDN 后面，节点无法认证。二次 TLS（CDN 回源时用 CDN 自己的客户端证书，例如 EdgeOne"回源双向认证"）也不行：网关看到的是 CDN 的证书；各家 CDN 也不透传终端客户端证书。

用户的两条约束合起来（原话 7/9 + 原话 10）：节点通道不经主控 nginx 中转；网关名要套 CDN 时也必须能用，而且不是"直连为主、CDN 兜底"（直连不通时 CDN 回源同样不通，原话 9）。所以网关的同一个端口要同时能被节点直连、也能被 CDN 回源，节点用哪条由主控按"网关名有没有套 CDN"下发，而不是靠失败探测。

### 4.2 默认通道：网关自己的端口，同端口承载 gRPC 直连与 WebSocket 隧道

网关进程直接监听两个端口（注册、通道，§3.5），每个端口按 ALPN 分流（PoC `sharedport.go` 在握手后分流；实现改为握手前窥 ClientHello，见 §9）：

| 握手结果 | 去向 | 身份 |
|---|---|---|
| ALPN `h2` + 已验证的节点客户端证书 | 今天的 mTLS `grpc.Server`（直连） | 叶子证书，`authenticatedNode` 不改 |
| ALPN `http/1.1` 或无 ALPN（CDN 回源、或节点拨隧道） | HTTP 处理器，两个路径（第四版：两个网关端口上都有）：`/agent/v1/tunnel` 升级前验签名令牌（§4.6），隧道内是原样 TLS 1.3 mTLS + gRPC，落到 mTLS `grpc.Server`；`/agent/v1/enroll` 不验令牌、按来源 IP 限速，隧道内落到注册 `grpc.Server` | 隧道内层叶子证书（注册路径无证书），`authenticatedNode` 不改 |
| ALPN `h2` 但没有客户端证书（注册端口除外） | 直接关闭 | — |

- 外层 TLS 用 `VerifyClientCertIfGiven`：节点直连时带证书走 gRPC；CDN 回源不带证书走隧道。直连会话的身份仍只来自已验证的叶子证书，与今天 19444 的 `RequireAndVerifyClientCert` 等价（没证书进不了 gRPC）。（实现：握手前按 ClientHello ALPN 分流，gRPC 路径仍由原 `grpc.Server` 用 `RequireAndVerifyClientCert` 握手，见 §9。）
- 注册端口：直连时是今天 19443 的注册 `grpc.Server`（不要客户端证书，ALPN `h2`）；经 CDN 时走 `/agent/v1/enroll`，隧道内是注册 `grpc.Server`。`Enroll` 与 GW-02 的 `RecoverCertificate` 都在这里；没有证书可签，不验令牌，按来源 IP（§4.4 换算后的地址）限速。注册端口上 ALPN `h2` 不要求证书，这是与通道端口唯一的区别。
- 两个隧道路径在两个端口上都提供（第四版）：CDN 的一个域名通常只配一个回源端口，按路径分到注册或通道 `grpc.Server`，所以 CDN 回源只需填一个网关端口（推荐注册端口），另一个端口只给直连用。
- 隧道内层 TLS 的 ServerName = 网关名（`gateway-host`），由节点安装时校验过的 root CA 验证（`install-node.sh:314` 拉 `/downloads/gateway-ca.pem` 并按 `--control-plane-ca-sha256` 校验）。外层 TLS：直连时就是这张 root CA 证书；套 CDN 时是 CDN 边缘证书，节点按系统根证书校验。节点外层同时信任系统根与 root CA。
- 套 CDN 的标准接法（第四版）：节点连 CDN 的 **443**（WebSocket）；CDN 上的域名可以是单独的网关域名（例如 `gw.example.com`），也可以直接用已套 CDN 的主控域名；CDN 回源地址填网关机 IP，**回源端口填网关注册端口**（安装完成时告知），回源协议 HTTPS，开启 WebSocket。CDN 边缘端口与网关端口无关，不需要挑 CDN 支持的非标端口。管理员在网关管理页为这个入口填"连接地址 `gw.example.com:443`、传输 `ws`"。
- 用主控域名做入口时：同一域名下管理页与 `/agent/v1/*` 要回源到不同端口（管理端 443、网关注册端口）。CDN 需要支持按路径设置回源端口/源站（例如 Cloudflare Origin Rules，[来源](https://developers.cloudflare.com/rules/origin-rules/)）；不支持时用单独的网关域名。主控 nginx 仍不加 `/agent/` 路径。
- 不套 CDN：节点直连网关 IP/域名的网关端口，传输 `grpc`。
- 管理端域名套不套 CDN、主控 nginx 怎么配，与节点通道无关；主控 nginx 不加任何 `/agent/` 路径。
- 公网要开的端口：管理端口（443）+ 两个网关端口。只走 CDN 时，网关端口可只对可信 CDN 回源段放行（§4.4），由管理员选择。安装器预检与完成提示里列出（§3.5）。

为什么同一个端口而不是"gRPC 一个端口、隧道再一个端口"：用户要求只开网关两个端口；CDN 回源落到节点也能直连的同一端口，管理员不需要按"套不套 CDN"开不同的端口。代价是网关多一层 ALPN 分流（几十行，PoC 已实现）。PoC s9a 用的是边缘 8443 回源 8443；"边缘 443、回源 19443"未单独跑，但边缘端口只影响节点拨号地址，网关收到的回源请求与之无关（§4.7）。

为什么不用"gRPC 经 CDN + 签名头"（第一版的 A 模式）：EdgeOne 明确不支持双向流（§4.3），`Connect`、`StreamTelemetry` 都是双向流；阿里云经典 CDN 也不支持 gRPC。隧道已覆盖所有支持 WebSocket 的 CDN，再维护一套签名头身份分支只多出一个认证入口。PoC s2/s0/s4/s5 保留作为取舍依据。

WebSocket 隧道与 gRPC 签名头的开销对比（用户问题①）：两者都是长连接，稳定后每条消息的延迟相同（都是一次 CDN 中转）；隧道多一次内层 TLS 1.3 握手（建连时约 1 个往返）和每帧 2–14 字节 WebSocket 头 + 约 22 字节 TLS 记录开销，CPU 多一层 AES-GCM。心跳 15s 一条、遥测按批上报，额外开销可以忽略；制品下载多一层加解密，GW-03 验收时实测吞吐。PoC 只验证功能，未测吞吐。

### 4.3 主流 CDN 的支持（2026-10 查官方文档）

| CDN | gRPC | 双向流 | WebSocket | 空闲/读超时 | 来源 |
|---|---|---|---|---|---|
| Cloudflare | 支持（全套餐，需开开关，源站须 443+TLS+ALPN h2） | 官方文档未列；博客写"需要支持双向请求/响应"并按此实现 | 全套餐支持 | 回源读超时 125s（524，仅企业版可调）；HTTP/2 回源空闲 900s；客户端侧 HTTP/2 空闲 400s；发布新代码时会重启并断开长连接 | [gRPC](https://developers.cloudflare.com/network/grpc-connections/)、[连接限制](https://developers.cloudflare.com/fundamentals/reference/connection-limits/)、[WebSockets](https://developers.cloudflare.com/network/websockets/)、[博客](https://blog.cloudflare.com/road-to-grpc/) |
| 腾讯云 EdgeOne | 支持（默认关，需 HTTP/2 访问+HTTP/2 回源） | **只支持简单 RPC 与服务端流**，不支持客户端流与双向流 | 支持 | WebSocket 最大超时 300s | [gRPC](https://cloud.tencent.com/document/product/1552/85320)、[WebSocket](https://www.edgeone.ai/document/46971) |
| 阿里云 ESA | 支持（源站须 TLS+HTTP/2，回源协议 HTTPS 或跟随） | 文档只泛述 gRPC"单向与双向流"，未明确 | 支持（免费版不支持） | 文档未给 gRPC 超时 | [网络优化](https://help.aliyun.com/en/edge-security-acceleration/esa/user-guide/network-optimization) |
| 阿里云 DCDN | 未见 gRPC 文档 | — | 支持（单独计费，HTTP/2 与 WebSocket 不能同开） | WebSocket 默认 60s 空闲 | [DCDN WebSocket](https://help.aliyun.com/en/edge-security-acceleration/dcdn/configure-websocket) |
| 阿里云 CDN（经典） | 不支持 | — | **不支持** | — | [FAQ](https://help.aliyun.com/en/cdn/user-guide/faq-about-domain-name-management) |

套 CDN 的条件（第四版：节点连 CDN 的 443，所以只看"支持 WebSocket"与"能自定义回源端口"两项；2026-10-21 查官方文档）：

| CDN | 支持 WebSocket | 支持自定义回源端口 | 注意 | 来源 |
|---|---|---|---|---|
| Cloudflare | 是，全套餐 | 是：默认与访问端口相同，Origin Rules 改目标端口（全套餐），也可按路径改 | 空闲会断、发布新代码会断；China Network 只有 80/443 访问端口（不影响本方案） | [WebSockets](https://developers.cloudflare.com/network/websockets/)、[Origin Rules](https://developers.cloudflare.com/rules/origin-rules/)、[网络端口](https://developers.cloudflare.com/fundamentals/reference/network-ports/) |
| 腾讯云 EdgeOne | 是，最大超时 300s | 是：回源端口可指定，默认 HTTPS 443（文档未写范围） | — | [WebSocket](https://www.edgeone.ai/document/46971)、[回源配置](https://cloud.tencent.com/document/product/1552/90433) |
| 腾讯云 CDN | 未在本次核对的页面中出现，接入前确认 | 是：自有源站支持 0–65535 端口（IGTM 源只能 80/443） | — | [源站配置](https://cloud.tencent.com/document/product/228/41334) |
| 阿里云 ESA | 是（免费版不支持） | 是：默认 HTTPS 回源 443，在 Origin Rules 设 HTTPS 端口为网关端口 | 不设会回源到 443 | [网络优化](https://help.aliyun.com/en/edge-security-acceleration/esa/user-guide/network-optimization)、[非标准端口](https://help.aliyun.com/en/edge-security-acceleration/esa/support/non-standard-ports-are-inaccessible) |
| 阿里云 DCDN | 是：须开动态加速、关 HTTP/2、单独计费，默认空闲 60s | 文档写 WebSocket 在 HTTPS 模式下源站须支持 443，**自定义端口未核实**，接入前向阿里云确认 | — | [DCDN WebSocket](https://help.aliyun.com/en/edge-security-acceleration/dcdn/configure-websocket) |
| 阿里云 CDN（经典） | **否** | 回源端口可设（官方页未抓到） | 不能用 | [FAQ](https://help.aliyun.com/en/cdn/user-guide/faq-about-domain-name-management)、[DCDN WebSocket](https://help.aliyun.com/en/edge-security-acceleration/dcdn/configure-websocket)（"CDN does not support the WebSocket protocol, but DCDN does"） |
| 华为云 CDN | 仅业务类型"全站加速"（公测） | 源站端口可自助配置（PDF 文档所述，**未逐项核实**） | — | [CDN 常见问题 PDF](https://support.huaweicloud.com/cdn_faq/cdn-faq-pdf.pdf) 第 1.4、2.18、4.1 节 |
| 百度智能云 CDN | 是：须开动态加速；**默认 10 秒断联**，须调大回源超时；动静态加速已不再支持新增，新接入用 DRCDN | 是：源站可写 `IP:端口`（例如 `1.2.3.9:8080`） | 回源超时调到 ≥ 60s | [动态加速配置](https://cloud.baidu.com/doc/CDN/s/mlujn974h)、[配置类 FAQ](https://cloud.baidu.com/doc/CDN/s/6jwvyfd8c)、[源站配置](https://cloud.baidu.com/doc/CDN/s/jk0dt4qwv) |

结论：

1. 节点连 CDN 的 443，各家都开放 443，第三版"挑 CDN 支持的非标端口"的问题不再存在；网关端口不必在 CDN 对外端口里选（§3.5 删除白名单的依据）。
2. 能用的条件只有两项：CDN 支持 WebSocket、能把回源端口设成网关端口。Cloudflare、EdgeOne、阿里云 ESA、百度云两项都有官方依据；腾讯云 CDN 的 WebSocket、阿里云 DCDN 的自定义回源端口、华为云未逐项核实，runbook 标"接入前向厂商确认"。
3. 阿里云经典 CDN 不支持 WebSocket，不能用。
4. 空闲超时：百度云默认 10 秒，低于节点心跳 15 秒（`config.go:85`），必须按其文档调大回源超时到 ≥ 60 秒，否则会像 PoC s4 一样被周期性掐断；其余已知最短是 DCDN 60 秒。CDN 发布时也会断开长连接，断开后节点按 250ms→30s 退避重连（`gatewayclient/config.go:72-73`）。
5. 安装器与网关管理页的提示统一为 §3.5 的文案，附本表链接（GW-13 runbook）。

### 4.4 节点真实 IP

需要真实 IP 的地方只有一处：网络清单确认（候选地址必须等于网关看到的对端地址，`network_inventory.go:120-122`），确认后的地址会进 DNS 记录，所以来源必须可信。经 CDN 后 TCP 对端是 CDN 回源 IP，今天会全部 `peer_mismatch`。

新规则（删除第一版"节点必须偶尔直连"）：

1. **可信回源段**：系统设置"可信 CDN 回源 IP 段"（网关管理页，§3.4），管理员可增删。默认**只预置 Cloudflare**（官方公开列表 `https://www.cloudflare.com/ips-v4`、`ips-v6`，绑定 `CF-Connecting-IP`，随版本发布数据文件，含来源 URL 与抓取日期，可定时刷新）。其他 CDN（EdgeOne、阿里云、百度、华为等，回源段多按账号在控制台/API 提供）由管理员在页面粘贴或填官方列表 URL 定时刷新，避免预置过期地址把伪造头放进来。页面提示："只预置了 Cloudflare；用其他 CDN 时请添加该 CDN 的回源 IP 段，否则节点真实 IP 会显示为 CDN 地址"。
2. **取头规则**（网关进程自己实现，三种模式相同；没有 nginx 参与）：每个可信段绑定一个头名——Cloudflare 段绑 `CF-Connecting-IP`，其他 CDN 默认绑 `X-Forwarded-For`（管理员可改，例如 `True-Client-IP`）。只有隧道升级请求的 TCP 对端落在可信段内时才读该段绑定的那一个头；`X-Forwarded-For` 从右往左跳过可信段，取第一个不可信地址，遇到无法解析的一跳就停并退回 TCP 对端。对端不在可信段内时一律用 TCP 对端，客户端自带的头全部忽略。直连 gRPC 会话不读任何头，用 TCP 对端。PoC `realip.go` 是这条规则的参考实现，`realip_test.go` 7 个用例。
3. **节点自报**：网络清单仍由节点上报默认出口网卡地址（`types.proto:237-242`，现有字段）。网关在 `GatewayHello` 里新增"我看到的你的地址"字段，节点网卡是私网地址（云厂商 NAT）时用它作候选再上报，主控再与网关看到的地址比对一次。不依赖第三方回显服务。
4. **判定**：网关把换算后的地址作为 `PeerIp` 传给主控，并新增 `peer_ip_source`（`tcp` / `trusted_proxy`）；主控比对规则不变（`network_inventory.go:120`）。CDN 没带头、对端不在可信段 → 对端是 CDN IP，结果仍是 `peer_mismatch`，节点页提示"请把该 CDN 回源段加入可信列表"，管理员也可以手动确认（现有功能）。

PoC s8b/s9a 验证了这条规则：节点在升级请求里伪造 `X-Forwarded-For: 203.0.113.9`，直连网关端口时 `real_ip` 是 TCP 对端（`source=tcp`），经 CDN 时 `real_ip` 是 CDN 追加的节点地址（`source=trusted_proxy`），伪造值都没被采信（§4.7）。

### 4.5 多端点与兜底

节点配置 `gateway` 从单端点改为有序列表，安装时由主控 `node-install-defaults` 下发（节点只填 `--control-plane`）：

```json
"gateway": {
  "root_ca_file": "...",
  "endpoints": [
    {"address": "gw.example.com:443",    "server_name": "gw.example.com",  "transport": "ws"},
    {"address": "203.0.113.10:19444",    "server_name": "gw.example.com",  "transport": "grpc", "enrollment_address": "203.0.113.10:19443"}
  ]
}
```

- 每个端点 = {连接地址, SNI/Host, 传输 `ws`|`grpc`}（第四版）：`ws` 端点是 CDN 入口（CDN 的 443，网关域名或主控域名），注册与通道都走同一地址的 `/agent/v1/enroll`、`/agent/v1/tunnel`，不需要 `enrollment_address`；`grpc` 端点是直连（IP 或不套 CDN 的域名 + 网关端口），注册走 `enrollment_address`。`server_name` 同时用作外层 SNI/Host 与内层 TLS ServerName（内层固定为网关名，外层是 CDN 域名时另给 `host` 字段）。可配多个，按健康切换（下文）。
- 来源：主控"网关管理"页（§3.4）的在线网关 + 管理员加的额外入口地址。`node-install-defaults` 新键 `gateway_endpoints_json` 取代今天的单值 `gateway_address`/`gateway_enrollment_address`（`install-control.sh:1891-1918`），`all` 模式缺省就是本机网关一项（`GATEWAY_HOST` + 选定端口，传输 `grpc`）。运行中由网关在 `GatewayHello` 下发最新列表与版本号（新字段，节点持久化）。今天的单端点 `port_transition` 状态文件（`port_transition.go:31-60`）并入同一个端点状态存储。
- `grpc` 端点失败时再在同一地址同一端口试一次 `ws`（网关端口同时接受两种传输，PoC `endpointsFromControl`）；`ws` 端点在 CDN 443 上不试 `grpc`（CDN 不转发节点客户端证书，§4.1）。传输配错只多一次失败，不会断线（PoC s9b）。
- 切换：按列表顺序尝试；一次失败（拨号失败、升级被拒、心跳 ack 超过 `OfflineAfter`）就换下一个，列表轮转，退避沿用 250ms→30s；连上的不是第一个时，每 5 分钟后台探测一次更靠前的端点，能握手就在下一次会话结束时切回（不主动打断健康会话）。
- 第一版的"制品直连优先"删除：制品、站点对象和其他 RPC 都走当前会话所在的网关地址。
- 只有一个网关地址且它套了 CDN 时，CDN 整体故障就等它恢复，期间影响同 §6.3（站点照常服务）；要兜底就为同一网关再加一个不套 CDN 的入口地址（例如另一个只解析到网关机的域名），或再加一台网关。

### 4.6 隧道升级门禁：签名令牌

升级前先验签，防止陌生人占用网关隧道资源（内层 mTLS 才是身份，令牌只是门禁）：

```
Cdnca-Node-Cert: base64(DER 节点叶子证书)
Cdnca-Node-Auth: v1.<iat 秒>.<nonce 16 字节 hex>.<base64 Ed25519 签名>
签名原文 = "cdnca-gw-auth-v1\n" + audience + "\n" + "/agent/v1/tunnel" + "\n" + node_id + "\n" + serial_hex + "\n" + iat + "\n" + nonce
```

- 私钥：节点现有 `client-key.pem`（Ed25519，`enrollment.go:46`），不新增密钥。
- `audience` = 主控 `INSTALLATION_ID`（同一安装的所有网关共用：CDN 可能把同一网关名负载到多台网关）；跨网关重放由共享 Redis 的 nonce 去重挡住（`SET NX PX 120000`）。
- 网关校验：证书链到节点 CA、`clientAuth` 用途、唯一 SPIFFE URI SAN（与 `identity.go:49-65` 同一函数）、签名、`|now-iat| ≤ 60s`、nonce 未见过。证书已过期的节点走注册端口的 `RecoverCertificate`（§6.1），不走通道端口。
- 注册端口上的隧道没有证书可签，不验令牌，改为按来源 IP（§4.4 换算后的地址）限速。

### 4.7 PoC 结果

`tests/gateway-cdn-poc/`：真实 `agent.v1` 的 `Connect`、`StreamTelemetry` 双向流（hello、心跳/ack、下发一条部署命令、状态回执、3 批遥测/ack），OpenResty 1.27.1.2 容器扮演 CDN。经 `tests/gateway-cdn-poc/run.sh` 执行，约 6 分钟，exit 0，结果原文：

| 场景 | 链路 | 结果 |
|---|---|---|
| s8a（第三版默认形态） | 节点只配主控地址，从 `node-install-defaults` 读到 `[::1]:8443`、首选 `grpc` → 直连网关单端口 8443，ALPN h2 + 客户端证书 | `endpoints from https://127.0.0.1:18460: mtls=[::1]:8443,tunnel=[::1]:8443`；30s 会话：心跳 ack 6、命令 1、遥测 ack 3 |
| s8b | 同一端口 8443 走 WebSocket 隧道（直连），伪造 `X-Forwarded-For: 203.0.113.9` | 30s 会话同上；`real_ip=::1 source=tcp`，伪造值未采信 |
| s8c | 同一端口 8443，h2 不带客户端证书 | 网关 `reject shared port: h2 without node certificate`，节点 `error reading server preface: EOF` |
| s9a（默认形态套 CDN） | 节点读到 `127.0.0.1:18453`、首选 `tunnel` → CDN（网关同名、CDN 自己的边缘证书，边缘 8443）→ 按同一端口 8443 回源网关 → 隧道内 mTLS；伪造 XFF | 30s 会话：心跳 ack 6、命令 1、遥测 ack 3；`real_ip=172.17.0.1 source=trusted_proxy`（XFF 链 `203.0.113.9, 172.17.0.1`，从右取第一个不可信地址），伪造值未采信 |
| s9b | 同 s9a 但首选配错成 `grpc` | 第一次 `tls: no application protocol`（CDN 边缘不说 h2）10.0s 失败，同地址换 `tunnel` 后建立会话 |
| s3 | 节点 → CDN(WebSocket) → 网关独立 HTTPS 隧道端口（第一版形态） | 全通，同上 |
| s1 | 节点 → 网关 19444 直连 mTLS | 全通，同上 |
| s2 | 节点 → CDN(gRPC, h2) → 网关，签名头（已删除的方案，留作依据） | 全通 |
| s0 | 经 CDN gRPC 不带签名头 | 全部 `Unauthenticated: signed node headers required` |
| s4 | CDN 读/空闲超时 8s，心跳 15s | 每 8.0s 被 `RST_STREAM INTERNAL_ERROR` 断开，反复重连 |
| s5 | 同 s4 的 CDN，心跳 5s | 30s 会话不断 |
| s6 | 端点 [CDN gRPC, 网关 B 直连]，12s 时 CDN 黑洞（`docker pause`） | 心跳 ack 超时（3×心跳）后切到网关 B，**事件→新会话建立 19.0s** |
| s7 | 端点 [CDN WebSocket, 网关 B 直连]，10s 时杀网关 A | WebSocket 1006 立即断开，**1.2s** 切到网关 B |

说明：
- 单机 PoC 里网关占了宿主 8443，CDN 容器的边缘 8443 只能映射到宿主 18453；容器内是 `listen 8443` + `proxy_pass https://host.docker.internal:8443`，即"边缘端口 = 回源端口"。
- Docker Desktop 下容器访问宿主时宿主看到的对端是 127.0.0.1（已实测），所以可信段配 `127.0.0.1/32=X-Forwarded-For`；直连节点改用 `[::1]` 拨号，保证它不在可信段内。172.17.0.1 是 CDN 容器看到的节点地址。
- s9b 的 10s 来自 PoC 的拨号超时；生产按 `HandshakeTimeout`。`tls: no application protocol` 是 OpenResty 未开 h2 时的表现，各家 CDN 在 gRPC 未开时的具体错误可能不同（例如返回 HTTP/1.1），节点只看"失败即换传输"，不依赖错误文本。
- 单测：`auth_test.go` 覆盖重放、跨方法、跨 audience、过期令牌、篡改签名、他 CA 证书、过期证书 7 种拒绝；`realip_test.go` 覆盖 §4.4 规则 7 例。

取舍与未覆盖：PoC 网关是精简版（不连主控、不用 Redis/NATS），只验证传输、分流与身份；PoC 只演示了通道端口，注册端口同一机制（区别只是 h2 不要求证书）未单独做；没连真实公网 CDN（约束不允许），各家 CDN 的端口与超时来自官方文档（§4.3）；未测吞吐。第二版的"主控 nginx 443 同域名"用例已删除。

### 4.8 连带改动与 CDN 配置要点

- **网关按来源 IP 的限制**：经 CDN 后所有节点都从少数回源 IP 来，网关现有按来源 IP 的限制（若有）改为按 §4.4 换算后的地址或节点 ID。
- **带宽与费用**：网关名套 CDN 时，制品下载（`FetchArtifact`，最大 128MiB，`install-node.sh:2253`）与站点对象都经 CDN 回源，按 CDN 流量计费，由管理员自选：接受 CDN 流量费，或为同一网关加一个不套 CDN 的入口地址排在前面。制品端到端 HPKE 加密（`hpke.go:15-25`），CDN 看不到内容。
- **CDN 侧配置**写进 runbook（GW-13）：网关域名（或主控域名的 `/agent/v1/*` 路径）开代理、节点连 443、回源地址填网关机、**回源端口填网关注册端口**（阿里云 ESA 须在 Origin Rules 设，§4.3）、回源 HTTPS、`/agent/v1/*` 开 WebSocket、不缓存、关 WAF 对该路径的 body 检测与挑战（JS 挑战会让 agent 升级失败）、空闲超时 ≥ 60s（百度云默认 10s 必须改）；把该 CDN 的回源段加入可信列表。
- **健康检查**：主控页面对每个网关地址做两次自检——直连 gRPC 握手、经公网拨 `/agent/v1/tunnel` 升级（期望 401 未授权而不是 400/404/超时），与该入口配置的传输对照，能提前发现 CDN 没开 WebSocket、端口不支持或被 WAF 拦，并提示"配置的传输与实际不符"。

## 5. 多网关冗余

### 5.1 模型

N 个网关同时在线（主动-主动），共享主控侧的 Redis 与 NATS，每个网关独立连主控 ControlInternal。节点任意时刻只连一个网关（一个 `Connect` 会话 + 一个 `StreamTelemetry` 会话）。

| 状态 | 归属 | 多网关下的行为 | 依据 |
|---|---|---|---|
| 节点会话归属 | Redis `cdnca:agent-gateway:<node>:state`，epoch 单调递增 | 节点换到网关 B 时，B 的 `Acquire` 等旧租约 `inflight==0` 后 `INCR` epoch 接管；A 上的旧会话续约失败即 `Superseded`，被围栏，不会再发命令 | `redis_sessions.go:98-107,150-205,315-335` |
| 待发命令 | JetStream durable 消费者，每节点一个 | 只有持有租约的会话去拉；A 已拉未 ack 的消息 2 分钟（`AckWait`）后重投，B 会拿到 | `nats_commands.go:89,180-215` |
| 防重放窗口 | 网关进程内，每会话 | 新会话新窗口；消息 ID 跨会话去重由主控侧回执（event_id）负责 | `replay.go:21` |
| 授权快照 | 每会话从主控拉 | 与网关无关 | `gateway.go:961` |
| 隧道升级令牌 nonce | 新增，放 Redis | 跨网关去重 | §4.6 |
| `GatewayInstanceID` | 今天取 `INSTALLATION_ID` | 改为 `gateway_id`，否则多网关同 ID，主控侧按网关区分的记录会串 | `install-control.sh:2288` |

### 5.2 网关列表下发与节点迁移

- 节点端点列表（§4.5）由主控按"网关管理"表生成，网关在 `GatewayHello` 中带列表版本号与列表；节点发现版本更新即持久化。
- 冗余有两种接法，可混用：①多个网关共用一个网关名（CDN 或 DNS/负载均衡分到任一台，节点端点列表只有一项；各网关的服务端证书都签这个名字）；②每个网关一个名字，节点按列表切换。①依赖 CDN/负载均衡的健康检查速度，②由节点自己判定（§5.3）。
- 停用网关：主控把该网关标为"停用"→ 网关从 Redis 实例键读到停用状态后，向已连节点发 `GatewayPortTransitionCommand` 风格的"端点迁移"命令（复用 `port_transition.go` 的探测-切换流程，目标是列表里下一个网关），节点探测成功后主动断开重连；30 分钟后仍未迁走的节点由网关直接断开。
- 网关滚动升级：同上，先停用→等连接数归零→升级→启用。

### 5.3 网关下线时的节点迁移时长

| 故障方式 | 节点感知 | 迁移时长（估算/实测） |
|---|---|---|
| 网关进程崩溃或被杀、机器重启（TCP RST/FIN） | `Recv` 立即报错（经 CDN 时 CDN 关闭 WebSocket） | 实测 0.6s（PoC s7）；B 侧 `Acquire` 在旧租约 `inflight==0` 时直接覆盖接管（脚本不等旧键过期，`redis_sessions.go:98-107`） |
| 网关机器断网/黑洞（无 RST） | 心跳 ack 超过 `OfflineAfter`（生产 45s，PoC 用 15s） | 生产约 45s + 拨号下一个端点 ≤ 10s（`HandshakeTimeout`）≈ **55s**；PoC s6 实测 18.4s（心跳 5s） |
| CDN 整体故障 | 同上 | 有第二个入口地址（另一家 CDN，或不套 CDN 直连网关端口的名字）时同上；只有一个套 CDN 的地址时等 CDN 恢复，站点照常服务（§6.3） |
| 计划停用 | 端点迁移命令 | 秒级，节点先连上新网关再断旧会话 |

旧租约的最坏情况：接管脚本只看 `inflight`，不看旧租约是否过期（`redis_sessions.go:98-107`），所以通常 B 立即接管、A 上的旧会话在下次续约（≤10s）时发现 token 已变而自行围栏。只有 A 黑洞时恰好有一次发送在途（`inflight>0` 且 A 永远不会 `endSend`），B 才要等旧键 45s 过期；B 的 `Acquire` 单次最多等 10s（`AcquireTimeout`，`runtime.go:144`），节点会重试，最坏约 45s（节点判定）+45s（键过期）≈ 90s。是否把 `LeaseTTL` 降到 30s 由 GW-11 实测决定。

主控侧的节点在线状态在迁移期间可能短暂显示离线（离线判定 45s，`nodepresence/inventory.go:93`），不会触发 DNS 摘除：DNS 摘除依据的是外部探测和监测报告（§6.3），不是心跳会话。

### 5.4 需要补的测试

现在只有单协调器的 Redis 集成测试（`redis_sessions_integration_test.go:24`）。GW-11 要补两个网关进程共享真实 Redis+NATS 的集成测试：节点在 A、B 之间切换时命令不丢不重、旧会话被围栏、遥测 ack 游标连续。

## 6. 控制面故障时的节点韧性

### 6.1 缺陷：节点证书 24 小时过期后需人工重新注册

链条（均已核对）：

1. 证书 24h，节点过半（12h）开始续签（`nodeidentity/service.go:32`；`enrollment/renewal.go:101`）。
2. 续签只能走 mTLS 通道 `RenewCertificate`（`registration.go:35`；`gateway.go:324-352`），主控或网关不可用时续不上。
3. 24h 到期后 TLS 握手被网关拒绝（`tls.go:36`），续签通道本身也没了。
4. agent 重启时 `LoadIdentity` 校验 `NotAfter`，过期直接返回"load enrollment identity"，进程起不来（`cmd/edge-agent/config.go:269-273`；`enrollment.go:649`）。
5. 主控允许过期节点重新注册（`store.go:370-385`），但要人工生成 `re_enrollment` 令牌并在节点上执行（`reenrollment_expired_integration_test.go`）。

修法（两部分，一起做）：

**a. 证书 TTL 拉长到 30 天，过半续签。** 主控 `CertificateTTL` 改 30 天、`RenewBefore` 15 天，校验上限从 7 天放宽到 31 天（`validate.go:327`）。节点 CA 有效期 10 年（`install-control.sh:1200` 的 `-days 3650`；节点证书不得超出 CA 窗口，`store.go:589`），无冲突。吊销不依赖证书过期：网关每次建连都按序列号向主控查授权，会话中在快照（1 分钟）过半时刷新（`gateway.go:961,1072,3884-3886`），离线 checkpoint 也按序列号吊销（`revocation_checkpoint.go`），所以拉长 TTL 不降低吊销时效。

**b. 证书过期后用原 Ed25519 私钥自助续签，不需人工。** 新增 `RecoverCertificate`（放在注册 `grpc.Server`，不要求客户端证书；与 `Enroll` 同在网关注册端口，直连或经同端口隧道均可，§4.2）：

- 请求：`node_id`、过期证书 DER、新 CSR（必须是**同一把公钥**，不允许换钥）、`iat`、nonce，整体用旧私钥签名。
- 主控校验：证书由本安装的节点 CA 签发、序列号是该节点最近一张 `current/overlap` 证书、未吊销、节点未停用/删除、签名有效、`|now-iat| ≤ 5min`、nonce 未用过；过期不超过 **恢复窗口（默认 180 天）**。超过窗口或证书被吊销 → 拒绝，仍需人工重新注册。
- 通过后签发新证书（30 天），记 `node_certificate_events` 事件 `recovered`，管理端节点详情显示"证书过期自动恢复"并发通知（进通知中心）。
- 节点侧：`LoadIdentity` 增加 `AllowExpired` 模式——证书过期但私钥与证书匹配、链有效时允许启动，agent 进入"恢复模式"：只尝试 `RecoverCertificate`（退避 30s→10min），成功后正常连接；OpenResty 不受影响。
- 安全考量：恢复等价于"持有节点私钥即可续签"，与正常续签（持有私钥+未过期证书）的信任前提相同；限制同一把公钥，因此窃取者拿不到比私钥本身更多的东西。私钥泄露的处置仍是吊销该序列号（吊销后不可恢复）。

修后：主控/网关连续不可用 ≤ 30 天，节点证书仍有效、自动续签；30 天～180 天，节点恢复后自动自助续签；超过 180 天才需人工。

### 6.2 主控/网关不可用时节点能撑多久

前提：OpenResty 是独立 systemd 单元（`install-node.sh:32,2244`），已加载的站点配置、证书、WAF/CC 规则、动态路由对象都在节点本地，与控制面连接无关。

| 时长（从控制面不可用起） | 节点状态 | 依据 |
|---|---|---|
| 0–45s | 无感；会话断开后 agent 按 250ms→30s 退避重连 | `gatewayclient/config.go:72-73` |
| 2 分钟 | 302 调度表停止重定向（直接本节点服务） | `sched302.go:70-72` |
| 24 小时 | 遥测 spool 达软龄上限，开始背压（新事件写不进，旧事件保留） | `config.go:246`；`eventspool/spool.go:423-426` |
| 7 天 | 遥测 spool 硬龄上限，拒收新事件（告警 `SPOOL_AGE_HARD_WATERMARK`） | `spool.go:398-400` |
| **今天：24 小时** | **节点证书过期；agent 重启后起不来；恢复需人工重新注册** | §6.1 |
| 修后：30 天 / 180 天 | 证书过期 / 自助恢复窗口结束 | §6.1 |
| 站点证书各自到期 | 主控提前 30 天续期（`acmeworker/model.go:465`），控制面挂超过约 30 天，最早到期的站点证书开始过期 | — |

### 6.3 租户受影响的功能清单

控制面（主控或全部网关）不可用期间：

| 功能 | 是否受影响 | 说明与依据 |
|---|---|---|
| 已发布站点的访问、缓存、回源、HTTPS | 不受影响 | OpenResty 本地配置（§6.2 前提） |
| WAF、CC、自动防御、内核封禁 | 不受影响 | 节点自治（`docs/adr/0010-auto-defense.md:11`）；封禁到期由 agent 本地调度删除（`firewall/kernel_bans.go:16-19`） |
| 回源故障切换（节点本地探测部分） | 不受影响 | 节点本地 |
| DNS 解析、节点摘除 | 不摘除（fail open） | 所有节点都无新监测报告时视为上报链路故障，不暂停节点（`nodeserving/monitor.go:32-34,87-89`）；主控挂了也不会改 DNS |
| 新建/修改站点、证书、规则发布 | **受影响**：不能下发 | 命令经网关下发（`nats_commands.go:180`） |
| 清缓存、预热 | **受影响** | 同上 |
| 新节点注册、节点升级 | **受影响** | `Enroll`/升级命令经网关 |
| 302 调度 | 2 分钟后退化为本节点直接服务 | `sched302.go:70-72` |
| 访问日志、统计、攻击日志、计费用量 | **延迟**，节点 spool 保留，恢复后补报；超过 7 天（硬龄）或 2GiB 的部分丢弃 | `config.go:241-246`；`spool.go:398-418` |
| 套餐流量超额停用、到期停用 | **延迟执行**（主控侧计算），恢复后按补报用量执行 | `packagetrafficenforcement/engine.go:53` |
| 跨节点联防（签名/封禁广播） | **受影响**：只在单节点内生效 | ADR 0010 §1 |
| 站点 ACME 证书续期 | 主控挂 > 30 天才会出现过期 | `acmeworker/model.go:465` |
| 节点 mTLS 证书 | 今天 24h 后有人工恢复风险；修后见 §6.1 | §6.1 |

只是部分网关不可用（还有别的网关在线）时：节点 ≤ 约 55 秒（黑洞）或秒级（进程退出）迁到其他网关，以上功能都不受影响（§5.3）。

只是某个入口（CDN/域名）不可用时：节点切到列表里下一个入口，同上；没有其他入口时等它恢复，期间影响同上表（站点照常服务）。

## 7. 任务拆分

按第三版默认重排：网关自己的端口同时承载 gRPC 与隧道（GW-03）、端口选择与下发（GW-04）、真实 IP（GW-05）是 1.0.35 的最小闭环——`all` 模式节点只填 `--control-plane` 就能直连网关，网关名套 CDN 也能用。独立网关、多网关在后。原 GW-12"可选直连加速"删除：直连就是默认。

迁移号：control-api 加载器要求连号（`database/migrate.go:239-245`），各任务本地按集成头 +1 占位、守卫写前一版，合入时统一改号。新能力号（`proto/agent/v1/types.proto`）待分配：`CAP-GW-TUNNEL`（节点支持同端口隧道）、`CAP-GW-ENDPOINTS`（多端点列表）、`CAP-GW-RECOVER`（自助恢复，gw-01 已用）。

| ID | 内容 | 依赖 | 文件范围 | 迁移 | 验收 |
|---|---|---|---|---|---|
| GW-01 | 节点证书 TTL 30 天、续签 15 天、校验上限 31 天 | — | `control-api/internal/nodeidentity/` | — | 已在 gw-01 分支实现（提交 40114e146），待合 |
| GW-02 | 过期证书自助恢复 `RecoverCertificate`，窗口 180 天、同钥约束、事件与通知；节点允许过期进入恢复模式 | GW-01 | proto、`agent-gateway` 注册监听、`nodeidentity`、`controlinternal`、`edge-agent/internal/enrollment` | 本地 429 | 已在 gw-01 分支实现 S1–S5，S6 三进程 e2e 未做；在注册端口上，经隧道的路径随 GW-03 自动可用 |
| GW-03 | **同端口双传输（核心）**：网关注册端口与通道端口都改为 TLS 握手后按 ALPN+客户端证书分流（§4.2，移植 PoC `sharedport.go`）：`h2`+证书→现有 mTLS `grpc.Server`，`http/1.1`→`/agent/v1/tunnel`（WebSocket→`chanListener`→同一 `grpc.Server`）与 `/agent/v1/enroll`（→注册 `grpc.Server`），两个路径在两个端口上都提供（CDN 只回源一个端口，§4.2），注册端口 `h2` 不要求证书；升级前验令牌（§4.6，nonce 进 Redis）；节点 `tunnel` 拨号（gorilla/websocket，`edge-agent/go.mod:16` 已有依赖），外层信任系统根+root CA；`telemetryclient`、`enrollment` 拨号同样两种传输 | — | `agent-gateway/`（新 `shared_listener.go`、`tunnel_ingress.go`）、`cmd/agent-gateway/tls.go,config.go`、`edge-agent/internal/gatewayclient/dialer.go`、`telemetryclient`、`enrollment` | — | 单测：令牌 7 种拒绝（移植 `auth_test.go`）、`h2` 无证书被关、隧道内 `authenticatedNode` 结果与直连相同；三进程 e2e：同一端口上节点直连注册+心跳+发布+拉制品，再经 OpenResty 模拟 CDN（边缘 443、回源到网关注册端口）走隧道重复一遍，含注册（等价 PoC s8/s9） |
| GW-04 | **端口选择与下发**：`--gateway-ports` 与交互菜单（§3.5 默认 20000–29999 随机两个空闲端口、指定范围 1024–65535+两端口不同+`run_preflight` 端口清单查占用+保留表+防火墙提示+套 CDN 提示文案）；`write_gateway_environment` 写选定端口；`node-install-defaults`/`runtime-config.js` 改为 `gateway_endpoints_json`（连接地址、SNI/Host、传输 `ws`\|`grpc`、直连注册地址）；节点安装只填 `--control-plane`、按列表展开两种传输 | GW-03、`CAP-GW-TUNNEL` | `scripts/install-control.sh`、`scripts/install-node.sh`、`edge-agent/cmd/edge-agent/config.go`、`tests/install-*.test.mjs` | — | 静态测试：非法端口（如 80、70000、`all` 下 443、等于管理端端口、两端口相同、被占用）全部拒绝且给出推荐值；不指定时两个端口落在 20000–29999 且本机空闲；docker e2e：`--gateway-ports 21443,21444` 安装后节点只给 `--control-plane` 上线 |
| GW-05 | **节点真实 IP**：可信 CDN 回源段设置（每段绑定头名；预置 Cloudflare 数据文件+管理员增删+URL 定时刷新）、网关隧道升级按 §4.4 取地址（移植 PoC `realip.go`）、`PeerIp`+`peer_ip_source`、`GatewayHello` 回显对端地址、节点 NAT 时用回显作候选 | GW-03 | `control-api`（设置与下发）、`agent-gateway/node_inventory.go,gateway.go`、`edge-agent` 网络清单、前端设置页 | 1 个（可信段表） | 单测移植 `realip_test.go` 7 例；e2e：经 CDN 的节点网络清单确认为 `confirmed`，伪造头无效 |
| GW-06 | 网关管理：`agent_gateways`（含端口）、入口（地址、SNI/Host、传输、优先级）、绑定令牌表；主控 API、权限码 `system.gateway.manage`；网关实例心跳键；页面"系统 → 网关管理"（含可信段、双传输自检 §4.8） | — | `control-api/internal/gatewayregistry/`（新）、`httpapi`、迁移、`apps/web`、OpenAPI | 1 个 | API 集成测试；页面 vitest；令牌只能用一次、1 小时过期、库里只存哈希 |
| GW-07 | 节点多端点：配置 `gateway.endpoints[]`、`GatewayHello` 下发列表与版本、按序切换与回切探测；`port_transition` 并入 | GW-03、GW-06、`CAP-GW-ENDPOINTS` | `edge-agent/cmd/edge-agent/config.go`、`internal/gatewayclient/{dialer,client,port_transition}.go`、`proto/agent/v1/types.proto` | — | 单测：失败即换下一个、同地址换传输、列表轮转、回切不打断健康会话；三进程 e2e：两个网关，停第一个后节点迁到第二个 |
| GW-08 | 网关绑定与凭据：`POST /api/v1/gateway-bindings/complete`、每网关 SPIFFE SAN、主控按前缀认网关、`RenewGatewayCertificate`、吊销拦截、`GatewayInstanceID=gateway_id` | GW-06 | `controlinternal/service.go`、`gatewayregistry`、`agent-gateway/cmd/agent-gateway/config.go,runtime.go`、`proto/controlinternal/v1` | 1 个 | 被吊销网关的 ControlInternal 调用被拒；`all` 模式本机网关不受影响 |
| GW-09 | 主控跨机开放：ControlInternal 新监听（端口另定，9445 已被升级源占用）、NATS TLS+每网关 nkey、Redis TLS+ACL、防火墙按网关 IP 放行（同机房/内网时可关 TLS 由管理员选） | GW-08 | `install-control.sh`（`setup_nats`/`setup_redis`/`configure_firewall`/`generate_pki`） | — | 未绑定 IP 连 4222/6379/ControlInternal 被丢弃；网关凭据只能访问自身主题与键 |
| GW-10 | 安装器三模式 `--mode all\|control\|gateway`，`gateway` 模式可选 443、公网证书、CA 指纹校验 | GW-04、GW-08、GW-09 | `install-control.sh`、`tests/install-control-*.test.mjs` | — | 静态测试三种模式步骤集合；docker 两容器 e2e：A 装 `control`、B 装 `gateway` 绑定 A，节点只填 A 的管理端地址，连 B 注册、心跳、发布 |
| GW-11 | 多网关：两网关共享 Redis/NATS 的集成测试、`LeaseTTL` 调优、停用网关→端点迁移命令 | GW-07、GW-08 | `agent-gateway/redis_sessions*.go`、`nats_commands*.go`、新集成测试 | — | 节点 A→B 命令不丢不重、旧会话被围栏、遥测游标连续；实测黑洞迁移时长写入 §5.3 |
| GW-13 | 文档：部署 runbook（三模式、端口选择 §3.5、CDN 端口对照与配置要点 §4.3/§4.8）、故障 runbook（§6.2/§6.3）、用户文档"网关与 CDN" | GW-04、GW-10 | `docs/runbooks/gateway-deployment.md`、`docs/user/*` | — | 审阅 |

建议顺序：GW-01/02（gw-01 进行中）→ **GW-03 → GW-04 → GW-05**（最小闭环）→ GW-06 → GW-07 → GW-08 → GW-09 → GW-10（独立网关）→ GW-11 → GW-13。GW-12 编号空出不复用。

## 8. 待用户定

已有结论：默认通道（网关自己的端口，同端口 gRPC+隧道）；恢复窗口 180 天、证书 30 天；Redis/NATS 放主控侧；真实 IP 用可信 CDN 转发头；制品走同一入口；套 CDN = 节点连 CDN 443、回源端口填网关端口；预置可信回源段只有 Cloudflare。第三版第 1 项"EdgeOne/华为/百度/DCDN 没有 2053 等端口"因节点改连 443 不再成立；第 2 项（预置范围）已定。剩下：

1. ~~网关端口不再给固定选项与区间~~ **已定**：安装时 20000–29999 随机两个空闲端口并告知，可指定 1024–65535；GW-04 已按此实现（§9）。
2. **腾讯云 CDN 的 WebSocket、阿里云 DCDN 的自定义回源端口、华为云**未逐项核实（§4.3）。推荐：runbook 标"接入前向厂商确认"，不在 1.0.35 前补核。是否同意？

## 9. 实现记录（gw-impl，2026-10-22）

基线 `10c7eecc1`：

| 任务 | 状态 | 提交 | 与设计的差异 |
|---|---|---|---|
| GW-03 同端口双传输 | 已实现 | `3978e9864` | 分流改为**握手前窥 ClientHello ALPN**：只报 `h2` 的 gRPC 客户端原样交给现有 `grpc.Server`（各自 TLS 策略不变，通道端口仍 `RequireAndVerifyClientCert`，h2 无证书在握手即失败），其余走 HTTP/1.1 隧道。比 PoC 的"外层 `VerifyClientCertIfGiven` 后按证书分流"少一套外层 TLS 策略。令牌 nonce 用 Redis `SET NX`；注册隧道按来源地址每分钟 30 次限速。未占能力号：传输由节点发起，兼容基线 1.0.35 |
| GW-04 端口选择 | 已实现 | `13357c02f` | `--mode` 三模式属 GW-10，未做；`gateway_endpoints_json` 未做（单端点键 + 新增 `gateway_transport`/`gateway_tunnel_host`/`gateway_endpoints` 键） |
| GW-05 真实 IP | 已实现网关与节点侧 | `d3440c75a` | 可信段暂由网关文件 `CDNCA_GATEWAY_TRUSTED_PROXIES_FILE` 配置，缺省为内置 Cloudflare 列表；管理页与主控下发待 GW-06。`peer_ip_source` 只进审计，比对规则不变 |
| GW-07 多端点 | 节点侧已实现 | `7f29a34e4` | 节点配置 `gateway.endpoints[]` + 失败换下一个/轮转/grpc 同地址补试 ws；`GatewayHello` 下发列表与回切探测待 GW-06 |
| GW-08 绑定与凭据 | 已实现 | `03d5b62fb`、`b11518721` | 见 §3.2 身份取舍；路径 `/v1/gateway-bindings/complete` |
| GW-09 跨机开放 | 已实现 | `51e81b51b` + gw-impl3 S2b | 端口 9446/4223/6380；共享网关账号（1.0.36 改每网关）；nftables 与监听白名单同源 |
| GW-10 三模式 | 已实现 | gw-impl3 S3 | `--mode gateway`：令牌指纹钉 root CA → 主控签名网关包 → `agent-gateway bind` 本机生成私钥 → systemd |
| GW-06、11、13 | 部分/未实现 | — | 待实现 |
| §5.2 停用驱逐 | 已实现 | gw-impl5 S1 | 不经 Redis 实例键：网关每 60s 拉 `GetGatewaySettings`，响应 `disabled` 即进入停用；主控对停用网关保留 32 分钟宽限（取授权/制品/设置照常，注册与就绪/续签拒绝，放行 IP 保留）。网关拒绝新会话与注册，对协商了能力 50 `GATEWAY_ENDPOINT_MIGRATION` 的会话发一次 `GatewayEndpointMigration`（当前列表，已不含自己），30 分钟后断开剩余会话。节点收到后学习列表、回避该网关并在 `HandshakeTimeout` 内按序探测其他端点，命中即重连；会话在 GatewayHello 前被拒也推进到下一端点。端点列表 grpc 项带 `enrollment_address`（独立网关注册端口）并持久化 |
