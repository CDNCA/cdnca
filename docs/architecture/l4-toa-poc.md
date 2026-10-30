# L4 TOA PoC（1.0.35 G5，v6.1.0 #5）

结论：**通过**。节点四层回源时，eBPF sockops 程序在握手 ACK 和首批数据段上写入 TOA 选项（kind 254、长度 8：2 字节端口 + 4 字节 IPv4，网络序），源站侧装标准 TOA 接收端后 `getpeername()` 返回真实客户端 `IP:端口`；未挂 BPF、IPv6 客户端、未开 `proxy_toa` 的流、已建立的连接都照常转发、不带选项。

验证环境只覆盖 arm64：Docker Desktop linuxkit 内核 6.10.14（aarch64，BTF、cgroup v2、`CONFIG_CGROUP_BPF=y`），Debian 13 特权容器，clang 19 / bpftool 7.5 / libbpf 1.5。amd64 和 Ubuntu 24.04 / Debian 12 / Rocky 9 实机内核**未验证**，留给测试机（复现步骤见文末）。

## 1. 方案

```
客户端 ──> 节点 L4 OpenResty（proxy_toa on）──> 源站
                │ connect() 前 setsockopt(IPPROTO_TCP, 0x43464c54, {family, port, addr[16]})
                ▼
   cgroup/setsockopt 程序：吞掉这个私有选项（optlen=-1，不进内核），
   客户端地址写进该 socket 的 BPF_MAP_TYPE_SK_STORAGE
                ▼
   sockops 程序：ACTIVE_ESTABLISHED（收到 SYN-ACK 后）打开写头选项回调；
   HDR_OPT_LEN 预留 8 字节、WRITE_HDR_OPT 写入 254/8；
   对端已确认我方数据（bytes_acked>1）或已收到对端数据后关闭回调
```

- 关联“哪条上游连接对应哪个客户端”：规划里写的是“在 upstream socket 建好后用 fd 更新 sk_storage”。实测采用等价但更简单的做法：nginx 补丁在 `connect()` 前对上游 socket 调一次私有 `setsockopt`，由 `cgroup/setsockopt` 程序写入 sk_storage。不需要 agent 和 nginx 之间传 fd 或共享 map 句柄。
- 不用补丁的替代路线不可行：曾考虑用 `proxy_bind $remote_addr`/`cgroup/bind4` 钩子传地址，但 `bpf_setsockopt` 的 `SOL_IP` 只允许 `IP_TOS`（内核 `net/core/filter.c` v6.10 `sol_ip_sockopt`），设不了 `IP_BIND_ADDRESS_NO_PORT`，带端口的 bind 在 bind 时就占用本地端口，并发会被端口范围卡死。所以需要一个小补丁：`edge/openresty/native/patches/22-cdnca-stream-toa.patch`（新指令 `proxy_toa on|off`，改 3 个文件，默认关，`-Werror` 编译通过，已进 `sources.lock.json` 并随签名源码整链回放通过）。
- BPF 程序只用 UAPI 上下文结构（`struct bpf_sock_ops`、`struct bpf_sockopt`、`struct bpf_sock`），不读内核私有结构，所以不需要 `vmlinux.h`，也没有 CO-RE 重定位；一个小端对象同时适用 amd64/arm64，`build.sh` 可复现（同输入同 sha256，`SHA256SUMS` 固定，单测校验）。
- 挂载点：程序挂在 edge-agent 自己的 cgroup v2 上（`/proc/self/cgroup` 的 `0::` 路径）。L4 OpenResty 由 agent 直接 exec（`agents/edge-agent/internal/l4runtime/openresty.go:940`），继承该 cgroup。只有调过私有 `setsockopt` 的 socket 才有 sk_storage，其它 socket（agent 自己、站点 OpenResty 若同 cgroup）进入 sockops 后查不到存储就返回，不受影响。

## 2. 实测结果（`scripts/l4-toa-poc/run.sh`，`ORIGIN_TOA=1`）

拓扑：`cli` netns（10.10.1.2 / fd00:1::2）→ 宿主（节点，10.10.1.1:9000/9001/9002）→ `org` netns（源站 10.10.2.2:8000）。源站进程单独一个 cgroup，挂阿里云 `alibabacloud-cdn-tool-toa` 的 `toa-ebpf` 接收端（BSD-2-Clause，仅在临时目录下载编译，未进仓库）。

| # | 场景 | 结果 |
| --- | --- | --- |
| 2 | 开 `proxy_toa`，**未挂 BPF** | 转发正常；源站看到节点地址；每个 worker 记一次 `setsockopt(CDNCA_TOA) failed ... (92: Protocol not available)` |
| 3 | IPv4 客户端 → TOA 监听 | `client=10.10.1.2:49718 origin_saw=10.10.1.2:49718`（源站 `getpeername` 得到真实客户端） |
| 4 | 同节点、未开 `proxy_toa` 的监听 | `origin_saw=10.10.2.1:…`，抓包无 254 选项 |
| 5 | IPv6 客户端 → TOA 监听（IPv4 上游） | 不插选项（统计 `skip_v6_client=1`），源站看到节点地址，转发正常 |
| 6 | 4 MiB 上传 | sha256 一致；只有握手 ACK 和首批 2 个数据段带选项，之后的段不带 |
| 7 | 挂 BPF **之前**已建立的连接 | 挂载后继续收发正常，不带选项 |
| 8 | 同时开 `proxy_toa` 和 `proxy_protocol` | 两者都生效（PROXY 头 + 选项都发出）。但源站一般只认一种，所以控制面禁止同时开（§4） |

抓包（场景 3，源站侧 `tcpdump`）：

```
[S]  opts=[2, 4, 8, 3]  toa=None                  # SYN 只有 MSS/SACK/TS/WS，不占 SYN 选项空间
[A]  opts=[8, 254]      toa=10.10.1.2:35196       # 握手 ACK
[PA] opts=[8, 254]      toa=10.10.1.2:35196 len=5 # 首个数据段
[A]  opts=[8]           toa=None                  # 之后不再带
```

BPF 计数（stored, skip_v6_client, skip_v6_upstream, bad_optlen, written, no_space, done）：`3 1 0 0 7 0 3`。

### 2.1 共享端口经分发器转入（真实 OpenResty，`scripts/l4-toa-poc/run-dispatch.sh`）

完整 OpenResty 1.31.1.1（LuaJIT、stream、ssl_preread、realip，22 步补丁链）在同一 arm64 内核上运行 `l4runtime.CompileV2` 生成的运行时（`TestRenderTOADispatchRuntime` 输出）：两条 TOA 流共享 TCP 9443，一条按 SNI `toa.example` 透传 TLS、一条纯 TCP，于是走“公网分发器（ssl_preread + PROXY）→ unix socket（`set_real_ip_from unix:`）→ 各流 server（`proxy_toa on`）”。分发器本身不带 `proxy_toa`（`TestV2TOAOnADispatchedPortStaysInTheStreamServers`）。源站挂阿里 eBPF 接收端：

```
tls: client=10.10.1.2:42326 origin_saw=10.10.1.2:42326
plain: client=10.10.1.2:42330 origin_saw=10.10.1.2:42330
stats: stored 2, written 4, done 2（无 skip/no_space），error.log 无 CDNCA_TOA 告警
```

agent 侧 Go 加载器（`internal/toa`，cilium/ebpf v0.19.0）也在同一容器实测：`CDNCA_TOA_PRIVILEGED_TEST=1 toa.test` 通过——加载、挂到测试进程的 cgroup、本机回环自检写出选项、`Close` 后卸载；未打补丁的 OpenResty 在加载前就被拒绝。

## 3. 评估

- **选项空间 / MSS**：TCP 头选项最多 40 字节。上游连接带时间戳时数据段已用 12 字节（NOP NOP TS），再加 8 字节 TOA 共 20 字节，余量充足；SACK 块出现在重传期间，此时 TOA 早已关闭。选项只出现在握手 ACK 和对端确认前的少数段上，内核按预留长度自动缩小这些段的有效载荷（抓包里 TSO 合并段为 7200 字节，后续 16384），不需要改 MSS。空间不足时 `bpf_reserve_hdr_opt` 失败，计 `no_space`，连接照常（本次为 0）。
- **SYN 不写**：TOA 接收端（Huawei 模块读 `syn_recv_sock` 时的 skb，即三次握手 ACK；阿里 eBPF 版读 `PASSIVE_ESTABLISHED` 时的 ACK 和保存的 SYN）都从 ACK 取值。实测只写 ACK + 首批数据即可被读到。
- **IPv6**：第一期只支持 IPv4 客户端。IPv6 客户端（不论上游是 v4 还是 v6）不插选项，计 `skip_v6_client`；上游是 IPv6 时计 `skip_v6_upstream`。各家 IPv6 TOA 格式不统一（阿里 eBPF 版 v6 用 kind 254 长度 20，Huawei 模块不支持 v6），以后单独评估。
- **与 PROXY protocol 的关系**：互斥。出站 PROXY 会让客户端信息出现两次、源站只认其一；入站 PROXY（流量来自前置代理）时，`proxy_toa` 传的是 `c->sockaddr`；四层编译器对这种监听不写 `set_real_ip_from`（`v2_compiler.go:185-186`），`c->sockaddr` 仍是代理地址，会把代理当客户端发出去。共享端口经分发器转进来的连接（`listen unix: proxy_protocol` + `set_real_ip_from unix:`，`v2_compiler.go:175-176`）由 realip 在 post-accept 阶段改写成真实客户端，TOA 写入的是真实客户端（§2.1 实测）。控制面和节点都拒绝 `toa` 与任一方向 PROXY 同开。
- **对已有连接无影响**：挂载前建立的连接没有 sk_storage，程序直接返回（场景 7）。卸载（agent 退出、`Close`）后，新连接的私有 `setsockopt` 得到 `ENOPROTOOPT`，nginx 记一次告警继续转发（场景 2）。
- **失败降级**：内核 < 5.10、无 cgroup v2、OpenResty 未带补丁、加载/挂载失败、自检未写出选项，任何一项不满足都不声明 `L4_TOA`，主控对要求 TOA 的发布直接 422 并列出节点；节点转发本身不受影响。
- **最低内核**：sockops 头选项回调与 `bpf_reserve_hdr_opt`/`bpf_store_hdr_opt` 在 5.10 引入；`cgroup/setsockopt` 在 5.3、`BPF_MAP_TYPE_SK_STORAGE` 在 5.2。节点准入已要求 ≥5.10 + cgroup v2（`docs/install/os-support-matrix.md` §2），探测仍以“实际加载+自检”为准，不只看版本号。
- **许可证**：BPF 源码为原创，`GPL-2.0-only OR BSD-2-Clause`，对象 `license` 段为 `Dual BSD/GPL`（`agents/edge-agent/internal/toa/bpf/THIRD_PARTY.md`）。仓库不含任何第三方 TOA 代码或内核模块。

## 4. 未验证 / 遗留

- amd64 内核、Ubuntu 24.04 / Debian 12 / Rocky 9 实机内核；Huawei `TCP_option_address` 内核模块（需要源站内核头文件，linuxkit 没有对应 headers 包，本次用阿里 eBPF 接收端代替，选项格式相同：都按 kind 254、长度 8 解析）。
- 真实 OpenResty 全量构建（本次只编了 nginx 核心 + stream 模块验证补丁）；节点包里 BPF 对象随 agent 二进制嵌入，无需额外文件。

复现（测试机，root，内核 ≥5.10，cgroup v2）：

```sh
node edge/openresty/native/verify-sources.mjs openresty-1.31.1.1.tar.gz /tmp/toa/src
docker run -d --rm --privileged --name toa-poc -v /tmp/toa:/work \
  -v "$PWD/scripts/l4-toa-poc":/work/poc -v "$PWD/agents/edge-agent/internal/toa/bpf":/bpf debian:13 sleep 3600
docker exec toa-poc sh -c 'apt-get update && apt-get install -y clang llvm libbpf-dev bpftool build-essential libpcre2-dev libssl-dev zlib1g-dev tcpdump iproute2 python3'
docker exec toa-poc sh /work/poc/build-nginx.sh && docker exec toa-poc sh /work/poc/run.sh
docker rm -f toa-poc
```
