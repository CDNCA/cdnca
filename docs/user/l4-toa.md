# 四层转发：用 TOA 把客户端真实 IP 传给源站

四层转发编辑页的“回源携带客户端 IP”有三个选项：

| 选项 | 源站需要做什么 | 说明 |
| --- | --- | --- |
| 关闭 | 无 | 源站看到的是 CDN 节点的地址 |
| PROXY protocol v1 | 源站程序支持 PROXY protocol（如 nginx `listen ... proxy_protocol`、HAProxy `accept-proxy`） | 改应用配置，不改内核 |
| TOA | 源站安装 TOA 内核模块（或 eBPF 版接收端） | 应用不用改，`getpeername()`/`ss` 直接得到客户端地址 |

三者只能选一个，且都只用于 TCP。

## TOA 怎么工作

节点在发往源站的 TCP 连接里，于三次握手的 ACK 和最先几个数据段上加一个 TCP 选项：kind 254、长度 8，内容是客户端的端口（2 字节）和 IPv4 地址（4 字节），网络字节序。源站的 TOA 模块读到这个选项后，让这条连接的 `getpeername()` 返回客户端地址。

限制：

- 只传 IPv4 客户端。IPv6 客户端的连接照常转发，但不带 TOA，源站看到的是节点地址。
- 源站没装 TOA 模块时，这个选项会被内核忽略，连接不受影响，只是拿不到客户端地址。
- 节点需要 Linux 5.10 及以上内核（节点安装要求本来就满足）。节点不支持时，发布会被拒绝并列出节点，可以改用 PROXY protocol 或升级节点系统。
- 节点到源站之间如果有会剥掉未知 TCP 选项的设备（部分防火墙、负载均衡），TOA 会丢失。

## 在源站安装 TOA 接收端

我们不分发源站模块。下面是常用的开源实现，仓库许可证为 **GPL-2.0**（阿里云仓库中 `toa-ebpf` 的源文件头另标 BSD-2-Clause），请按各自仓库的说明在源站编译安装：

| 实现 | 地址 | 许可证 | 备注 |
| --- | --- | --- | --- |
| Huawei TCP_option_address | https://github.com/Huawei/TCP_option_address | GPL-2.0 | 内核模块，仅 IPv4；较老，依赖 x86 和 `kallsyms_lookup_name`，新内核可能编不过 |
| 华为云 ELB TOA | https://github.com/huaweicloud/elb-toa | GPL-2.0 | 内核模块 |
| 阿里云 CDN TOA | https://github.com/aliyun/alibabacloud-cdn-tool-toa | GPL-2.0（`toa-ebpf` 源文件头标 BSD-2-Clause） | 内核模块支持 2.6.32–5.14；eBPF 版支持 5.10+，需 cgroup v2 |
| 字节跳动 TOA | https://github.com/bytedance/toa | 仓库未声明许可证，已归档 | 内核模块，使用前自行确认授权 |

内核模块的一般步骤（以 Huawei 版为例，具体以仓库 README 为准）：

```sh
# 需要与运行内核一致的头文件
apt-get install -y build-essential linux-headers-$(uname -r)    # Debian/Ubuntu
dnf install -y gcc make kernel-devel-$(uname -r)                # RHEL/Rocky
git clone https://github.com/Huawei/TCP_option_address.git
make -C TCP_option_address/src
insmod TCP_option_address/src/toa.ko
cat /proc/net/toa_stats       # syn_recv_sock_toa 计数增长说明已收到 TOA
```

阿里云 eBPF 版（无需内核头文件，内核 5.10+，cgroup v2）：

```sh
git clone https://github.com/aliyun/alibabacloud-cdn-tool-toa.git
cd alibabacloud-cdn-tool-toa/toa-ebpf && make && sh load.sh
```

阿里云 eBPF 版默认把 kind 254 当作“IP+端口”格式解析，与节点发送的格式一致。

## 验证

1. 在四层转发里选择“TOA”并发布（目标节点需支持 TOA）。
2. 从一台客户端连接转发端口，在源站执行 `ss -tn`，或看应用日志里的对端地址，应为客户端的公网地址。
3. 没生效时，在源站抓包：`tcpdump -nn -v -i <网卡> 'tcp port <源站端口>'`，握手 ACK 的 options 里应能看到 `exp-…`（kind 254）。抓得到但地址仍是节点，说明 TOA 模块没装好；抓不到，检查节点能力和中间设备。
