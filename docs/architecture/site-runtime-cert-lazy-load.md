# 站点 HTTPS 证书懒加载 PoC（G8-b）

状态：PoC（014b0faa）已实现为 site runtime v7（节点 a7799a99、主控 871318e1、真实 OpenResty 验收 1430fa03），实现与生产形状数据见 §6 与 million-sites-benchmark.md §8。PoC 基线 `62fe1ae4`；运行时 `cdnca-native-runtime:wafdual`（openresty/1.31.1.1，nginx 1.31.1，ngx_lua 0.10.31rc5，OpenSSL 3）。
复现：`tests/scale/cert-lazy-poc.sh`（3 站握手）、`tests/scale/cert-lazy-mem.sh [N]`（内存对比）。均为 1 个 `--rm` 容器，用完即删。

## 1. 结论

- **可行，但不能用 `ssl_certificate_by_lua`，要用 nginx 原生变量证书。** 站点 server 不写证书、只靠 default server 的 `ssl_certificate_by_lua` 必然握手失败（G8-a `nocert` 的现象），原因是 OpenResty 的 Lua 证书回调按 SNI 选中的站点 server 查 handler，而站点 server 没有 SSL 上下文、也不能挂 handler（§2）。改成 default server 写 `ssl_certificate $lazy_cert.crt` + `map $ssl_server_name $lazy_cert { hostnames; … }` + `ssl_reject_handshake on` 后，3 个 SNI（精确、精确、通配符）全部握手成功，证书链与主机名校验通过，ALPN 仍按站点给 h2，未知 SNI / 无 SNI 被拒（alert 112），证书文件原子替换后新握手拿到新证书（§4）。
- **内存**（§5，2000 站）：每个 HTTPS 站点 server 从 66.6 KiB 降到 39.9 KiB，与纯 HTTP server（39.7 KiB）相同；TLS 部分不再随站点数增长，只剩一个 SSL_CTX 加每 worker 的热证书缓存（实测约 3.8 KiB/张，`ssl_certificate_cache max=` 封顶）。全部站点握手后 cgroup 153.0 MiB → 98.6 MiB（−36%）；`nginx -t` CPU 0.32 s → 0.04 s。server{} 本身仍是每站 ≈40 KiB 线性，那部分要靠第 2 期共享 server 去掉。
- Lua 方案里唯一能握手的是“每站写同一张占位证书 + 每站挂 `ssl_certificate_by_lua`”（`luaplaceholder`），每站仍一个 SSL_CTX，只省 ≈7 KiB/server（59.7 KiB），不推荐。

## 2. 根因（代码依据，nginx 1.31.1 / ngx_lua 0.10.31rc5）

1. 站点 server 没有 `ssl_certificate` 且没有 `ssl_reject_handshake` 时不创建 SSL_CTX：`src/http/modules/ngx_http_ssl_module.c:757`。
2. SNI 回调选中站点 server 后，先把连接的配置切过去 `hc->conf_ctx = cscf->ctx`（`src/http/ngx_http_request.c:971`），但只有站点有 SSL_CTX 时才 `SSL_set_SSL_CTX`（`:981-982`）。所以握手继续用 default server 的 SSL_CTX 及其证书回调，配置却已是站点的。
3. Lua 证书回调从 `hc->conf_ctx` 取 srv_conf（`ngx_http_lua_ssl_certby.c:257`），站点 server 上没有 handler 就报 `no ssl_certificate_by_lua* defined in server a.example` 并失败（`:304-308`）。`ssl_client_hello_by_lua` 同理（`ngx_http_lua_ssl_client_helloby.c:259,310`）。
4. 想给站点 server 也挂上 handler（http 级或每站写）会在 `-t` 时报 `no ssl configured for the server`，因为合并时要求该 server 有 SSL_CTX（`ngx_http_lua_module.c:1388-1415`）。
5. 原生变量证书回调不受影响：`SSL_CTX_set_cert_cb(conf->ssl.ctx, ngx_http_ssl_certificate, conf)` 把 default server 的配置作为参数注册（`ngx_http_ssl_module.c:815`），回调里直接用这个参数（`ngx_http_request.c:1064`），`$ssl_server_name` 是连接级变量，map 在 http 级，选中哪个站点 server 都能求值。
6. `ssl_reject_handshake on` 只在 SNI 没匹配到站点（停留在 default server）时生效（`ngx_http_request.c:1021`）；匹配到的站点继承 http 级默认 off。default server 写了变量证书，`-t` 的“listen 没有证书”检查走 `certificates` 分支直接通过（`ngx_http_ssl_module.c:1449-1460`），站点 server 不用写占位证书。

## 3. 可行配置

```nginx
http {
    # key 直接用站点 server_name 的同一字符串，匹配语义与 server_name 一致（精确 > 前缀通配 > 后缀通配）
    map $ssl_server_name $lazy_cert {
        hostnames;
        default "";
        a.example    /var/lib/cdnca/certs/<version-a>;
        b.example    /var/lib/cdnca/certs/<version-b>;
        *.c.example  /var/lib/cdnca/certs/<version-c>;
        # 规模化时用 include 分片文件（每个 scope/分片一个），map 只定义一次
    }

    server {   # 每个 TLS 监听一个
        listen 443 ssl default_server;
        # listen 443 quic reuseport;
        server_name _;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_reject_handshake on;                 # 未知 SNI / 无 SNI：alert 112，与现在 certstore/compile.go:166 一致
        ssl_certificate     $lazy_cert.crt;
        ssl_certificate_key $lazy_cert.key;
        ssl_certificate_cache max=<热站上限> valid=60s;
        location / { return 421; }
    }

    server {   # 每个站点：不写任何 ssl_certificate*
        listen 443 ssl;
        http2 on;
        server_name a.example;
        ...
    }
}
```

`ssl_certificate` 变量需 nginx ≥ 1.15.9，`ssl_certificate_cache` 需 ≥ 1.27.4，当前运行时满足。站点多时 `map_hash_max_size` 要随条目数调大（PoC 用 4×N，2000 条 `-t` 0.04 s）。

## 4. 三站握手实测（`tests/scale/cert-lazy-poc.sh`）

宿主机 `openssl s_client -servername <host> -CAfile <3 张自签> -verify_hostname <host> -verify_return_error`，并发 HTTP 请求看进到哪个 server；另起一次 `-alpn h2,http/1.1` 看 ALPN。

| 形态 | `-t` | a.example / b.example / x.c.example | 未知 SNI / 无 SNI | error.log 关键行 |
|---|---|---|---|---|
| `luanocert`（G8-a nocert） | 通过 | 全部失败，alert 80 | alert 80 | `no ssl_certificate_by_lua* defined in server a.example` |
| `luahello`（再挂 client_hello_by_lua） | 通过 | 全部失败，alert 80 | alert 80 | `no ssl_client_hello_by_lua* defined in server a.example` |
| `luahttp`（http 级 certby） | `[emerg] no ssl configured for the server` | — | — | — |
| `luapersite`（每站 certby、无证书） | `[emerg] no ssl configured for the server` | — | — | — |
| `luaplaceholder`（每站占位证书 + certby） | 通过 | 成功，CN 正确，Verify 0，h2 | alert 80（Lua 返回 ERROR） | 每个未知握手记一条 `cert cb error` |
| **`nativemap`** | 通过 | **成功**，CN=a.example / b.example / *.c.example，Verify 0，h2，`site=` 与 SNI 一致 | **alert 112** | 无 error 级日志 |
| `nativemapquic`（再加 `listen 443 quic`） | 通过 | 同 nativemap（TCP） | alert 112 | 无 |

- 证书轮换：`nativemap` 下把 a.example 的 crt/key 原子 `mv` 成新证书，等 `valid=2s` 过期后新握手的 SHA-256 指纹变为新证书。依据：缓存过期后按 inode + mtime 判断是否重读（`src/event/ngx_event_openssl_cache.c:347-365`）。
- JA4：用 `cdnca-native-runtime:g2-ja4` 跑 `nativemap`，站点 server 里 `$cdnca_ja4` 仍有值（`t13d3012h1_…`）。JA4 模块把 msg_callback 挂在所有有 SSL_CTX 的 server 上（`edge/openresty/native/ja4/ngx_http_cdnca_ja4_module.c:112-122`），ClientHello 本来就在 default server 的 SSL_CTX 上收。
- 未验证：HTTP/3 真实握手（本机无 HTTP/3 客户端，只验证了 `-t`、启动和 TCP）；多 worker；reload 时缓存继承。

## 5. 内存对比（`tests/scale/cert-lazy-mem.sh 1000|2000`）

最小配置、`worker_processes 1`、P-256 自签每站一张（同一把私钥）。“空闲”在启动后 2 s 测；“全握手后”是容器内 cosocket 对全部 N 个站点各做一次 `verify=true`（链 + 主机名）握手并核对响应体之后测，三种 TLS 形态都是 N/N 成功、0 失败。每站成本 = (master RSS − empty 基线 2740 KiB) / N。

| 形态 | N | master RSS 空闲 | 每站 | worker RSS 全握手后 | cgroup 全握手后 | `-t` CPU (user+sys) |
|---|---|---|---|---|---|---|
| plain（N 个 HTTP server，对照） | 1000 | 41.5 MiB | 39.7 KiB | 42.7 MiB（空闲） | 45.4 MiB（空闲） | 0.02 s |
| tls（每站 `ssl_certificate`，现状） | 1000 | 67.8 MiB | 66.7 KiB | 73.2 MiB | 79.7 MiB | 0.17 s |
| luaplaceholder | 1000 | 61.0 MiB | 59.7 KiB | 69.8 MiB | 77.2 MiB | 0.11 s |
| **nativemap** | 1000 | **41.6 MiB** | **39.9 KiB** | 50.3 MiB | **52.4 MiB** | **0.03 s** |
| plain | 2000 | 80.2 MiB | 39.7 KiB | 81.4 MiB（空闲） | 84.2 MiB（空闲） | 0.04 s |
| tls | 2000 | 132.8 MiB | 66.6 KiB | 138.1 MiB | 153.0 MiB | 0.32 s |
| luaplaceholder | 2000 | 119.2 MiB | 59.7 KiB | 127.7 MiB | 145.1 MiB | 0.24 s |
| **nativemap** | 2000 | **80.6 MiB** | **39.9 KiB** | 92.9 MiB | **98.6 MiB** | **0.04 s** |

- nativemap 的配置内存与纯 HTTP server 相同（map 2000 条只多 ≈0.4 MiB）：每个 HTTPS 站点省 ≈27 KiB（−40%），与 G8-a 拆分出的“证书 + SSL_CTX ≈27 KiB”吻合。
- nativemap 的 worker 在全握手后多出来的是热证书缓存：1000→2000 张多 3.7 MiB 而 tls 形态的握手增量不变，约 3.8 KiB/张（X509 + EVP_PKEY），每个 worker 各一份，用 `ssl_certificate_cache max=` 封顶；不配缓存则每次握手读文件 + 解析（nginx 文档语义，未实测开销）。
- 顺序握手 2000 次墙钟 tls 1.1 s / nativemap 1.8 s（首次握手要读文件解析，含宿主机负载噪声，只说明没有数量级劣化）。

## 6. 落地（site runtime v7）

- 设计：编译器生成 map + default server 原生变量证书 + `ssl_certificate_cache max=`（可配，默认 10000）+ `ssl_reject_handshake on`；不用节点 Lua、`index.json`、LRU。产品里证书与私钥各一个 map（`$cdnca_lazy_cert_<端口>` / `$cdnca_lazy_key_<端口>`），值是共享证书池里的文件全路径（G8-c 起，见下“证书文件”）。G8-c 分片未做，map 暂内联在 http{}，分片后改为按分片 `include` 进同一个 map。
- TLS 设置：站点监听协议不是 nil / `TLSv1.2 TLSv1.3`（与端口 default server 不同）时，该站点保持逐站证书与自己的 SSL_CTX；只有一致的走懒加载，同一端口可以混用（`TestLazyCertificatesKeepNonDefaultTLSSitesOnTheirOwnCertificate`、真实 OpenResty 里 TLSv1.3-only 站点拒绝 TLSv1.2）。之后站点有完整 TLS 档案（TLS 版本区间、加密套件预设、OCSP stapling、客户端证书校验，`edgeconfig.TLSProfile`），判定在 `edgeconfig.LazyCertificateTLSProfile`：只有基线档案（协议为 nil 或 TLSv1.2+TLSv1.3、modern 套件、不 staple、不校验客户端证书）走懒加载；其余监听保留自己的证书与 SSL_CTX（OCSP stapling 与客户端 CA 只能挂在静态证书的 SSL_CTX 上）。
- 同一主机名不同端口不同证书：每个端口各自一对 map、各自的 default server（`TestLazyCertificatesMapEachPortSeparately`）；同一端口 IPv4/IPv6 对同一域名给出不同证书时按地址族拆分。
- mux 分发的套接字（同端口明文与 TLS 混用）上的监听保持逐站证书。
- 证书文件：证书库是 root 0400，worker 读不到 → 懒加载监听的证书/私钥复制进站点运行时状态根下的共享证书池 `tls-pool/<site>.<version>.crt|.key`（G8-c；原来每个派生 release 复制一份 `tls/<site>/<version>`）。池按需写一次（流式复制，按证书库记录的 sha256 校验），文件 root:worker 0440，状态根与池目录 root:worker 0710（只穿越、不可列目录）；worker 组：原生 profile 为 cdnca-runtime，容器（Agent 与 master 为 root、worker 为编译默认 nobody）为 nobody 组（没有时 nogroup），非 root 运行时 worker 即 Agent 本人、池保持私有。已存在的目录只接受目标模式或首次的 0700（升级一次），其它一律 fail closed、不修。按“正在准备的计划 ∪ 证书库 current/previous 引用”回收。私钥 worker 可读的取舍不变。证书过期或未生效的站点不进 map、不进池，其 TLS server 为 `ssl_reject_handshake on`。
- 能力与回落：主控在全部目标节点声明 site_runtime ≥ 7 且文档有 TLS 监听时才写 `lazy_certificates`（同时 required site_runtime 提到 7），否则发逐站证书形态，不报错。
- 生产形状内存（G8-a 工具，一半站点 HTTPS，2000 站）：master RSS 234.8 → 208.6 MiB，PSS 238.6 → 212.4 MiB，全部 HTTPS 握手后 PSS 275.3 → 251.9 MiB，reload 峰值 PSS 516.7 → 459.0 MiB，`-t` CPU 0.47 → 0.22 s；每个 HTTPS 站点 ≈ −26.4 KiB（详见 million-sites-benchmark.md §8.4）。
- 共享 SSL_CTX 后只作用于 SSL_CTX 的指令（`ssl_protocols`、`ssl_session_tickets`、`ssl_ciphers`、`ssl_verify_client`、`ssl_early_data`）对懒加载站点只取 default server 的值；仍按站点生效的：`http2`/`http3`（ALPN 按 `hc->conf_ctx` 选，实测 h2）、`$ssl_server_name`、`$cdnca_ja4`。
- 未做：80/443 合并为一个 server、真实 HTTP/3 握手、节点升级到 v7 后自动重新发布。证书库去 64 上限已由 G8-c（g8c-certstore）完成，见 million-sites-benchmark.md §8.3。
- 备选未做：给 ngx_lua 打补丁让 certby 在站点没有 handler 时退回 SSL_CTX 所属 server 的 handler（要长期维护补丁，原生方案已满足需求）。
