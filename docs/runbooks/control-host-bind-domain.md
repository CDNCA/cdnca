# 主控改用域名（control-api control-host bind）

适用：主控先用 IP 安装（`--master-host <IP>`），之后改用域名访问，或换一个域名。不重装、已装节点不断、业务不中断；浏览器用域名访问时使用正式证书；之后复制的节点安装命令使用域名。

页面入口：系统设置 → 系统 →「管理端地址 / 绑定域名」，输入域名后复制命令。页面不执行，命令需在主控服务器上以 root 运行。

## 1. 前提

- 域名 A/AAAA 记录已解析到主控公网 IP（绑定期间关闭 CDN 代理）。预检要求每条解析结果都是本机地址：control.env 里原控制面地址、节点升级下载地址或网卡地址。
- 申请 Let's Encrypt 证书：公网能访问本机 TCP 80，且 80 端口空闲（certbot standalone）。做不到时用 `--cert-file/--key-file` 提供证书链和私钥。
- 宝塔环境（`/etc/cdnca-native-dependencies/runtime.env` 里 `ENV=bt`）不适用：公网证书由宝塔站点负责，在宝塔「网站」中为域名开启 SSL。

## 2. 命令

```bash
CA=/data/cdnca-native-root/cdnca/current/bin/control-api
sudo $CA control-host bind --domain console.example.com                 # certbot 申请证书
sudo $CA control-host bind --domain console.example.com \
  --cert-file /path/fullchain.pem --key-file /path/privkey.pem          # 已有证书
sudo $CA control-host status                                            # 地址、证书到期与 SAN
```

可选参数：
- `--gateway-host-too=false`：新节点和网关端点列表仍用原地址（默认 true，改用域名）。
- `--email`：Let's Encrypt 账户邮箱。
- `--skip-dns-check`：跳过解析预检，只能和证书文件一起用（例如先在内网验证）。
- `CDNCA_HOST_BIND_ACME_STAGING=1`：certbot 申请测试证书（仅测试）。

命令可以重复执行。同一域名、证书未变时输出“无需改动”，不会再次申请证书。

## 3. 改了什么

| 位置 | 变化 |
|---|---|
| `/etc/cdnca-control/nginx.conf` | 在安装器生成的 server（`server_name _`）后追加带标记的同内容 server 块，`server_name <域名>`，证书用 `keys/pki/bind-public-{cert,key}.pem`。原 server 不动。 |
| `keys/pki/bind-public-*.pem` | 域名证书。certbot 证书另装 `/etc/letsencrypt/renewal-hooks/deploy/cdnca-control-web-bind.sh`，续期后自动复制并重载。 |
| `keys/pki/gateway-server.pem` | 用原私钥、本机根 CA 重签，SAN 保留原有项（含 IP），加上域名。 |
| `control.env` | `PAYMENT_CHANNELS_NOTIFY_BASE=https://<域名>`。默认还会把 `CDNCA_GATEWAY_LOCAL_ADDRESS/_SERVER_NAME/_ENROLLMENT_ADDRESS` 改成域名。 |
| `downloads/node-install-defaults`、`runtime-config.js` | 网关地址和名称改成域名，并更新升级信任 SHA。域名证书为公网受信时，`__CDNCA_CONTROL_CA_SHA256__` 置空。 |
| `downloads/edge-agent/upgrade-trust.json` | 按 control.env 重新发布，内容一般不变。 |

服务：重载 `cdnca-control-web`，不断连；重启 `cdnca-agent-gateway`，节点自动重连；重启 `cdnca-control-api`。

## 4. 刻意不改的

- `CONTROL_UPGRADE_ARTIFACT_BASE_URL` 和升级下载策略的主机：edge-agent 只接受安装时钉住的下载主机（`updater/download_policy.go` 的 `Adopt`）。改成域名后，按 IP 安装的节点将无法再升级。新装节点也继续按原 IP 和私有根下载。
- 默认 server 与私有证书：节点按 IP 下载升级时不带 SNI，并用私有根校验，所以 443 的默认证书必须仍是私有证书。浏览器按 SNI 拿到域名证书。
- 已装节点的主网关地址：节点配置里仍是安装时的 IP，网关证书保留 IP SAN。域名只作为学到的备用端点。
- 授权端：续租按安装私钥签名，`control_installations` 不记地址。`installation_endpoint_reports` 只用于门户展示和搜索，不影响续租，所以不需要改授权端。

## 5. 失败与回滚

改动前，所有涉及的文件都会备份到 `/var/lib/cdnca-control/host-bind-backup-<UTC 时间>/`。以下任一步失败，命令会自动恢复文件，并对已动过的服务再次执行重载或重启：nginx -t、重载、重签、重发信任、重启、就绪检查。输出会说明“已回滚”和备份目录。回滚不完整时输出 `ROLLBACK INCOMPLETE`，此时按备份目录手工复制回原路径，再执行 `systemctl reload cdnca-control-web && systemctl restart cdnca-agent-gateway cdnca-control-api`。

升级时运行的 `converge-management-web-nginx.py` 能识别域名块：先收敛原 server，再派生出新的域名块，绑定不会因此丢失。

## 6. 完成后

1. 用 `https://<域名>/dashboard/` 重新打开管理端，再到节点页复制安装命令。命令以页面地址为控制面地址。
2. `control-host status` 核对域名证书到期时间和网关 SAN。
3. 运营者自带的证书不在 certbot lineage 内，不会自动续期。到期前带新证书重新执行 bind。
