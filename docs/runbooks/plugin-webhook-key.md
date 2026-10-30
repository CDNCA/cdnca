# 插件 Webhook 投递证明密钥（attestation key）

control-api 的插件 Webhook 运行时每次把投递或死信写进 JetStream 后，用一把 Ed25519 私钥给这次发布签名；数据库（迁移 084）用 `plugin_webhook_runtime_attestation_head` 里的公钥验签，不认的签名一律拒绝。

- 私钥只在 control-api 进程里，数据库只存公钥。
- 数据库同一时刻只有一把 `active` 密钥。轮换就是：旧钥改为 `retired`、新钥按 `generation+1` 装入、头部推进，三步在同一个事务里完成。已有发布记录仍指向旧代际，不受影响。
- 运行时第一次发布时，用当前密钥自动装入第 1 代（有效期 5 年）。

## 配置

| 变量 | 说明 |
|---|---|
| `PLUGIN_WEBHOOK_ATTESTATION_KEY_ID` | 当前密钥 ID，`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` |
| `PLUGIN_WEBHOOK_ATTESTATION_PRIVATE_KEY_FILE` | 当前私钥，PKCS#8 PEM（`-----BEGIN PRIVATE KEY-----`） |
| `PLUGIN_WEBHOOK_ATTESTATION_NEXT_KEY_ID` | 可选，轮换时预置的下一把密钥 ID，不能和当前相同 |
| `PLUGIN_WEBHOOK_ATTESTATION_NEXT_PRIVATE_KEY_FILE` | 可选，下一把私钥，不能和当前是同一把 |

`PLUGIN_WEBHOOK_RUNTIME_ENABLED=true` 时当前密钥缺失或格式不对，control-api 启动直接失败并报出变量名，不会在空密钥下运行。

默认生成：

- 原生安装（`scripts/install-control.sh`）：生成 `/etc/cdnca-control/keys/plugin-webhook-attestation-v1.pem`（root 0400），`control.env` 写入 ID `plugin-webhook-attestation-v1`。运行时默认关闭，开启时不用再补密钥。
- 本地栈（`scripts/local-stack.sh` + `compose.full.yaml`）：生成 `plugin-webhook-attestation-key.pem`，ID `local-plugin-webhook-attestation-v1`。
- Helm：chart 不创建 Secret。启用 `pluginWebhook.enabled` 前先建好 Secret；`pluginWebhook.attestationKey.id` 或 `.secret.name` 为空时，`helm template/install` 报错并指向本文。

```bash
openssl genpkey -algorithm ED25519 -out attestation.pem
kubectl -n cdnca create secret generic cdnca-plugin-webhook-attestation-v1 --from-file=attestation.pem
rm -f attestation.pem
```

```yaml
pluginWebhook:
  attestationKey:
    id: plugin-webhook-attestation-v1
    secret: {name: cdnca-plugin-webhook-attestation-v1, key: attestation.pem}
```

## 查看状态

```bash
control-api plugin-webhook-attestation-key status
# plugin webhook attestation head: generation=1 key_id=plugin-webhook-attestation-v1 expires_at=... matches=current next_staged=false
```

`matches=none` 表示数据库头部和进程配置的两把密钥都对不上，运行时此时无法发布，按下文「回退」处理。

## 轮换（不中断投递）

命令读取和进程相同的 `PLUGIN_WEBHOOK_ATTESTATION_*` 与 `DATABASE_URL`；`DATABASE_URL` 需要 schema 属主权限（和首次装入第 1 代时相同）。

1. 生成新密钥，作为 next 配给运行时，并滚动重启 control-api。此时仍用当前密钥签名。
   - 原生：
     ```bash
     /usr/local/libexec/cdnca/cdnca-ed25519 genkey /etc/cdnca-control/keys/plugin-webhook-attestation-v2.pem
     chmod 0400 /etc/cdnca-control/keys/plugin-webhook-attestation-v2.pem
     cat >>/etc/cdnca-control/control.env <<'EOF'
     PLUGIN_WEBHOOK_ATTESTATION_NEXT_KEY_ID=plugin-webhook-attestation-v2
     PLUGIN_WEBHOOK_ATTESTATION_NEXT_PRIVATE_KEY_FILE=/etc/cdnca-control/keys/plugin-webhook-attestation-v2.pem
     EOF
     systemctl restart cdnca-control-api
     ```
   - Helm：建好新 Secret，设置 `pluginWebhook.attestationKey.next.id` / `.next.secret.name`，`helm upgrade`，等所有 control-api Pod 就绪。
2. 确认 `status` 输出 `matches=current next_staged=true`，然后推进：
   ```bash
   set -a; . /etc/cdnca-control/control.env; set +a
   control-api plugin-webhook-attestation-key rotate
   # plugin webhook attestation key rotated: generation 1 (plugin-webhook-attestation-v1) -> 2 (plugin-webhook-attestation-v2), expires_at=...
   ```
   Helm 部署用 `kubectl exec` 进任一 control-api Pod 执行同一命令。推进会等正在发布的事务结束；持有两把密钥的进程随后自动改用新钥，不用重启。重复执行只会报告 `already rotated`，不会再写一次。
3. 把新钥提为当前、去掉 next，再滚动一次：
   - 原生：`PLUGIN_WEBHOOK_ATTESTATION_KEY_ID` / `_PRIVATE_KEY_FILE` 改成 v2，删掉两行 `NEXT`，重启；旧私钥文件确认不再引用后删除。
   - Helm：`attestationKey.id/secret` 改成 v2，`next` 清空，`helm upgrade`；旧 Secret 随后删除。

每次成功轮换都会在平台作用域写一条审计事件 `plugin.webhook_attestation_key.rotate`（操作者 `system`，`actor_ref=cli:plugin-webhook-attestation-key`，变更 `key_id`、`generation`，附新钥到期时间），可在审计日志里按动作查看。

## 回退与故障

- 第 2 步之前：去掉 next 配置即可，数据库没有变化。
- 第 2 步之后不能回到旧钥：084 不允许重新激活已退役的密钥。如果新钥有问题，再生成一把 v3，按同样步骤轮换。
- 第 2 步之后有进程只配了旧钥（漏滚动）：这些进程确认发布时报 `plugin webhook runtime attestation key does not match the database head`，确认不会写入；租约到期后由持有新钥的进程重新领取，先在流里对账已发出的消息再补确认，投递不会丢失。给漏掉的进程补上新钥并重启即可。
- 私钥泄露：立即按上面步骤轮换，泄露的钥退役后数据库不再接受它签的新发布。

## 有效期

每一代有效期 5 年，从装入时计算。到期后数据库拒绝发布，到期前用 `status` 查看 `expires_at` 并按上面步骤轮换。
