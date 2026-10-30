# 插件发布者签名工具 cdnca-plugin

插件发布者用自己的 Ed25519 私钥做两件事：

1. 在卖家站“发布者公钥”页登记公钥时，证明你持有对应的私钥（签名平台给出的挑战）。
2. 上传插件版本前，给 manifest 签名（`integrity` 段）。

`cdnca-plugin` 是离线命令行工具，签名规则与 market-service 的校验代码相同
（`services/market-service/internal/plugin`：`PossessionMessage`、`KeyID`、`CanonicalManifestPayload`、
`VerifyManifestSignature`）。私钥只在本机使用，工具不联网。

## 下载

对外文档页：<https://www.cdnca.com/developers/plugin-signing>（`apps/www/src/content/pluginSigning.ts`）。

市场发布包（`scripts/native-market-package.mjs`）随卖家网站带上四个平台的静态二进制和 `SHA256SUMS`，
都在发布清单里、由发布签名覆盖，装好后从卖家站下载：
`https://developer.cdnca.com/downloads/cdnca-plugin/<文件>`，文件为 `cdnca-plugin-linux-amd64`、
`cdnca-plugin-linux-arm64`、`cdnca-plugin-darwin-arm64`、`cdnca-plugin-windows-amd64.exe`。

```sh
curl -fsSLO https://developer.cdnca.com/downloads/cdnca-plugin/cdnca-plugin-linux-amd64
curl -fsSLO https://developer.cdnca.com/downloads/cdnca-plugin/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS      # macOS: shasum -a 256 -c --ignore-missing SHA256SUMS
chmod +x cdnca-plugin-linux-amd64 && mv cdnca-plugin-linux-amd64 cdnca-plugin
```

## 从源码构建

```sh
go -C services/market-service build -o "$PWD/cdnca-plugin" ./cmd/cdnca-plugin
```

## 1. 生成密钥

```sh
./cdnca-plugin keygen -out publisher.key
```

- 会生成 `publisher.key`（权限 0600，内容是 base64url 编码的 32 字节 Ed25519 种子），已存在的文件不会被覆盖。
- 标准输出打印公钥（base64url 编码，32 字节），在卖家站登记时填这个值。之后需要时可用
  `./cdnca-plugin pubkey -key publisher.key` 再打印一次。
- 私钥丢失后无法恢复，只能登记新公钥。请备份到受控位置，不要提交到仓库。

## 2. 登记公钥（卖家站 → 发布者公钥）

1. 点“登记公钥”，填命名空间和第 1 步打印的公钥，点“获取待签名内容”。
2. 复制页面显示的“待签名内容（base64url）”，在本机执行：

   ```sh
   ./cdnca-plugin sign-challenge -key publisher.key -message '<待签名内容>'
   ```

3. 把输出粘贴到“签名（base64url）”，点“提交登记”。挑战 15 分钟内有效，并且只能用一次。

工具会先确认这段内容是平台签发给这把公钥的挑战（`cdnca-market-publisher-key-possession/v1` 域、
公钥和 key ID 一致），不是的话会拒绝签名。这样你的私钥不会被拿去签别的东西。

## 3. 签名 manifest

```sh
./cdnca-plugin sign-manifest -key publisher.key -in manifest.json -out manifest.signed.json
```

- `metadata.publisher.id` 必须是你登记过的命名空间，`integrity.key_id` 由工具按“命名空间 + 公钥”算出，
  必须是该命名空间下状态为 active 的公钥。
- 工具会覆盖原有的 `integrity` 段，写入 `algorithm=Ed25519`、`key_id`、`payload_sha256` 和 `signature`。
  签名对象是去掉 `integrity` 后的规范化 manifest（规则见 [插件供应链 §5](plugin-supply-chain.md)）。
- 签名后再改 manifest 的任何字段，签名都会失效，需要重新签名。
- manifest 只允许对象、数组和字符串，出现数字或布尔值时工具会报错（和服务端规则一致）。

上传版本时用 `manifest.signed.json`。

## 4. 离线验证签名

```sh
./cdnca-plugin verify -in manifest.signed.json -pubkey '<公钥>' -schema configuration_schema.json
```

- 规则与 market-service 上传时相同（`uploadVersionTx`）：`integrity.algorithm` 为 `Ed25519`，
  `integrity.key_id` 等于“`metadata.publisher.id` + 公钥”算出的 key ID，`payload_sha256` 与规范化 manifest 一致，签名有效。
  通过时输出 `OK <插件 ID> <版本> key_id=... payload_sha256=...`，退出码 0。
- `-pubkey` 填卖家站登记过的公钥（base64url）；手边有私钥文件时也可以用 `-key publisher.key`，两者只能给一个。
- 可选 `-schema`、`-content`：核对配置结构文件、内容文件（rule_pack / theme）的 sha256 是否等于 manifest 里
  `spec.configuration_schema.sha256`、`spec.entrypoint.sha256`。
- 工具不联网，无法确认这把公钥在平台上是否仍为 active；以平台上传结果为准。

## 错误

工具出错时退出码为 1，并在标准错误输出原因（不会回显密钥内容）；用法错误退出码为 2。
