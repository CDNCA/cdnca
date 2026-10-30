// 插件签名文档页（/developers/plugin-signing）。内容取自 docs/developer/plugin-signing.md；
// pluginSigning.test.tsx 校验：命令只用 cdnca-plugin usage 里的子命令与参数
// （services/market-service/cmd/cdnca-plugin/main.go），下载文件名与发布构建
// scripts/native-market-package.mjs pluginCliTargets 一致，挑战域与 market-service 一致。
import type { L } from '../i18n'
import type { Block } from './docs'
import { LINKS } from '../site'

const s = (zh: string, en = zh): L => ({ zh, en })

export const PLUGIN_SIGNING_PATH = '/developers/plugin-signing'

/** 卖家网站随市场发布包提供的下载（seller-portal/downloads/cdnca-plugin/）。 */
export const PLUGIN_CLI_DOWNLOADS = `${new URL(LINKS.developerLogin).origin}/downloads/cdnca-plugin`

export const PLUGIN_CLI_FILES: { file: string; platform: L }[] = [
  { file: 'cdnca-plugin-linux-amd64', platform: s('Linux x86_64') },
  { file: 'cdnca-plugin-linux-arm64', platform: s('Linux ARM64') },
  { file: 'cdnca-plugin-darwin-arm64', platform: s('macOS（Apple 芯片）', 'macOS (Apple silicon)') },
  { file: 'cdnca-plugin-windows-amd64.exe', platform: s('Windows x86_64') },
]

/** 开发套件（主题工具、示例、SDK、Webhook 接收器、provider 协议参考实现）：与 cdnca-plugin 同站下载
 *  （scripts/native-market-package.mjs devKitDownloadDir / devKitFile），随市场发布包签名发布。 */
export const DEV_KIT_DOWNLOADS = `${new URL(LINKS.developerLogin).origin}/downloads/dev-kit`
export const DEV_KIT_FILE = 'cdnca-dev-kit.tar.gz'
/** 来源清单（版本、精确 commit/tree、包摘要），与包同列在 SHA256SUMS 里（devKitManifestFile）。 */
export const DEV_KIT_MANIFEST = 'dev-kit.manifest.json'

/** 解包并核对开发套件（Linux 用 sha256sum，macOS 换成 shasum -a 256）。 */
export const DEV_KIT_FETCH = `CDNCA_KIT='${DEV_KIT_DOWNLOADS}'\ncurl --fail --location --show-error --output ${DEV_KIT_FILE} "$CDNCA_KIT/${DEV_KIT_FILE}" &&\ncurl --fail --location --show-error --output ${DEV_KIT_MANIFEST} "$CDNCA_KIT/${DEV_KIT_MANIFEST}" &&\ncurl --fail --location --show-error --output SHA256SUMS "$CDNCA_KIT/SHA256SUMS" &&\nsha256sum -c SHA256SUMS &&\ntar -xzf ${DEV_KIT_FILE} &&\ncd cdnca-dev-kit && cat VERSION SOURCE`

/** 挑战签名域（services/market-service/internal/plugin/plugin.go PublisherKeyPossessionDomain）。 */
export const POSSESSION_DOMAIN = 'cdnca-market-publisher-key-possession/v1'

const dl = (file: string) => `${PLUGIN_CLI_DOWNLOADS}/${file}`

export const DOWNLOAD_INTRO = s(
  '离线命令行工具，单个可执行文件，无需安装。每个文件与 SHA256SUMS 都随平台发布包签名发布，下载后先核对哈希：',
  'An offline command-line tool shipped as a single executable. Every file and SHA256SUMS ship in the platform’s signed release; check the hash after downloading:',
)

export const VERIFY_BLOCKS: Block[] = [
  { h: s('下载并校验', 'Download and verify') },
  { cmd: `curl -fsSLO '${dl('cdnca-plugin-linux-amd64')}'\ncurl -fsSLO '${dl('SHA256SUMS')}'\nsha256sum -c --ignore-missing SHA256SUMS\nchmod +x cdnca-plugin-linux-amd64 && mv cdnca-plugin-linux-amd64 cdnca-plugin`, label: s('Linux 下载与校验', 'Linux download and verify') },
  { p: s('macOS 用 shasum（ARM64 Linux 把文件名换成 cdnca-plugin-linux-arm64）：', 'On macOS use shasum (on ARM64 Linux use cdnca-plugin-linux-arm64):') },
  { cmd: `curl -fsSLO '${dl('cdnca-plugin-darwin-arm64')}'\ncurl -fsSLO '${dl('SHA256SUMS')}'\nshasum -a 256 -c --ignore-missing SHA256SUMS\nchmod +x cdnca-plugin-darwin-arm64 && mv cdnca-plugin-darwin-arm64 cdnca-plugin`, label: s('macOS 下载与校验', 'macOS download and verify') },
  { p: s('Windows（PowerShell）：输出 True 表示哈希一致。', 'Windows (PowerShell): True means the hash matches.') },
  { cmd: `Invoke-WebRequest '${dl('cdnca-plugin-windows-amd64.exe')}' -OutFile cdnca-plugin.exe\nInvoke-WebRequest '${dl('SHA256SUMS')}' -OutFile SHA256SUMS\n(Get-FileHash cdnca-plugin.exe -Algorithm SHA256).Hash.ToLower() -eq ((Select-String 'cdnca-plugin-windows-amd64.exe' SHA256SUMS).Line -split '\\s+')[0]`, label: s('Windows 下载与校验', 'Windows download and verify') },
  { note: s('哈希不一致时不要运行，重新下载；仍不一致请联系平台。', 'If the hash does not match, do not run the file; download again and contact us if it still differs.') },
]

export const SIGNING_BLOCKS: Block[] = [
  { p: s('插件发布者用自己的 Ed25519 私钥做两件事：在卖家站“发布者公钥”页登记公钥时证明你持有私钥（签名平台给出的挑战）；上传插件版本前给 manifest 签名（integrity 段）。签名规则与平台校验代码相同；私钥只在本机使用，工具不联网。',
    'Publishers use their own Ed25519 private key for two things: proving possession when registering a public key on the seller site’s “Publisher keys” page (signing the platform’s challenge), and signing the manifest (its integrity section) before uploading a plugin version. The signing rules are the same code the platform verifies with; the key never leaves your machine and the tool makes no network calls.') },
  { h: s('1. 生成密钥', '1. Create a key') },
  { cmd: './cdnca-plugin keygen -out publisher.key' },
  { list: [
    s('生成 publisher.key（权限 0600，内容是 base64url 编码的 32 字节 Ed25519 种子），已存在的文件不会被覆盖。', 'Writes publisher.key (mode 0600, a base64url-encoded 32-byte Ed25519 seed); an existing file is never overwritten.'),
    s('标准输出打印公钥（base64url，32 字节），登记时填这个值；之后可用 ./cdnca-plugin pubkey -key publisher.key 再打印一次。', 'Prints the public key (base64url, 32 bytes) to fill in at registration; print it again any time with ./cdnca-plugin pubkey -key publisher.key.'),
    s('私钥丢失后无法恢复，只能登记新公钥。请备份到受控位置，不要提交到代码仓库。', 'A lost private key cannot be recovered — you can only register a new public key. Back it up somewhere controlled and never commit it to a repository.'),
  ] },
  { h: s('2. 登记公钥（卖家站 → 发布者公钥）', '2. Register the public key (seller site → Publisher keys)') },
  { list: [
    s('点“登记公钥”，填命名空间和第 1 步打印的公钥，点“获取待签名内容”。', 'Click “Register key”, enter your namespace and the public key from step 1, then click “Get the message to sign”.'),
    s('复制页面显示的“待签名内容（base64url）”，在本机执行下面的命令。', 'Copy the “Message (base64url)” shown on the page and run the command below on your machine.'),
    s('把输出粘贴到“签名（base64url）”，点“提交登记”。挑战 15 分钟内有效，只能用一次。', 'Paste the output into “Signature (base64url)” and click “Register”. A challenge is valid for 15 minutes and can be used once.'),
  ], ordered: true },
  { cmd: "./cdnca-plugin sign-challenge -key publisher.key -message '<待签名内容>'" },
  { p: s(`工具会先确认这段内容是平台签发给这把公钥的挑战（${POSSESSION_DOMAIN} 域，公钥和 key ID 一致），否则拒绝签名，这样私钥不会被拿去签别的东西。`,
    `The tool first checks that the message is a platform challenge for this very key (${POSSESSION_DOMAIN} domain, matching public key and key ID) and refuses otherwise, so your key cannot be tricked into signing anything else.`) },
  { h: s('3. 签名 manifest', '3. Sign the manifest') },
  { cmd: './cdnca-plugin sign-manifest -key publisher.key -in manifest.json -out manifest.signed.json' },
  { list: [
    s('metadata.publisher.id 必须是你登记过的命名空间；integrity.key_id 由工具按“命名空间 + 公钥”算出，必须是该命名空间下状态为 active 的公钥。', 'metadata.publisher.id must be a namespace you registered; the tool derives integrity.key_id from namespace + public key, and it must be an active key of that namespace.'),
    s('工具覆盖原有 integrity 段，写入 algorithm=Ed25519、key_id、payload_sha256 和 signature；签名对象是去掉 integrity 后的规范化 manifest。', 'The tool replaces any existing integrity section with algorithm=Ed25519, key_id, payload_sha256 and signature, computed over the canonical manifest without integrity.'),
    s('签名后再改 manifest 的任何字段，签名都会失效，需要重新签名。', 'Changing any manifest field after signing invalidates the signature; sign again.'),
    s('manifest 只允许对象、数组和字符串，出现数字或布尔值时工具会报错（与平台规则一致）。', 'Manifests may only contain objects, arrays and strings; numbers or booleans are rejected (same rule as the platform).'),
  ] },
  { p: s('上传版本时用 manifest.signed.json。', 'Upload manifest.signed.json with the version.') },
  { h: s('4. 离线验证签名', '4. Verify the signature offline') },
  { cmd: "./cdnca-plugin verify -in manifest.signed.json -pubkey '<公钥>' -schema configuration_schema.json" },
  { list: [
    s('按平台上传时的同一套规则复核：algorithm 为 Ed25519、key_id 等于“命名空间 + 公钥”、payload_sha256 与规范化 manifest 一致、签名有效。通过时输出 OK、插件 ID、版本和 key_id。', 'Runs the checks the platform applies at upload: algorithm Ed25519, key_id equal to namespace + public key, payload_sha256 matching the canonical manifest, and a valid signature. On success it prints OK with the plugin ID, version and key_id.'),
    s('-pubkey 填登记过的公钥（base64url）；手边有私钥文件时也可用 -key publisher.key。可选 -schema、-content 核对配置结构和内容文件的 sha256 是否与 manifest 声明一致。', '-pubkey takes the registered public key (base64url); with the key file at hand, -key publisher.key works too. Optional -schema and -content check the configuration schema and content file against the sha256 the manifest declares.'),
    s('工具不联网，无法确认这把公钥在平台上是否仍为 active，以平台上传结果为准。', 'The tool is offline: it cannot tell whether the key is still active on the platform; the upload result is authoritative.'),
  ] },
  { h: s('错误与退出码', 'Errors and exit codes') },
  { p: s('出错时退出码为 1，并在标准错误输出原因（不会回显密钥内容）；用法错误退出码为 2。', 'On failure the tool exits 1 and prints the reason to stderr (never key material); usage errors exit 2.') },
]
