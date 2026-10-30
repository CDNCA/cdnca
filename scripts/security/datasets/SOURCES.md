# WAF/Bot 公开数据集来源

由 `scripts/security/datasets/gen_sources.py` 生成；数据只放 `~/.cache/cdnca-waf-datasets/`，不进仓库、不随产品分发。

分类口径：攻击样本不论许可证全部进授权端样本库与本地评测；规则文本为宽松许可证（MIT/BSD/Apache/CC0/ISC/Unlicense）直接转官方规则包；GPL/AGPL/LGPL 来源的规则原文也已转换进官方规则包（规则已采用，不注明出处）；CC-BY-SA/NC/无许可证的规则只作样本。

统计：规则可直接用 6，规则已采用 3，仅样本 22，共 31。

提交号取自下载目录名后缀（GitHub tarball 短提交号）；SHA-256 针对 `seed/tar/<目录名>.tar.gz`。

| 仓库 | URL | 提交 | 许可证 | 分类 | 用途 | tar SHA-256 |
|---|---|---|---|---|---|---|
| swisskyrepo/PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings | `3ac27901c711` | MIT | 仅样本 | 多类攻击样本 | `a2c4e4b1712fcb444757391135d72a2da5ab078fee2800a359d7a2cf8832124c` |
| fuzzdb-project/fuzzdb | https://github.com/fuzzdb-project/fuzzdb | `5656ab25dc6b` | BSD-3-Clause（_copyright.txt） | 仅样本 | 攻击样本 | `40f50a6969028f46f527a7333dd361c970ae773e06296ea25a3b8d0180a48f3c` |
| sqlmapproject/sqlmap | https://github.com/sqlmapproject/sqlmap | `6530184e2c56` | GPL-2.0-or-later | 仅样本 | SQLi 载荷（data/xml/payloads） | `8edf96ff87f6968999339494540654797d4d9fe05a04bfad9056e78ad2ea6e0d` |
| s0md3v/XSStrike | https://github.com/s0md3v/XSStrike | `ab27955d3674` | GPL-3.0 | 仅样本 | XSS 载荷 | `a9ba98402f1273cddab76519af966ad690c47e380c87e12776b28b29b5a71194` |
| payloadbox/command-injection-payload-list | https://github.com/payloadbox/command-injection-payload-list | `2a9f7b3acf01` | MIT | 仅样本 | 命令注入 | `a88295e256ac4e14cd45571c60baacf15fc77ec960683b9a106d7c9ccf9b70df` |
| payloadbox/crlf-injection-payload-list | https://github.com/payloadbox/crlf-injection-payload-list | `12c7274456e2` | MIT | 仅样本 | CRLF | `add07c8607723187e4c5828b6c1fdb6b64fc8ede99e68c703474f787fc537f8a` |
| payloadbox/directory-payload-list | https://github.com/payloadbox/directory-payload-list | `55d0ade67078` | MIT | 仅样本 | 路径穿越 | `fda1b4113e66e0f352ebf01a8482f3255291fc982ef38364f2f9da52c1de16fb` |
| payloadbox/open-redirect-payload-list | https://github.com/payloadbox/open-redirect-payload-list | `aa688c2b6cdf` | MIT | 仅样本 | 开放重定向 | `7d571adae09997d63562fdbbbfa4704dd802d81ea217796f158cec94da886f93` |
| payloadbox/server-side-template-injection-payloads | https://github.com/payloadbox/server-side-template-injection-payloads | `6c18c83b1905` | MIT | 仅样本 | SSTI | `28412346fff8819183894430af9455f800d51c19308744e339c0b5b53681c8ad` |
| payloadbox/sql-injection-payload-list | https://github.com/payloadbox/sql-injection-payload-list | `ffaeb80590fc` | MIT | 仅样本 | SQLi | `1a5ab3191602c2e63612ddea345aae0c2e37352ba5735de182b9a674f957952f` |
| payloadbox/waf-bypass-payload-list | https://github.com/payloadbox/waf-bypass-payload-list | `3a7125f7e6ea` | MIT | 仅样本 | WAF 绕过 | `e6b90b4b4d560ce0f2cd3d5e43e1d837a873c6f3b3b76e6669e5cc59a581a12d` |
| payloadbox/xss-payload-list | https://github.com/payloadbox/xss-payload-list | `5d8818076dd3` | MIT（仅 README 徽章，无 LICENSE 文件） | 仅样本 | XSS | `08b62240fb51dbf86e5a82267c8d49c11591fb057e6eb7f32d28099380e660b3` |
| payloadbox/xxe-injection-payload-list | https://github.com/payloadbox/xxe-injection-payload-list | `dceb185617e1` | MIT | 仅样本 | XXE | `6c29a2a0005003add9406a8a142bd4c29708e207161675c6745f06aa87c9d6d9` |
| 1N3/IntruderPayloads | https://github.com/1N3/IntruderPayloads | `9b84328441e0` | 无许可证 | 仅样本 | 多类攻击样本 | `e598f2dece4a716113687c63cfb6e3169b768faa69361268595105ae32c41980` |
| foospidy/payloads | https://github.com/foospidy/payloads | `38ac97fc0adf` | GPL-3.0 | 仅样本 | 多类攻击样本 | `165034c5cf026bec6f7100b61f91f6bc4f561cc7065dc6d18d4e4b44c0149b76` |
| nemesida-waf/waf-bypass | https://github.com/nemesida-waf/waf-bypass | `887f2f9d4667` | MIT | 仅样本 | WAF 绕过样本 | `bf77c6d68c2761dc0746011c0f10bac39bbbc835b144052881a857d675605e56` |
| chaitin/blazehttp | https://github.com/chaitin/blazehttp | `afc88a94d03d` | GPL-3.0 | 仅样本 | 攻击/白样本 HTTP 报文 | `02c024a6cd27e5aa5065abb4d638c3ee2ac3dd8797f36a72b5fd097ddd2db560` |
| PortSwigger/xss-cheatsheet-data | https://github.com/PortSwigger/xss-cheatsheet-data | `bf194a086546` | 无许可证（版权声明禁止衍生速查表） | 仅样本 | XSS 向量，仅内部评测 | `5da5e3c136ee7298604a40d3c65e993da7ac9082f26230ae5bb9c69a5d0c1a50` |
| cujanovic/SSRF-Testing | https://github.com/cujanovic/SSRF-Testing | `c26c3df20bcb` | 无许可证 | 仅样本 | SSRF | `8b24a1ee0e5b38612df08be638420a4a0cf27e31baf42dccaf9276b634bbbf12` |
| minimaxir/big-list-of-naughty-strings | https://github.com/minimaxir/big-list-of-naughty-strings | `db33ec7b1d5d` | MIT | 仅样本 | 边界字符串（误报评测） | `49b82d6c54b62daf74bc5954ece1a6cb658decf7060843688d360e68bed4434f` |
| wallarm/gotestwaf | https://github.com/wallarm/gotestwaf | `8ed7bc210ab7` | MIT | 仅样本 | 测试用例 | `11f5c2cbed798165b4cc7358e2ef322daa68a12ad54437cab1fff6d04c38b89f` |
| JayBizzle/Crawler-Detect | https://github.com/JayBizzle/Crawler-Detect | `64baedf9f5ee` | MIT | 规则可直接用 | 爬虫 UA 正则 | `8b139ec996b88d7fad66d04e444684098bd6983c7069402a9918058c75d25a1d` |
| monperrus/crawler-user-agents | https://github.com/monperrus/crawler-user-agents | `9345a7ad9c49` | MIT | 规则可直接用 | 爬虫 UA 模式 | `f530ce1f448ce976eae5d577a3c5c3d035d681f295d8bd4de880076a2657a15a` |
| omrilotan/isbot | https://github.com/omrilotan/isbot | `3f9c982acd95` | Unlicense | 规则可直接用 | Bot UA 模式 | `b2e0fcf71939084ce33cf2715dd40f75ac9065e0e3b61469199667daa31f96b2` |
| arcjet/well-known-bots | https://github.com/arcjet/well-known-bots | `bdf29352478e` | MIT | 规则可直接用 | 良性爬虫清单（分类/验证方式） | `3b16c506a977a1e1ad1c570303d27c395168047bea71d8e509975e1a0aadfd18` |
| ai-robots-txt/ai.robots.txt | https://github.com/ai-robots-txt/ai.robots.txt | `6abe630599ad` | MIT | 规则可直接用 | AI 爬虫清单 | `8d8dbfb2d1bba6c2593b9556a9afa1ce9aeb72fdcda1d8a879406278c617f09e` |
| mitchellkrogza/nginx-ultimate-bad-bot-blocker | https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker | `cc84d6177e49` | MIT | 规则可直接用 | 恶意 UA/扫描器 | `0bfbf48b965734189d5882320e3a887d6eb03d55be1b7babbfb720f31ed7a9b2` |
| matomo-org/device-detector | https://github.com/matomo-org/device-detector | `103aefadc9da` | LGPL-3.0 | 规则已采用 | Bot 正则 → system/bot-dd-scraper、bot-dd-service | `060fd5df9d93a8eb2f71c693b5009753c145d4132121a6987b47fe23e08b1158` |
| bunkerity/bunkerweb | https://github.com/bunkerity/bunkerweb | `23203c0cef50` | AGPL-3.0 | 规则已采用 | 方法/请求头数/请求体默认限制 → system/bw-request-limits（坏 UA、坏行为已在 bot-bad-ua、cc-404-burst） | `da2ffa546f3948dd2e20c51e0717e7a3225f4d5f10b727fd63389baf8e95b2e6` |
| wargio/naxsi | https://github.com/wargio/naxsi | `7e867e20e282` | GPL-3.0（另含 LGPL-3.0 部分） | 规则已采用 | 核心规则+blocking 规则 → system/naxsi-strong（核心规则多字符强特征）、naxsi-scanner、naxsi-websec、naxsi-sqli | `83abfefba3508288028b2a73c32a714f3130293ed64b8579e38646b3e2248b22` |
| danielmiessler/SecLists | https://github.com/danielmiessler/SecLists | `75064ac792b5` | MIT | 仅样本 | 攻击样本（git 浅克隆，无 tar） | — |
