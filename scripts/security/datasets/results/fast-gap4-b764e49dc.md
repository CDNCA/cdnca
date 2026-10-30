# waf-gap4 b764e49dc fast 正常集复测（gotestwaf 全量 + wafcomp-legit fast 4/4 片，155,077 条）

攻击集 wafcomp-mal 与 Leipzig 沿用 7d55a53c0（fast-gap4-7d55a53c0.md），其后改动只影响请求头令牌、crlf 头转储、redirect 无斜杠 scheme

- gotestwaf/attack 严格防护 346/671 51.56%
- gotestwaf/attack 仅记录 0/671 0.00%
- gotestwaf/attack 极严格防护 351/671 52.31%
- gotestwaf/attack 标准防护 295/671 43.96%
- gotestwaf/benign 严格防护 16/141 11.35%
- gotestwaf/benign 仅记录 0/141 0.00%
- gotestwaf/benign 极严格防护 16/141 11.35%
- gotestwaf/benign 标准防护 13/141 9.22%
- wafcomp-legit/benign 严格防护 28242/155076 18.21%
- wafcomp-legit/benign 仅记录 1/155077 0.00%
- wafcomp-legit/benign 极严格防护 32883/155074 21.20%
- wafcomp-legit/benign 标准防护 21290/155077 13.73%

## 逐条对比 fast-cookiefp（252c87be7）
- 标准档：1 条 forever21_hl-1576，改后 STDEXC tier=1 code=0（传输排除，非判定变化）
- 严格/极严格：wafcomp-legit 0 条变化（新增误报 0）；gotestwaf 攻击 +18
- 非递增 1 条 delta-286，改前即有
