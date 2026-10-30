# 官方规则包评测（真实 OpenResty 规则计划）

命令：eval_imported_packs.py（seed 攻击 5000 + waf-comparison fast：正常 155k / 攻击 11k）。“+包”列 = CRS 档拦截 ∪ 包命中（即包动作改为 block 后）。
新包 7 个：naxsi-strong / naxsi-scanner / naxsi-websec / naxsi-sqli / bot-dd-scraper / bot-dd-service / bw-request-limits。
naxsi-core 原样转换不发布（白名单式计分，单字符特征逐个加分）：上一轮评测其正常集命中 111017/154834 = 71.70%，改 block 后标准档误报 13.75%→72.04%。
naxsi-strong 只保留 naxsi-core 中正常集单条命中 <0.5% 的 26 个多字符特征（screen_naxsi_strong.py 离线筛选，真实 OpenResty 结果与离线估算一致）。
UA 类包在这些语料上几乎不命中（语料 UA 均为浏览器）；UA 误伤由 rulepackcheck 良性爬虫 UA 回归 0 命中保证。

## 四档拦截/误报（包动作改为 block 后；CRS 档结果取已有评测）

| 集 | 样本 | 档 | 仅 CRS | +已发布 7 包 | +全部 14 包（7 旧 + 7 新） |
|---|---|---|---|---|---|
| seed/attack | 5000 | 仅记录 | 0.00% | 7.92% | 19.42% |
| seed/attack | 5000 | 标准防护 | 45.06% | 45.52% | 46.52% |
| seed/attack | 5000 | 严格防护 | 47.68% | 48.04% | 48.76% |
| seed/attack | 5000 | 极严格防护 | 48.96% | 49.32% | 50.04% |
| wafcomp-legit/benign | 154834 | 仅记录 | 0.00% | 0.10% | 4.04% |
| wafcomp-legit/benign | 154834 | 标准防护 | 13.75% | 13.84% | 16.76% |
| wafcomp-legit/benign | 154834 | 严格防护 | 38.14% | 38.17% | 39.11% |
| wafcomp-legit/benign | 154834 | 极严格防护 | 41.70% | 41.73% | 42.63% |
| wafcomp-mal/attack | 11087 | 仅记录 | 0.00% | 19.36% | 24.12% |
| wafcomp-mal/attack | 11087 | 标准防护 | 89.75% | 90.55% | 91.17% |
| wafcomp-mal/attack | 11087 | 严格防护 | 90.03% | 90.83% | 91.40% |
| wafcomp-mal/attack | 11087 | 极严格防护 | 90.12% | 90.92% | 91.49% |

## 按包命中（默认 log 时的记录数）

| 包 | seed/attack | wafcomp-legit/benign | wafcomp-mal/attack |
|---|---|---|---|
| bw-request-limits（新） | 0 (0.00%) | 297 (0.19%) | 0 (0.00%) |
| naxsi-scanner（新） | 0 (0.00%) | 4 (0.00%) | 0 (0.00%) |
| naxsi-sqli（新） | 355 (7.10%) | 1684 (1.09%) | 71 (0.64%) |
| naxsi-strong（新） | 235 (4.70%) | 724 (0.47%) | 1129 (10.18%) |
| naxsi-websec（新） | 58 (1.16%) | 3586 (2.32%) | 88 (0.79%) |
| waf-scheme-wrapper | 219 (4.38%) | 1 (0.00%) | 14 (0.13%) |
| waf-traversal-probe | 258 (5.16%) | 156 (0.10%) | 2135 (19.26%) |

排除（状态非 200 或原评测排除）：seed/attack 0，wafcomp-legit/benign 244，wafcomp-mal/attack 0
