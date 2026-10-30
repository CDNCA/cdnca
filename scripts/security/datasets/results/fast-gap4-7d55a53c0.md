# waf-gap4 fast 子集（7d55a53c0，真实 OpenResty）

| 数据集 | 档 | 计入 | 拦截 | 比率 | 95% 区间 | 排除 |
|---|---|---|---|---|---|---|
| gotestwaf/attack | 仅记录 | 671 | 0 | 0.00% | 0.00%–0.57% | 4 |
| gotestwaf/attack | 标准防护 | 671 | 295 | 43.96% | 40.25%–47.74% | 4 |
| gotestwaf/attack | 严格防护 | 671 | 342 | 50.97% | 47.19%–54.73% | 4 |
| gotestwaf/attack | 极严格防护 | 671 | 347 | 51.71% | 47.93%–55.47% | 4 |
| gotestwaf/benign | 仅记录 | 141 | 0 | 0.00% | 0.00%–2.65% | 0 |
| gotestwaf/benign | 标准防护 | 141 | 13 | 9.22% | 5.47%–15.14% | 0 |
| gotestwaf/benign | 严格防护 | 141 | 16 | 11.35% | 7.11%–17.64% | 0 |
| gotestwaf/benign | 极严格防护 | 141 | 16 | 11.35% | 7.11%–17.64% | 0 |
| leipzig/benign | 仅记录 | 200000 | 0 | 0.00% | 0.00%–0.00% | 0 |
| leipzig/benign | 标准防护 | 200000 | 1154 | 0.58% | 0.54%–0.61% | 0 |
| leipzig/benign | 严格防护 | 200000 | 1590 | 0.80% | 0.76%–0.83% | 0 |
| leipzig/benign | 极严格防护 | 200000 | 3322 | 1.66% | 1.61%–1.72% | 0 |
| wafcomp-legit/benign | 仅记录 | 155077 | 1 | 0.00% | 0.00%–0.00% | 1 |
| wafcomp-legit/benign | 标准防护 | 155077 | 21290 | 13.73% | 13.56%–13.90% | 1 |
| wafcomp-legit/benign | 严格防护 | 155077 | 28299 | 18.25% | 18.06%–18.44% | 1 |
| wafcomp-legit/benign | 极严格防护 | 155076 | 32934 | 21.24% | 21.03%–21.44% | 2 |
| wafcomp-mal/attack | 仅记录 | 11087 | 0 | 0.00% | 0.00%–0.03% | 0 |
| wafcomp-mal/attack | 标准防护 | 11087 | 9951 | 89.75% | 89.18%–90.30% | 0 |
| wafcomp-mal/attack | 严格防护 | 11087 | 9984 | 90.05% | 89.48%–90.59% | 0 |
| wafcomp-mal/attack | 极严格防护 | 11087 | 9994 | 90.14% | 89.57%–90.68% | 0 |

| 档 | TPR | FPR | 平衡准确率 |
|---|---|---|---|
| 仅记录 | 0.00% | 0.00% | 50.00% |
| 标准防护 | 89.75% | 13.73% | 88.01% |
| 严格防护 | 90.05% | 18.25% | 85.90% |
| 极严格防护 | 90.14% | 21.24% | 84.45% |

## 逐条对比 fast-cookiefp（252c87be7）
```
仅记录 逐条变化: 0
标准防护 逐条变化: {('wafcomp-legit', '-'): 1}
严格防护 逐条变化: {('gotestwaf', '+'): 14, ('wafcomp-legit', '+'): 57}
极严格防护 逐条变化: {('gotestwaf', '+'): 14, ('wafcomp-legit', '+'): 51}
改后非递增（某档拦、更严档不拦）: 1 [('wafcomp-legit', 'browsing_2024_delta-286')]
```
- 标准档 1 条为 hotels_al-415 改后 STDEXC code=0（传输排除）；非递增 1 条 delta-286 改前即有
- 严格 +57 正常：lazada x-ua 设备指纹（sqli）、boohoo 会话回放头转储（crlf）、booking dl=https:host（redirect），已由 8744e377b 修

## CRS 回归 ONLY=functional,tiers,adaptive,eval（对比 runs/cookie-fp/crs-eval-fp2.log）
EVALSUM tier=仅记录 attacks=3521 blocked=0 tpr=0.0000 challenged=0 tpr_with_challenge=0.0000 benign=251 fp=0 fpr=0.0000 benign_challenged=0 challenge_rate=0.0000
EVALSUM tier=标准防护 attacks=3521 blocked=1350 tpr=0.3834 challenged=0 tpr_with_challenge=0.3834 benign=251 fp=29 fpr=0.1155 benign_challenged=0 challenge_rate=0.0000
EVALSUM tier=严格防护 attacks=3521 blocked=2596 tpr=0.7373 challenged=354 tpr_with_challenge=0.8378 benign=251 fp=53 fpr=0.2112 benign_challenged=61 challenge_rate=0.2430
EVALSUM tier=极严格防护 attacks=3521 blocked=2677 tpr=0.7603 challenged=626 tpr_with_challenge=0.9381 benign=251 fp=68 fpr=0.2709 benign_challenged=76 challenge_rate=0.3028
RESULT failures=0
- 标准档逐条 0 变化；严格/极严格拦截各 +7（933111×3、934110、934120×3），0 丢失；四档递增 0 例外
