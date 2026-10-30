# waf-cookie-fp 最终版（252c87be7）fast 子集 + CRS 回归，真实 OpenResty

改前 = runs/fast（fast-c4879746c.md，waf-strict-algo c838d8ff2 + RI-03）；改后 = runs/fast-cookiefp（冻结副本 252c87be7，FAST=1 run-std.sh 全套 12 批，均 RESULT failures=0）。

| 档 | 改前 TPR | 改后 TPR | 改前 FPR | 改后 FPR | 改前平衡准确率 | 改后平衡准确率 |
|---|---|---|---|---|---|---|
| 标准 | 89.75% | 89.75% | 13.73% | 13.73% | 88.01% | 88.01% |
| 严格 | 90.03% | 90.05% | 38.08% | 18.21% | 75.98% | 85.92% |
| 极严格 | 90.12% | 90.14% | 41.64% | 21.20% | 74.24% | 84.47% |

| 其他 | 改前 | 改后 |
|---|---|---|
| GoTestWAF 攻击 标准/严格/极严格 | 43.96/48.88/49.63% | 不变 |
| GoTestWAF 正常 严格/极严格 | 16/139（2 条 500 排除） | 16/141 = 11.35%（500 消失） |
| Leipzig 20 万 标准/严格/极严格 | 0.58/0.80/1.66% | 不变（逐条相同） |

逐条（stdhit_compare.py runs/fast runs/fast-cookiefp）：
- 标准防护 0 变化。
- 严格：正常 -31,772 / +960，攻击 +2；极严格：正常 -32,607 / +921，攻击 +2。
- +960 里 589 条是改前“标准拦、严格不拦”的非递增（改前共 590 条：严格档两级计分在标准档已拦的请求上漏判），改后严格档也拦，属于修正；其余 371 条（极严格 332）是 Cookie 解码后交检测器、请求体含 `[` 不再让 CMDI.glob 抛错后检测器真实命中（Akamai sensor_data、编码 query 等）。
- 改后非递增只剩 1 条（browsing_2024_delta-286：严格/极严格 code=0 传输失败被排除，改前同样）。

CRS 回归（ONLY=functional,tiers,adaptive,eval，runs/cookie-fp/crs-eval-final.log，failures=0；ri03_compare 对 eval-ri03.jsonl.gz）：
| 档 | 改前拦截 | 改后拦截 | 改前拦截+挑战 | 改后拦截+挑战 | 正常误拦 | 正常被挑战 |
|---|---|---|---|---|---|---|
| 标准 | 1350 | 1350（逐条 0 变化） | 1350 | 1350 | 29 | 0 |
| 严格 | 2583 | 2589 | 2951 | 2943（丢 14、得 6） | 53 | 61 |
| 极严格 | 2665 | 2670 | 3372 | 3299（丢 79、得 6） | 68 | 76 |

丢失的全部是攻击只在 Cookie、只靠 PL2+ 弱分命中的回归样本（66 条 944 Java、名为 Base64 片段的 Cookie、`una$$me -a` 等）；四档逐条递增（0 例非递增）。

## Cookie 弱分按站点画像自适应（waf-cookie-fp2，b98bbad0f）

做法：两级 tier 多一个 Cookie 变体 location（弱分规则照读 Cookie）；Lua 只在请求里某个定型 Cookie 参数（typed_params，loc=cookie）的值偏离画像（类型/长度桶/字符类）时进入变体；没有定型 Cookie 的站点（画像未成熟）维持"弱分不读 Cookie"。

真实 OpenResty：functional,tiers,adaptive,eval 0 失败；CRS 回归各站无画像，3772 条与 252c87be7 逐条相同（无画像时行为不变）；新用例：定型 Cookie 偏离 + 弱命中 403、合画像 200、未定型 Cookie 200、无画像站 200、只偏离无弱命中 200。

离线估算（cookieprofile.py：wafcomp-legit 85% 学习、15% fast 评估，阈值同 ADR 3.3；results/cookieprofile-estimate.txt），"画像成熟" = 站点学习集 ≥1000 请求（408/692 站）：
| 口径 | 严格 偏离请求 | 严格 FPR | 极严格 FPR | CRS 丢失恢复 严格/极严格 |
|---|---|---|---|---|
| 现状（不读 Cookie 弱分） | — | 18.21% | 21.20% | 0/14、0/79 |
| 已实现：定型 Cookie 偏离 | 10（0.01%） | ≤18.22%（+7） | ≤21.21%（+7） | 0/14、0/79 |
| 同载荷放进站点已定型 Cookie | — | — | — | 56.8%、39.0% 的(站点,Cookie)判偏离 |
| 未实现：成熟站点出现未见 Cookie 名也算偏离 | 654（0.42%） | ≤18.23%（+33） | ≤21.23%（+39） | 14.3/14、78.8/79 |

CRS 丢失样本的 Cookie 名是 test / test_cookie / Base64 片段 / 无名，任何真实站点都不会把它们定型，所以只靠 typed_params 恢复 0 条；要恢复需"未见 Cookie 名"信号（节点需每站已知 Cookie 名集合 + 成熟标志，超出现 typed_params 契约）。
