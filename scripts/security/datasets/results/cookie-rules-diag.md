# 严格档 Cookie 误报规则归因（waf-cookie-fp 第 1 节，3000 条“严格拦、标准不拦”的 waf-comparison 正常请求，真实 OpenResty，STD_RULES=1）

命中位置取自审计消息 "found within <VAR>"；942200/942440 的 logdata 被截断、位置未标，交叉核对：942200 有 703 条出现在无 query/body 的请求上（只能来自 Cookie）。

## 严格防护
requests=3000 tier=2 only_cookie_or_unlocated=2131
| 规则 | 命中请求 | Cookie 值 | Cookie 名 | 其他 | 未标位置 | 典型 Cookie 名 | Cookie 值形态 |
|---|---|---|---|---|---|---|---|
| 942200 | 2654 | 0 | 0 | 0 | 2654 |  |  |
| 942340 | 2564 | 2168 | 0 | 396 | 0 | _tracking_consent, _cmp_a, __cq_bc | json 1636, kv-packed 113, json-like 5 |
| 942370 | 2287 | 1924 | 0 | 363 | 0 | _tracking_consent, _cmp_a, __cq_bc | json 1357, kv-packed 146, json-like 4 |
| 942330 | 849 | 740 | 0 | 109 | 0 | _tracking_consent, dataservices_product_context, _cs_cvars | json 608, plain 23, url-encoded 1 |
| 932271 | 819 | 739 | 0 | 80 | 0 | __cq_seg, bm_sv, ak_bmsc | plain 586, url-encoded 8, json 6 |
| 942430 | 582 | 0 | 0 | 582 | 0 |  |  |
| 932240 | 541 | 500 | 0 | 41 | 0 | dtPC, _gcl_gs, utag_main | plain 174, kv-packed 86, json 20 |
| 931130 | 508 | 0 | 0 | 508 | 0 |  |  |
| 932236 | 415 | 353 | 0 | 62 | 0 | OptanonConsent, __utmzz, __eoi | kv-packed 199, plain 70, url-encoded 3 |
| 932200 | 357 | 236 | 0 | 121 | 0 | dataservices_product_context, checkout_session_token__cn__Z2NwLWV1cm9wZS13ZXN0MTowMUpBNjVRVlFK, checkout_session_token__cn__Z2NwLXVzLWNlbnRyYWwxOjAxSkEzNUFXTUZZ | json 46, kv-packed 42, plain 11 |
| 942520 | 215 | 162 | 0 | 53 | 0 | channelAttributionData, _hp5_meta.913210224, _hp2_ses_props.1621830767 | json 116, kv-packed 8, json-like 3 |
| 942440 | 200 | 0 | 0 | 0 | 200 |  |  |
| 942120 | 122 | 0 | 0 | 122 | 0 |  |  |
| 941340 | 50 | 4 | 0 | 46 | 0 | anj, ANALYTICS_INFO |  |
| 942180 | 48 | 47 | 0 | 1 | 0 | 3ce88a9435c380ac6dfca1b1666eb57ef3378fcb7c0ee650c90a3c1c17f1ff88, ci-ppv, ci-vtimes | kv-packed 17 |
| 942300 | 35 | 28 | 0 | 7 | 0 | ud_last_auth_information, _cs_cvars, wisepops_props | kv-packed 15, json 12 |
| 932220 | 30 | 19 | 0 | 11 | 0 | __utmzz, ANALYTICS_INFO |  |
| 942131 | 30 | 0 | 0 | 30 | 0 |  |  |
| 941150 | 27 | 20 | 0 | 7 | 0 | sbjs_first, mage-messages, hiddenParamsDAC-JFK | kv-packed 14, json 1 |
| 932239 | 25 | 0 | 0 | 25 | 0 |  |  |

## 极严格防护
requests=3000 tier=3 only_cookie_or_unlocated=1989
| 规则 | 命中请求 | Cookie 值 | Cookie 名 | 其他 | 未标位置 | 典型 Cookie 名 | Cookie 值形态 |
|---|---|---|---|---|---|---|---|
| 942420 | 2665 | 2665 | 0 | 0 | 0 | OptanonConsent, _tracking_consent, section_data_ids | json 790, kv-packed 669, plain 311 |
| 942200 | 2654 | 0 | 0 | 0 | 2654 |  |  |
| 942340 | 2564 | 2168 | 0 | 396 | 0 | _tracking_consent, _cmp_a, __cq_bc | json 1636, kv-packed 113, json-like 5 |
| 942490 | 2523 | 2179 | 0 | 344 | 0 | _tracking_consent, section_data_ids, serverUAInfo | json 1583, kv-packed 119, plain 65 |
| 942370 | 2287 | 1924 | 0 | 363 | 0 | _tracking_consent, _cmp_a, __cq_bc | json 1357, kv-packed 146, json-like 4 |
| 942330 | 849 | 740 | 0 | 109 | 0 | _tracking_consent, dataservices_product_context, _cs_cvars | json 608, plain 23, url-encoded 1 |
| 932271 | 819 | 739 | 0 | 80 | 0 | __cq_seg, bm_sv, ak_bmsc | plain 586, url-encoded 8, json 6 |
| 942431 | 751 | 0 | 0 | 751 | 0 |  |  |
| 942430 | 582 | 0 | 0 | 582 | 0 |  |  |
| 932240 | 541 | 500 | 0 | 41 | 0 | dtPC, _gcl_gs, utag_main | plain 174, kv-packed 86, json 20 |
| 931130 | 508 | 0 | 0 | 508 | 0 |  |  |
| 932236 | 415 | 353 | 0 | 62 | 0 | OptanonConsent, __utmzz, __eoi | kv-packed 199, plain 70, url-encoded 3 |
| 942460 | 397 | 0 | 0 | 397 | 0 |  |  |
| 932200 | 357 | 236 | 0 | 121 | 0 | dataservices_product_context, checkout_session_token__cn__Z2NwLWV1cm9wZS13ZXN0MTowMUpBNjVRVlFK, checkout_session_token__cn__Z2NwLXVzLWNlbnRyYWwxOjAxSkEzNUFXTUZZ | json 46, kv-packed 42, plain 11 |
| 932331 | 288 | 286 | 0 | 2 | 0 | __cq_seg, _dy_soct, user | plain 244 |
| 932350 | 222 | 9 | 0 | 213 | 0 | __gads, SRCHUSR, dt_gender | plain 2 |
| 942520 | 215 | 162 | 0 | 53 | 0 | channelAttributionData, _hp5_meta.913210224, _hp2_ses_props.1621830767 | json 116, kv-packed 8, json-like 3 |
| 942440 | 200 | 0 | 0 | 0 | 200 |  |  |
| 932190 | 151 | 0 | 0 | 151 | 0 |  |  |
| 942120 | 122 | 0 | 0 | 122 | 0 |  |  |
