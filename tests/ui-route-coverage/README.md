# ui-route-coverage：四端 UI ↔ 后端路由静态对账

只读源码（Go 路由注册、TypeScript AST），不起服务。约 20 秒。

```sh
node tests/ui-route-coverage/cli.mjs --markdown /tmp/ui-routes.md --json /tmp/ui-routes.json   # 全量明细
node tests/ui-route-coverage/cli.mjs --check                                                    # 与白名单比对，CI 用
node --test tests/ui-route-coverage/ui-route-coverage.test.mjs                                  # 夹具单测 + 仓库白名单检查
node tests/ui-route-coverage/gen-allowlist.mjs                                                  # 刷新白名单（保留人工理由）
```

依赖仓库 `pnpm install` 后的 `node_modules/.pnpm/typescript@*`，不新增依赖。

## 输出

| 表 | 含义 |
|---|---|
| ① table1 | 后端有、四端都没调用（没按钮）。机器/节点/安装实例/健康检查/市场上游等按 `lib/classify.mjs` 排除，每类有理由 |
| ①附 proxyGaps | market-service 路由没有授权端代理 forwarded 行（运营端）或主控 member.go 映射（主控） |
| ② table2 | 前端调用了、后端不存在/方法不符/代理 pending；菜单或跳转指向不存在的前端路由 |
| ③ table3 | 前端引用未登记的权限码；页面可见条件与页面调用的接口权限码不相交（读 403 / 写按钮未门控）；接口权限码在前端从未作为显示条件 |
| ④ table4 | 有 `<Route>` 和页面组件，但无菜单、站内跳转或别名指向（孤儿页） |
| ⑤ table5 | 生产代码里的 mock 客户端、`notImplemented` 占位（按钮不发请求） |
| openapiNotServed | `api/openapi/v1/*.yaml` 有、代码没提供的操作 |

## 白名单

`allowlist.json` 逐条登记现存缺口（键不含行号）：`reason` 必填、`owner` 写承接任务。

- 新增路由没有页面、页面调了不存在的接口、新菜单无页面等 → 不在白名单 → 测试失败。修好它，或登记理由。
- 缺口修好后白名单条目变成"过期" → 测试同样失败，提示删除该条（白名单只减不增）。

## 已知局限

- 前端只认同文件内能静态展开的路径（字面量、模板、三元、同文件常量/路径构造函数/转发函数）；跨文件拼接的路径记为 `*` 方法或漏判。
- 权限码从处理器体内 `require*Permission/Authorize/has/Permission:` 等调用静态解析，只跟同包 3 层；解析不到的路由权限码为空，表③不对其判定。
- 表③b"页面作用域"按页面组件函数体与其引用的同文件声明、沿 import 走到组件与 api 文件，遇到其它 `*Page.tsx` 停止。
