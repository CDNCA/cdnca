# 控制面运行时接线审计

## 用途

该工具只做静态验收取证，用来区分包内实现与真实运行接线。`pass` 仅表示某一个检查项具备当前文件快照中的结构证据，不代表领域完成、可发布或已通过真实运行验收。工具不修改业务代码、迁移、OpenAPI、CI 或功能对照矩阵。

审计范围固定为：

- `services/control-api/internal/**`（含嵌套包）的非测试 Go AST；
- `services/control-api/cmd/control-api` 和中心 `internal/httpapi` 的构造、路由、worker 生命周期；
- `services/control-api/migrations` 的 up/down、`go:embed` 和生产迁移器加载链；
- 权威根 `api/openapi/v1/control.yaml`、其本地 `$ref` 链及 `api/*.openapi.yaml` 候选片段的结构化 path、operationId、错误响应与聚合关系；
- 非测试前端 API consumer，以及独立 smoke/e2e 入口。

包内 `_test.go` 只能提供 `test-only` 负向证据，不能证明生产挂载。注释、README 和单纯文件名不会成为运行时证据。runtime 接线只接受从 `cmd/control-api` 入口可达、且调用点本身经 CFG 证明可达的 constructor、handler 或 worker 构造；`if false`、终结语句之后、未调用 `FuncLit` 内的调用和普通外部符号引用均不算接线。已知事务 callback、errgroup/`go` callback、可达 IIFE 和由唯一函数值定义支配调用点的本地闭包才递归采集 call fact。直接或间接 `nil` 只有在可解析 callee 未提供非 nil 安全默认时才判失败；callee 无法解析时为 `unknown`。Noop、placeholder、generated/mock、in-memory 默认依赖仍按 fail-closed 处理。

worker 必须由 `go` 或 errgroup 类受控 goroutine 启动，传入 context，并由 WaitGroup/errgroup 等待后再关闭；同步 `.Run`、只有 `.Run` 字符串或从未等待的 goroutine 都不通过。迁移 current-head 必须同时满足合法 `//go:embed` 指令绑定到类型为 `embed.FS` 的变量、目标 up SQL 命中 embed pattern、可达 `cmd` 迁移入口调用 `database.Migrate`，以及该函数真实读取 `migrations.FS`。注释中的同名文本无效。

OpenAPI 聚合只从权威根 `api/openapi/v1/control.yaml` 的实际 `paths` path-item 节点起步，仅沿 Path Item 顶层结构化本地 `$ref` 解析，并把这些已达 Path Item 的真实 HTTP method operation 记为 canonical inbound operation。`callbacks`、`webhooks`、`components` 和 schema 引用仍会被加载、校验并进入源码哈希，但绝不能把其引用目标提升为入站 operation；未挂到 `paths` 的 `components.pathItems` 也不算聚合。递归时忽略所有 `x-*` vendor extension。visited key 同时包含 document 与 fragment，循环引用会终止，同文档未被引用的 sibling fragment 不算聚合，非权威文档的空 fragment 也不代表其全部 `/paths`。HTTP/HTTPS URI、scheme-relative host、绝对路径、query 或其他非本地引用会使审计失败。每次读取前同时校验 lexical `api` 边界与 realpath `repo/api` 边界，仓内 symlink 不得逃逸后读取仓外文件；经验证的根、引用链和候选片段快照都进入 `source_sha256`。其他文档互相引用不能冒充权威根聚合。

路由只接受可证明为 `net/http.ServeMux` 的注册接收者，包括 `http.NewServeMux()` 本地绑定、`go/types` 精确为 `*http.ServeMux` 的函数参数/结构字段和 `net/http` 包级注册；interface/unknown 初态无效。path 必须来自注册调用第一个参数且存在 handler 参数。自建 CFG 处理 goto、常量 if/switch、循环、return、空 `select{}`、内建 `panic` 和精确 `os.Exit` terminator 及分支，receiver 状态按 types object 区分 shadow，并在所有可达前驱上合流；任一路径缺少有效定义即不生成 route fact，调用后的未来赋值不能反向证明。普通扫描不进入 `FuncLit`；只有 CFG 可达的 IIFE，或由唯一函数值 reaching definition 证明的本地闭包才递归扫描。短声明和 `var` declaration 都按 `go/types.Object` 收集；`if false` 等不可达重绑不参与，调用前可达重绑覆盖旧定义，条件多候选降级，调用后的 future rebind 不反向污染。function/callback alias、ServeMux receiver alias、同步闭包 alias、IIFE 和 `handle := mux.Handle`/`var handle = mux.Handle` method value 的 binding/call target 都先经过同一个 `unwrapParen`，不按分支各自猜测括号语义。

`defer` capture 只有在 receiver 从调度点到退出没有可达写或逃逸，且后续 CFG 无环并在所有路径显式 return 或有限 fallthrough 时才继承调用点状态；非默认 `select`、空 `select{}`、`os.Exit` 和可能无限循环均保守拒绝。defer 函数参数仍按调用时实参 snapshot 单独播种。goroutine capture 仅在 closure entry 全路径可达地 `close(done)` 或发送完成信号，父 CFG 在 go 后全路径到达由 go 支配的直接阻塞 `<-done>` ExprStmt，并且每个采集的 route/call 在 closure CFG 上先于并支配完成信号时保留；signal-before-work、alternate signal、条件 work、select default 和竞争 case 均不算完成证明。明确的 `net/http` package receiver 不依赖可变 capture。闭包真实调用、传出、返回、地址逃逸，或赋给 package/global、selector field、容器及未知 helper 时，只要可能写 receiver 就使证明失效；未调用且未 escape 的本地 mutator closure 不当作已经执行。自定义同名 `Handle`/`HandleFunc`、普通 `/...` 字符串以及只调用其他 handler `ServeHTTP` 的函数都不生成 route fact。同文件多个真实注册会分别绑定各自 handler，不跨函数或 handler 泄漏。

nil 安全默认以 `go/types.Object` 身份而不是变量名证明：同一函数内 `nil` 分支必须给原参数对象赋入确定非 nil 值，该默认定义之前没有携带参数的构造、返回、调用或未知 alias，默认之后也未被 nil/未知值覆盖，并最终流入返回构造。短声明或 if-init 中的同名 shadow 绝不能证明外层参数已默认。默认后的 `FuncLit` 捕获、`&parameter`、指针 alias、字段逃逸或 helper 指针传参均视为无法证明安全；默认前提前返回、未覆盖分支或其他 alias 无法证明时降为 fail/unknown。RBAC 事务复验要求 mutation route 可达、授权调用携带 `pgx.Tx`，并可证明授权实现查询数据库。幂等与审计要求同一个 HTTP 写入口可达请求 header 和事务持久化调用；死 helper 或字符串共现无效。前端只接受等长 path segment 的 exact/template 匹配，不做父路径前缀匹配。

迁移 ownership 只由领域写入表与 migration 静态 `CREATE`/`DROP` 对象的交集证明。最小 SQL lexer 先剔除 `--` 行注释、可嵌套 `/* */` 块注释、普通单引号字符串、PostgreSQL `E'...'` backslash escape，以及普通 `$$`/`$tag$` dollar-quoted 内容；双引号 identifier 作为单独 token，其正文绝不再解释成 keyword。只有未引用的 `CREATE`/`DROP`/`INSERT`/`UPDATE`/`DELETE` keyword token 触发对象解析，支持 `IF EXISTS`/`IF NOT EXISTS`、`CREATE OR REPLACE VIEW`、`CREATE UNLOGGED TABLE`、`INSERT INTO ONLY`、`DELETE FROM ONLY`、schema-qualified 和 quoted identifier，并始终返回末级对象名。语句级 DO 的 E/plain/dollar body 只做保守 token 扫描；DO 内 `EXECUTE` 只有整个表达式为单一 E/plain/dollar literal 且随后直接结束语句时，才用同一 tokenizer 提取 DDL/write object 并进入 `Uncertain`。literal 后出现拼接、cast、helper 或其他表达式 token 一律进入 `GlobalUnknown`。`format(...)` 的首个静态 literal 只有在语句类型为 TABLE/VIEW/FUNCTION/TYPE DDL 或 INSERT/UPDATE/DELETE 时才进入 `GlobalUnknown`；CREATE TRIGGER 等无关动态 DDL不污染 table ownership，变量目标、拼接和不可解析 format 仍 fail-closed。所有动态候选都绝不进入 `Owned` 或直接形成 pass。`ON CONFLICT DO` 与 trigger 的 `EXECUTE FUNCTION` 不属于动态 SQL。判定逐个比较领域 write object：静态 `Owned` 已覆盖的保留；未覆盖 object 命中 `Uncertain`，或同一候选 migration 的 `GlobalUnknown` 可能覆盖剩余 write 时，up/down/current-head 才整体 `unknown`。同文件无关 DO/高级语法不得污染静态 sibling，静态 sibling 也不能掩盖未覆盖的动态对象。未闭合注释/字符串等词法错误仍只污染已解析出的相关对象。文件名不能产生 pass 或 unknown ownership。外键、查询或其他 SQL 仅引用共享表不会继承共享表的迁移。选中可证明的 up 后才按相同版本核对 down 和 current-head。

第十一轮补充证明边界：`panic` 与 `runtime.Goexit` 会终结普通 CFG 但执行已注册 defer，`runtime.Goexit` 后的语句不可达；`os.Exit` 终结且不执行 defer。defer 之后的静态命名函数、包函数和 interface method 不做跨过程“必返回”猜测，无法证明时拒绝；当前窄证明边界只保留内建、类型转换，以及 go/types 精确为 `*net/http.ServeMux` 的 `Handle`/`HandleFunc` 注册原语。被调度的外层 closure 调用本身不算已执行，其实参中的调用仍需单独证明。

`format(...)` 模板中任何未转义 `%s` 都按可注入原始 SQL 处理，即使其前面只有 block/line comment、`CREATE` 或 CTE 前缀也进入 `GlobalUnknown`；`%I`、`%L` 与 `%%` 不单独构成整命令动态证据。该规则优先于上一段按首个静态 SQL token 分类的窄规则。

第十二轮进一步区分求值与调用：`panic(argument)` 只有在全部 argument 求值可证明正常完成，或求值路径以会执行 defer 的 panic/`runtime.Goexit` 终止时，才证明外层 defer 会执行；`GoStmt` 只要求父 goroutine 中 callee 表达式与 arguments 求值完成，不要求新 goroutine 的 callee body 返回。同文件静态 helper 使用 types-object 身份做最多 16 个跨函数 helper hop 的有限证明；AST expression、return 与 body 遍历本身不消耗 hop。证明只接受空 body、纯表达式/赋值、显式 return 与已证明参数的 panic/Goexit；第 17 个 helper、递归、分支、循环、blocking、`os.Exit`、外部函数、跨文件 helper 和未知 method 均保守拒绝。

当 `format(...)` 的模板及全部替换参数都是单一 literal 时，工具支持 `%s`、`%1$s`、多个占位、固定 width/precision、大小写 `FORMAT`、`%I`、`%L` 与 `%%`，并把最多 4096 bytes 的展开结果重新交给同一 SQL lexer 做对象级 `Uncertain` 判定。参数最多 16 个；concat、nested expression、动态 raw `%s`、缺参、无法解析格式或超限都进入 `GlobalUnknown`，不会由静态 sibling 形成 pass。

第十三轮把 receiver 稳定性与 callee 返回性拆成独立证明：defer 调度后，同文件 helper 对 package receiver 的写、concrete method 对 receiver field 的写，以及已执行或逃逸的 factory-returned mutator closure，都会使 route 证明失效；pure helper 与只影响新 goroutine callee 返回性的 blocking body不受此副作用检查误伤。`EXECUTE format('DO %L', dynamic_body)`、`EXECUTE format('EXECUTE %L', dynamic_body)`及其 nested raw-command 形式进入 `GlobalUnknown`，普通 INSERT value 等数据位置的动态 `%L` 保持对象级隔离。静态 format 参数还支持 `NULL`、numeric、boolean、PostgreSQL newline-adjacent string 合并和未被模板引用的额外静态参数；`%s` 分别按空串、数字文本、`t`/`f` 与合并字符串展开，仍受 16 参数和 4096 bytes 上限约束。

## 运行

输出目录必须位于仓库外，并应由调用任务独占。包装脚本连续运行两次，逐字节比较 JSON、Markdown、source/tool manifest 和校验和文件；run-1 后及 run-2 后还会分别用同一份 source manifest 只读复验当前输入：

```sh
audit_out=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-runtime-wiring.XXXXXX")
scripts/runtime-wiring-audit.sh --root "$(git rev-parse --show-toplevel)" --out "$audit_out"
```

结果位于 `$audit_out/run-1/` 和 `$audit_out/run-2/`；每份结果包含 `source-manifest.json` 与 `tool-source-manifest.json`。前者列出所有 audited input（包括 inactive frontend、canonical OpenAPI 根及已加载引用），后者覆盖本工具的全部 task ownership。每个 entry 保存相对路径与文件 SHA-256；`total_sha256` 严格按 C-sort 顺序对每个 `path + NUL + content bytes + NUL` 连续哈希。报告引用两份 manifest 文件本身的字节 SHA-256，并明确标记 `snapshot-at-time`；历史 hash 不代表当前工作树仍可复现。只读复验命令如下，任一路径新增、删除、改字节、变成 symlink 或 manifest 使用非规范路径都会返回 `source manifest stale` 与非零状态，且不会生成报告：

```sh
scripts/runtime-wiring-audit.sh --root "$(git rev-parse --show-toplevel)" \
  --verify-source-manifest "$audit_out/run-1/source-manifest.json"
```

`determinism.sha256` 记录双跑一致的 JSON/Markdown SHA-256。报告不包含源码正文、数据库值、请求日志、域名、IP、账号、余额或密钥，只输出相对文件、symbol/operation 和固定判定说明。

自测命令：

```sh
cd tools/runtime-wiring-audit
GOWORK=off GOPROXY=off go test ./...
GOWORK=off GOPROXY=off go test -race ./...
GOWORK=off GOPROXY=off go vet ./...
cd ../..
sh tests/runtime-wiring-audit/wrapper_test.sh
shellcheck scripts/runtime-wiring-audit.sh tests/runtime-wiring-audit/wrapper_test.sh tests/runtime-wiring-audit/fixtures/project/scripts/samea-smoke.sh
```

fixtures 固定覆盖伪 handler、未注册路由、测试-only mount、自定义 Registry 同名 Handle、未来 ServeMux 赋值、goto 跳过初始化、`if false`/常量 switch 死注册、`panic`/`os.Exit`/空 `select{}` 后注册、未调用闭包、调用点 capture 重绑、defer/local-defer/go 延迟执行后重绑、stable typed/local receiver、defer 参数 snapshot、work-before-close/send、signal-before-work、alternate signal、条件 work、direct receive/`select default`/竞争 case goroutine wait、有限/非终止 defer、未执行 local mutator、package/global/selector/container/helper closure escape、闭包写 receiver、`&mux` alias 写、typed nil IIFE、可达 IIFE/闭包、短声明与 `var` function/transaction/jobs callback alias、统一 parenthesized alias/IIFE/method target、receiver alias、闭包内 receiver alias、method value alias、dead/live/future rebind、package receiver defer/go、typed ServeMux 参数/字段、interface 负例、裸 slash dispatch、死分支 constructor、未调用 constructor/`httpapi.New.Handler` 闭包、外部普通引用、Noop、直接/间接 nil、nil 安全默认、短声明/if-init shadow、默认前提前返回、默认后重置 nil、IIFE/闭包置 nil、地址 alias 和 helper 指针逃逸、generated/mock 默认依赖、OpenAPI-only、嵌套 canonical root、同文档 sibling fragment、未使用 `components.pathItems`、callback-only path ref、`x-*` ref、cycle、HTTP/HTTPS URI、scheme-relative、absolute path、query ref、symlink 逃逸、非根聚合、同文件多真实 dispatch、领域迁移引用共享表、仅文件名匹配的迁移、SQL 注释/普通/E-string/dollar quote/quoted identifier 伪对象、ONLY、CREATE modifier、schema-qualified/quoted/multiple DROP、对象级 Owned/Uncertain 隔离、trigger `EXECUTE FUNCTION`/`ON CONFLICT DO` 非动态语法、DO E-string/EXECUTE 单 literal/动态拼接 GlobalUnknown、reason-code unknown 不扩散、RBAC string-only/DB-less 死 helper、同步 worker/从未启动 worker、幂等与审计死 helper、行尾注释、README、前端 broad-prefix、嵌套 internal、不同包同名 symbol，以及 source manifest 的单文件漂移、新增、删除、Go/OpenAPI symlink 与路径规范化。walker、Go AST 与 OpenAPI YAML/JSON Pointer 任一解析错误都会终止执行，不生成可误用的部分报告。

第十一轮永久 fixture 另覆盖 defer 后静态永久阻塞函数、间接 `os.Exit` helper、interface method、`runtime.Goexit` 后死注册，以及 `format` comment/CREATE/CTE 前缀后的原始 `%s`。

第十二轮永久 fixture 覆盖 panic blocked/exit argument、literal/pure/nested/conversion/builtin argument，GoStmt named/IIFE blocking callee 与 blocked argument，同文件 empty/recursive helper，以及静态/动态/position/width/precision/case/concat/nested/escaped format 边界和展开上限。

第十三轮永久 fixture 覆盖 package shared receiver reset、concrete method field reset、goroutine factory-returned mutator、pure helper 与 blocking GoStmt 正例、16/17 helper hop、动态 `DO %L`/`EXECUTE %L`/nested format、普通数据 `%L`、静态 DO body、NULL/numeric/boolean/newline-adjacent/extra format arguments，以及 16/17 参数和 4096/4097 bytes 边界。

第十四轮对 deferred holder receiver 再收紧一层：已执行 closure 内调用 imported/unknown concrete method 且方法 body 不可得时，只要 receiver root 与已证明的 holder field 路径关联，就不能继续证明 field 中的 ServeMux 稳定；同文件 body 可见且无 receiver 写或逃逸的 pure method 仍可证明。仅解析同文件、单一 `return FuncLit` 的窄 factory 形态；返回 mutator 被赋给 global、selector field、index/container，或传给 helper 时视为逃逸，pure factory 不受影响。静态 PostgreSQL `format` 中 NULL 经 `%s` 展开为空串，经 `%L` 展开为未加引号的 `NULL`，普通字符串 `%L` 继续使用 SQL literal quote；动态 `%L` 的可执行 body 与数据位置边界保持第十三轮规则。

第十八轮永久反例覆盖带 `default` 的非阻塞 `select` 收发、returned/callee receiver alias 的 reaching-definition kill、条件分支 may-alias 和 package receiver 副作用回归。只有 select 顶层通信 receive/send 可按非阻塞处理；send RHS、send channel operand 或 receive channel operand 内嵌的 receive 仍在选择前求值，不能因此豁免。nested IIFE 内调用的外层函数值只有在 reaching definition 唯一、简单 body 可证明返回且返回值 alias 也按同一 CFG 证明传播时才保留 route；真实 alias、递归或超过 helper 深度上限仍保守拒绝。PostgreSQL `format(...)` 在函数名、模板和参数之间允许行注释与可嵌套块注释，并保留跨行静态 literal 合并；跳过动态参数时必须正确处理注释、quoted identifier、圆括号和方括号，不得把表达式内部标点或 literal 误当成后续 `%I` 的静态参数。检查动态 `%L` 前必须按真实的 `%s`、`%I`、`%L` 规则展开已知静态参数，包括位置参数和分片关键字，不能用占位文本丢失 `DO`/`EXECUTE` 执行前缀。未闭合 trivia、静态格式化失败或无法完整跳过的动态表达式仍 fail-closed 为 `GlobalUnknown`。

## 状态语义

- `pass`：该检查项存在生产级结构证据，证据同时带相对文件和 symbol/operation。
- `fail`：该能力有明确意图，但关键运行证据缺失或存在负向证据。
- `unknown`：静态关系不足以判断该包是否需要独立接线；不得升级为完成。
- `not-applicable`：当前结构没有该检查项的适用意图。

JSON 中每个领域固定输出 21 项：核心包、PostgreSQL repository、迁移 up/down/current-head、handler、router mount、依赖与配置接线、OpenAPI path/operation/error/aggregation、RBAC 与事务重检、幂等、审计、worker、outbox、前端 consumer 和 smoke/e2e。

## CI 接线

本任务不修改 CI。主 Agent 回收后可在现有校验 job 中使用 runner 临时目录，并保留 `run-1/report.json`、`run-1/report.md`、两份 manifest、`SHA256SUMS` 和 `determinism.sha256` 为 artifact。CI 应分别执行：

```sh
GOWORK=off GOPROXY=off go test ./...  # cwd: tools/runtime-wiring-audit
GOWORK=off GOPROXY=off go test -race ./...
GOWORK=off GOPROXY=off go vet ./...
sh tests/runtime-wiring-audit/wrapper_test.sh
shellcheck scripts/runtime-wiring-audit.sh tests/runtime-wiring-audit/wrapper_test.sh tests/runtime-wiring-audit/fixtures/project/scripts/samea-smoke.sh
scripts/runtime-wiring-audit.sh --out "$RUNNER_TEMP/runtime-wiring-audit"
scripts/runtime-wiring-audit.sh \
  --verify-source-manifest "$RUNNER_TEMP/runtime-wiring-audit/run-1/source-manifest.json"
```

不要把当前 `fail` 数量设为零门槛，也不要在测试或文档中写死某次 pass/fail/finding 数量；规则收紧和并行产品落盘都会使统计合法变化。主 Agent 应保存独立复核的完整基线 JSON，再按 domain/check 比较既有 `pass` 降级或新增高风险 finding。源文件在两次扫描之间变化会使字节比较失败，这是并行变更保护，不应绕过。

## 主 Agent 回收

1. 先用 `--verify-source-manifest` 对 run-1 清单做只读复验，再核对报告中的 source/tool total hash、manifest 文件 hash 与保存 artifacts；失败说明输入已漂移，应重新审计，不能把历史 hash 称为当前可复现。
2. 抽查最高优先的 `core_package=pass` 且 `runtime_dependency_wiring`、`router_mount` 或 `background_worker=fail` 领域，阅读证据所指 symbol。
3. 保持 OPS-04 announcement、BILL-04 packagecommerce、BILL-09 promotion、signerrevocation、signercheckpoint、plugin example、i18n/UI audit、NODE、CACHE 和 SYSTEMCONFIG 的冲突过滤；不要把建议任务派到这些 ownership。
4. 共享 `cmd/control-api/main.go`、中心 router 与 OpenAPI aggregator 只交给一个 integrator。其余任务只领取报告列出的互不重叠领域包。
5. 接线改动完成后重新生成报告，并结合真实数据库、HTTP、worker shutdown 与浏览器/smoke 验收；静态 `pass` 不能替代这些验证。

GitNexus 在新增审计器文件尚未索引时只能给出 `UNKNOWN` blast radius。重新索引可增强人工导航，但审计判定仍以当前 Go AST、结构化 OpenAPI 和文件快照为准，避免把陈旧图谱当作运行事实。
