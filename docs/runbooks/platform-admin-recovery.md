# 主控平台管理员本地恢复

仅用于失去登录能力时，对**已经存在且仍为 active 的平台 platform_owner** 改名及更换密码。此命令不创建用户、不提升权限、没有 HTTP 入口；只能由 Linux 上真实 UID 和有效 UID 均为 0 的本地进程执行。

## 执行前

- 使用已推送精确 commit 构建、来源和哈希已验证的 `control-api`。可以单独运行候选二进制的恢复子命令，不要为恢复账号替换正在运行的服务。
- 使用主控既有、受保护的 `DATABASE_URL` 运行配置；不要输出配置或复制数据库凭据到命令历史。命令不负责迁移数据库。
- 只读核实用户 ID、平台 scope ID、旧用户名、当前 revision、账号与 membership 均为 active，且仍有同 scope 的系统角色 `platform_owner`。不能仅凭用户名定位，更不能读取或手工修改密码哈希。
- 为这次操作生成并记录一个新的标准 UUID request ID，以及非秘密的目标和 CAS 条件。旧 revision 不应猜测。
- 密码按统一密码规则：8–1024 位，至少包含大写字母、小写字母、数字、符号（英文可见符号）中的两种，不能含空格、中文、全角等非 ASCII 字符（`libs/passwordpolicy`，用户 2026-10-26 决定）；NUL、回车及换行自然被拒。不要将密码放入参数、环境变量、文件、脚本、日志、命令历史或 `echo`/`printf` 参数。

## 交互恢复

以下为模板，替换非秘密的占位值后执行。密码在控制终端输入两次，不回显；没有控制终端时拒绝执行。

```sh
/absolute/path/to/verified/control-api recover-platform-admin \
  --user-id 'USER_UUID' \
  --scope-id 'PLATFORM_SCOPE_UUID' \
  --request-id 'REQUEST_UUID' \
  --expected-username 'OLD_USERNAME' \
  --expected-revision 'CURRENT_REVISION' \
  --new-username 'NEW_USERNAME'
```

受控自动化可以增加 `--password-stdin`，从仅在内存中持有秘密的调用方通过匿名管道写入密码并关闭管道。可有一个末尾换行；多行、普通文件重定向、命名 FIFO 均拒绝。不要使用 shell 字面量示例传递密码。stdin 若是终端仍使用不回显的双次确认。

## 事务与结果

改名、Argon2id 哈希替换、用户 revision 加一、该用户**所有 scope 的旧会话撤销**和 `identity.platform_admin.recover` 安全审计在同一事务提交。审计失败整体回滚。登录和刷新共用 IAM 全局排他锁：先完成的会话在恢复中撤销，后到的旧密码登录/旧 refresh 被拒绝。

用户 ID、邮箱、membership、角色/权限、MFA 凭据和恢复码、API keys 不变。恢复不绕过 MFA，也不吊销 API keys；用户须使用新用户名/密码重新登录，并继续满足原有 MFA 与登录安全策略。

成功输出 JSON `status: committed` 和不含秘密的回执。请求为单次 CAS 操作：同 request ID 再执行不会再次改密，而返回 `platform_recovery_request_already_used_check_status`。旧用户名或 revision 不符、scope/角色不符或禁用账号返回 `platform_recovery_precondition_failed`；用户名冲突返回 `platform_recovery_username_conflict`，均无部分修改。

## 断线、超时或输出失败后回查

不要直接发起第二次恢复，也不要自行递增 revision 绕过 CAS。保持原 target 和 request ID，先确认原进程已结束，再运行只读状态命令（不读取密码）：

```sh
/absolute/path/to/verified/control-api recover-platform-admin \
  --user-id 'USER_UUID' \
  --scope-id 'PLATFORM_SCOPE_UUID' \
  --request-id 'REQUEST_UUID' \
  --status
```

- `committed`：事务已提交，返回原安全审计回执；不要重置第二次。
- `not_found`：当前未读到该目标的已提交回执。原进程仍运行时，这**不代表**它稍后不会提交。只有确认原进程结束、数据库可读且再次核实原 CAS 条件后，才可用**原 request ID 和原条件**重试。
- `platform_recovery_unavailable_check_status`：数据库、锁、审计或提交结果不可确认；仍按未知结果处理，先恢复只读回查能力。命令不输出原始数据库错误。

完成后保存非秘密回执和来源证明，检查旧访问令牌/刷新会话已失效及新凭据登录。真实账号执行、Linux UID/EUID 门禁、真实登录和 MFA 的验收，应分别记录，不能用单元测试替代生产执行证据。
