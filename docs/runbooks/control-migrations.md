# 客户主控数据库迁移

## 文件规则

`services/control-api/migrations` 中的迁移必须使用 `NNN_name.up.sql` 和
`NNN_name.down.sql` 成对命名。编号从 `001` 开始连续递增，名称只使用小写
字母、数字和下划线。同一编号不得重复，up/down 名称必须完全一致。

已发布迁移是不可变制品。需要修正数据库结构时追加下一个连续编号，不得
重命名、改写或在高版本已经应用后回填低编号。

## 执行保证

主控在执行任何 SQL 前完成全部文件校验，并用 PostgreSQL advisory lock 将
同一集群上的迁移串行化。每个 up 脚本及其账本写入位于同一事务；down 每次
只回滚当前最高版本，脚本和账本删除同样位于一个事务。迁移文件不得包含顶
层 `BEGIN`、`START TRANSACTION`、`COMMIT` 或 `ROLLBACK`；加载器在执行前
拒绝这些会破坏 runner 事务边界的控制语句。advisory lock 使用有界上下文释
放；无法确认释放时连接会从池中移除并关闭，避免持锁连接重新入池。

`schema_migrations` 为每个已应用版本记录：

- `migration_id`：不含 `.up.sql` 的规范文件标识；
- `checksum_sha256`：up 文件原始字节的 SHA-256；
- `down_checksum_sha256`：down 文件原始字节的 SHA-256；
- `integrity_state`：`verified` 或 `legacy_unverified`；
- `metadata_recorded_at`：完整性元数据写入时间。

每次 up 或 down 前都会重新比对已应用版本的标识和哈希。缺号、未知版本、
标识变化和内容漂移都会终止迁移，且不会执行待处理 SQL。

## 旧账本兼容边界

旧版账本可能只有 `version` 和 `installed_at`（或 `applied_at`），无法证明
当时执行的 up SQL 字节，也无法证明当时配套的 down SQL。首次运行新版加载
器时，会为这些行记录当前发布包的规范标识、up 哈希和 down 哈希，并永久标
记为 `legacy_unverified`；它不会把这批行误标为 `verified`。只有 up 哈希的过
渡账本在补录 down 基线时也会降为 `legacy_unverified`。后续新迁移仍可执行，
基线建立后的任一方向漂移都会失败关闭。

`legacy_unverified` 行只允许继续向前迁移，禁止自动执行 down。自动 rollback
只接受由当前加载器在 up SQL 与双哈希账本写入的同一事务中创建的 `verified`
行。补录多个遗留版本时，加载器先只读校验全部账本，再在单个事务中写入基
线；任一版本漂移、数据库错误或取消都会使整批补录回滚。

可用以下只读查询审计遗留范围：

```sql
SELECT version, migration_id, checksum_sha256, down_checksum_sha256,
       integrity_state, metadata_recorded_at
FROM schema_migrations
ORDER BY version;
```

`legacy_unverified` 是历史证据缺失，不可通过修改账本消除。需要强证明时，
必须人工审核已归档发布制品、迁移前备份、目标结构和受影响数据，在隔离环
境演练恢复或重建流程；无法取得证据时保留该状态并停止自动 rollback。遇到
哈希不一致时恢复与账本匹配的已发布迁移文件，禁止更新账本哈希、修改状态
或增加 override 开关来绕过检查。
