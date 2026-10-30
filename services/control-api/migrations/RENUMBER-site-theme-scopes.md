# 467_site_theme_scopes 改号说明（主题插件 C）

## 当前状态（merge-c-theme，10-24）

- 已定号 467：文件 `467_site_theme_scopes.{up,down}.sql`、`site_theme_scopes_467_{contract,integration}_test.go`，错误码 P4670–P4674，对象后缀 `_467`。
- 基线 merge7 只到 `464_impersonation_direct_switch`；merge8 占 465（cname-retry3）和 466（site-backend6）。守卫前一版写 466。
- **466 是占位**：`PreviousID` 暂写 `466_site_edge_options`（origin 上 site-backend6 的迁移此时仍叫 `460_site_edge_options`，未改号），`PreviousUpSHA`=`0…01`、`PreviousDownSHA`=`0…02`。
- 在 465/466 进来之前，本分支的连号测试 `TestEmbeddedMigrationsAreContiguousAndPaired` 与 control PG 迁移测试必然失败（gap 465）。

### 合入 merge8 之后要做

1. 核对 466 的真实 ID（`ls services/control-api/migrations/466_*.up.sql`），并取 `shasum -a 256 466_<name>.up.sql 466_<name>.down.sql`。
2. 在 `467_site_theme_scopes.up.sql` 守卫里替换 `migration_id='466_site_edge_options'`、`checksum_sha256='0…01'`、`down_checksum_sha256='0…02'`。
3. 在 `site_theme_scopes_467_contract_test.go` 的 const 块里同步 `PreviousID`、`PreviousUpSHA`、`PreviousDownSHA`，重算 `UpSHA`（down 不变）。
4. 跑 `go test -count=1 ./migrations/ ./internal/database/`，以及 PG：`./migrations/ -run SiteThemeScopes`、`./internal/controlsite/`、`./internal/theme/`。

## 以下是 466 时的原说明（留档）

466 是占位号（BATCH 第 73 条：461 归 esc-gw，C 方案用 ≥466）。守卫暂时指向分支编号时集成头上的最高迁移 `459_tenant_system_role_grants`。在 460–465 进集成之前，加载器会报 `migration version gap: expected 460, found 466`（`internal/database` 的 `TestEmbeddedMigrationsAreContiguousAndPaired`），所以本分支不能单独上 PG 跑。

## 编号约定

- 错误码跟着编号走：`P<版本>0` 是 up 守卫，`P<版本>1` 是 admin 位只收官方主题，`P<版本>2` 是 site 位只收适用于官网的插件，`P<版本>3` 是 down 守卫，`P<版本>4` 是 down 时有只有本迁移能存的数据。现在是 P4660–P4664，原来是 P4610–P4614。
- 数据库对象带版本后缀：`theme_activations_slot_<版本>`（索引和触发器）、`validate_theme_activation_slot_<版本>()`、`site_theme_packages_scopes_<版本>`、`site_theme_packages_shape_<版本>`、`validate_site_theme_activation_<版本>()`、`site_theme_activations_scope_<版本>`。Go 代码不引用这些名字。

## merge7（460–464）和 465 合入后要改的地方

假设最终编号是 N，前一版是 N-1（`<prev_id>`）。

1. 文件名：`466_site_theme_scopes.{up,down}.sql`、`site_theme_scopes_466_{contract,integration}_test.go`。
2. `466_site_theme_scopes.up.sql`：
   - `$migration_466_up$`；
   - 守卫里的 `count(*) <> 459`、`max(version) <> 459`、`version=459 AND`；
   - `migration_id='459_tenant_system_role_grants'`；
   - 前一版的 `checksum_sha256` 和 `down_checksum_sha256`（取 `<prev_id>` 当前文件的 sha256）；
   - 文案 `migration 466 requires the exact verified 459 release head`；
   - 错误码 P4660–P4662；
   - 上面列的对象后缀 `_466`，以及注释里的 466。
3. `466_site_theme_scopes.down.sql`：
   - `$migration_466_down$`；
   - `count(*)`、`max(version)`、`version=` 三处的 466；
   - `migration_id='466_site_theme_scopes'`；
   - 错误码 P4663、P4664；
   - 对象后缀 `_466`。
4. `site_theme_scopes_466_contract_test.go`：const 块里的 `migration466Version`、`ID`、`PreviousVersion`、`PreviousID`、`PreviousUpSHA`、`PreviousDownSHA`、`UpSHA`、`DownSHA`，标识符里的 466（`migration466*`、`errcode466`、`TestSiteThemeScopes466Contract`）。上一版编号写在 const 块上方的注释里，改号时追加一条。
5. `site_theme_scopes_466_integration_test.go`：`const version, previous = 466, 459`，`want P466x` 和 `"P466x"`，以及测试名。

## 用仓库脚本改号

`scripts/ri-wire/renumber-control.py` 会改 SQL 文件名、`$migration_N_*$`、`ERRCODE='P<N>x'`（只认无空格写法）、守卫前一版的版本号、ID、两个校验和，以及 `migration N` 文案：

```bash
python3 scripts/ri-wire/renumber-control.py <repo> 466_site_theme_scopes <N> <prev_id>
# 例：python3 scripts/ri-wire/renumber-control.py "$PWD" 466_site_theme_scopes 465 464_xxx
```

它不会改下面这些，需要手动补，或者用 `sed -i 's/_466\b/_<N>/g; s/P466\([0-9]\)/P<N>\1/g; s/\b466\b/<N>/g'` 处理两个 SQL 文件：

- 带空格写法的 `ERRCODE = 'P4661'` 和 `'P4662'`；
- 对象后缀 `_466`；
- 注释里的 466；
- 两个测试文件的改名和内容（`git mv` 加上第 4、5 步）。

改完以后，在 `services/control-api` 下跑：

```bash
shasum -a 256 migrations/<N>_site_theme_scopes.*.sql   # 回填 const 块的 UpSHA / DownSHA
go build ./... && go test -count=1 ./migrations/ ./internal/database/
```

## 改号后必须跑的 PG 包

`./migrations/`（`-run SiteThemeScopes`）、`./internal/controlsite/`、`./internal/theme/`。改号后还要重算 control.yaml 的钉值。
