# 系统维护升级状态

`GET /v1/admin/maintenance-upgrade-status` 是只读状态接口。主控展示、节点库存和历史升级记录独立查询，历史筛选或翻页不能改变主控当前版本、候选版本及授权状态。完整字段见 `api/control-maintenance-upgrade-status.openapi.yaml`。

## 事实来源与权限

- 主控当前版本来自运行进程嵌入的 `controlVersion`；配置版本只用于报告一致性，不可作为兜底。开发构建无规范版本时返回 `null`。
- `control.build` 可选对象补充构建时嵌入的 `controlSourceCommit`、`controlSourceTree`、`controlBuildTime`，以及启动时读取实际运行程序的 SHA-256。Linux 固定读取 `/proc/self/exe` 对应 inode，不会把已经切换的 `current` 链接当成当前进程；未记录或非法字段返回 `null`。这些事实既不是升级授权，也不能替代制品签名。
- 本地授权来自当前签名租约及平台发布策略。失效、拒绝或不可用时不向授权服务查询候选。
- 候选来自安装身份认证的授权服务只读接口；请求签名绑定方法、路径、安装身份、请求 ID、时间和规范请求体。响应及制品签名均用本地可信公钥校验，包含时间窗和请求绑定校验。
- 候选有效期最多 60 秒；响应前再次检查过期。网络失败、撤回、未知密钥、篡改或版本范围不符均不可启用升级。服务端不向浏览器传递安装私钥、下载 URL、签名或授权凭据。
- 仅平台作用域且具有 `control.upgrades.read` 的当前成员可读；传入节点 ID 时还须有 `nodes.read`。数据库重新检查当前权限，不能仅依靠旧会话。
- 不传参数读取主控；节点批次使用重复 `node_id`，最多 100 个。节点列表按库存游标继续加载，不能把 100 当作总量上限。不存在或跨作用域节点返回 404，重复、非规范 UUID 和未知参数返回 400。

## UI 与执行边界

主控执行状态不再无条件返回一个笼统原因。未配置计划发布服务返回 `control_upgrade_plan_writer_unconfigured`；状态仓库不可读、HA 副本不足、正在 drain、独立执行器未确认分别返回稳定原因。状态探针只调用仓库 `Snapshot`，不得调用会写入副本观测的 `Observe`，也不得启动 runner。计划服务和健康副本不等于独立执行器已经运行；没有对应执行事实仍保持禁用。

启用 `CONTROL_UPGRADE_SYSTEMD_PLAN_SOURCE_ENABLED` 时，计划发布者、协调器与内部计划读取路由使用同一个 PostgreSQL `(installation_id, control-upgrade)` 仓库，而非误走 Kubernetes Secret。发布仍复用签名 bundle、安装身份、当前制品绑定、单调 revision、If-Match 与幂等审计；systemd HA 仍要求至少两个副本和严格多数，不能配置成一个副本冒充无中断升级。完整原生 release 的 standalone 维护模式需独立格式与执行验证，不属于此 HA 门禁的放宽。

节点状态使用已确认版本、会话、在线心跳与已授权能力事实。`eligible=true` 仅表示可以创建预检计划；执行仍走既有 grant、不可变制品、灰度、健康确认和回滚链路，不等于已保证升级成功。

正式 Control API 构建需要同时传入：`-X main.controlVersion=<规范SemVer>`、`-X main.controlSourceCommit=<精确已推送commit>`、`-X main.controlSourceTree=<tree>`、`-X main.controlBuildTime=<UTC RFC3339>`。不得以修改环境变量补写缺失构建版本；候选依旧只来自经过安装身份与签名校验的授权发布服务，不能把本地最新 commit 当成授权最新版本。

`available`、`up_to_date`、`rollback_required` 分别对应候选 SemVer 大于、等于、小于当前版本。不可把“不同版本”统一显示成可升级。页面按到期时间禁用旧候选，权限丢失后不能继续使用已缓存的可升级状态。不可用原因通过简中、繁中和英文资源映射，未知原因显示本地化兜底并保持禁用。

## 验证与发布门槛

回归覆盖运行版本与历史隔离、非法/失效签名、候选过期/降级、权限撤销、节点事实与超过 100 个节点的分页。真实 PostgreSQL 集成必须证明查询没有写入 grant、计划、检查请求或审计；浏览器最终验收在云端执行。只通过单元测试不算部署验收。

本改动跨 Web、Control API、License Service；集成和发布必须记录精确提交与各组件制品，逐组件确认真实运行版本，不可只发布 Web 后宣称链路完成。安装 ES/宝塔模式的展示验收与安装/迁移执行链验收继续单列。
