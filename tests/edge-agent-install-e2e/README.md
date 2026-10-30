# Edge Agent 安装升级验收

本目录是 OPS-11 的发行版验收入口。`run.sh` 先执行静态合同，再在 digest 固定的
Debian 12 与 Ubuntu 24.04 基础镜像上分别运行 `linux/amd64`、`linux/arm64`
四个隔离的真实 PID 1 systemd 生命周期，验证：

- Debian 12/systemd 252+ 与 Ubuntu 24.04/systemd 255+；
- Linux 5.10+、cgroup v2 和安装事务所需命令；
- host 与 mixed-version 稳定 reason code；
- 原生 `.deb`、`signed-by` apt 仓库、InRelease、Packages 与 repository provenance
  绑定的双架构 SHA-256；
- 签名、SHA-256、事务回滚、默认卸载保留数据和 systemd sandbox 接线；
- 安装脚本不存在网络 `curl|sh`/`wget|sh` 路径。

```sh
sh tests/edge-agent-install-e2e/run.sh
```

只检查无副作用静态合同：

```sh
sh tests/edge-agent-install-e2e/run.sh static
```

## Round 7 真实矩阵

统一基础设施波次使用全新、digest 固定的 Debian 12 与 Ubuntu 24.04 环境，分别
完成以下同一套场景；不修改宿主 `/etc/os-release`，也不伪造 `systemctl`：

1. 从本地五文件 release bundle 首次安装，核对 UID/GID、目录权限、签名、manifest、
   artifact/SBOM SHA-256；确认安装后默认未启用，完成 enrollment 后显式 enable/start。
2. 重启系统，确认 `multi-user.target` 自动启动、preflight 与稳定健康窗口通过。
3. 通过签名 apt 仓库安装下一 release sequence，确认配置预检、状态备份、原子
   current 切换和健康收敛。
4. 分别注入坏包签名、坏配置和健康失败，确认恢复上一 binary、状态、accepted
   manifest 与 service health。
5. 验证较新 control/Agent protocol minima、较低 release sequence、同 sequence 不同内容
   分别返回稳定 `COMPAT_*` code，且安装目录和服务均无变化。
6. 默认卸载确认 identity/config/state/backups/logs 保留且服务 disabled；随后使用精确 purge
   guard 清除保留数据。

5. 重启整个 systemd 容器，确认 unit 仍为 enabled/active、同一签名版本与状态恢复。

每个组合结束后只删除该任务创建的容器和派生镜像；最终核对任务容器、镜像、网络、
卷、listener、进程、临时目录与 `PPID=1` 孤儿均为 0。基础镜像和构建器属于固定依赖，
不由验收脚本删除。
