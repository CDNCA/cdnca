# 系统文档

本文档集描述仓库在 2026-07-23 的当前实现，不把目标架构或已冻结契约
等同于已经上线的能力。功能完成度仍以
[`docs/parity-matrix.md`](../parity-matrix.md) 的测试和验收证据为准。

## 阅读顺序

1. [架构与信任边界](architecture-and-trust.md)：四个控制端、数据面和故障边界。
2. [安装与配置](installation-and-configuration.md)：本地基础设施、服务配置、
   Kubernetes 和 Edge Agent 入口。
3. [运行与恢复](operations.md)：健康检查、迁移、备份、升级和专题运行手册索引。
4. [API 文档](../api/README.md)：当前 OpenAPI、gRPC、认证和错误约定。
5. [开发者文档](../developer/README.md)：API、插件、Webhook 和契约检查。

## 权威来源

| 内容 | 权威来源 |
| --- | --- |
| HTTP 字段、路径、认证与响应 | [`api/openapi/v1`](../../api/openapi/v1/) |
| Agent 和内部 gRPC wire contract | [`proto`](../../proto/) |
| 运行配置和默认值 | 各服务配置代码、Helm values 和打包配置 |
| 数据迁移 | 各服务 `migrations` 目录 |
| 操作步骤和失败恢复 | [`docs/runbooks`](../runbooks/) |
| 当前完成度 | [`docs/parity-matrix.md`](../parity-matrix.md) |

文档与契约冲突时，以机器可读契约和当前实现为准，并在同一变更中修正文档。
目标能力尚未接线时，本文使用“未实现”“仅契约”或“仅内核”标记。
