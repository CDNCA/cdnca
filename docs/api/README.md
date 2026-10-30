# API 文档

## 当前契约集

<!-- generated:openapi-counts:begin -->
| 文件 | 版本 | operation 数 | 范围 |
| --- | --- | ---: | --- |
| [`control.yaml`](../../api/openapi/v1/control.yaml) | 0.1.0 | 895 | 客户主控身份、账户、账务、套餐商业、节点、分析、任务、站点发布、缓存与安全 |
| [`dns-acme.yaml`](../../api/openapi/v1/dns-acme.yaml) | 0.1.0 | 41 | DNS provider、zone、record 和证书订单基础契约 |
| [`license.yaml`](../../api/openapi/v1/license.yaml) | 0.8.0 | 208 | Operator、许可证、发布、插件供应链、签名者撤销、平台策略和安装接口 |
| [`sites.yaml`](../../api/openapi/v1/sites.yaml) | 0.1.0 | 22 | 网站、源站、锁定和批量动作 |
<!-- generated:openapi-counts:end -->

完整 method/path/`operationId` 见 [OpenAPI 索引](openapi-index.md)。索引由
`scripts/verify-developer-docs.sh` 与四份 OpenAPI 双向核对，缺项、多项或映射漂移
都会失败。

按契约跳转：[control.yaml](openapi-index.md#controlyaml)、
[dns-acme.yaml](openapi-index.md#dns-acmeyaml)、
[license.yaml](openapi-index.md#licenseyaml)、[sites.yaml](openapi-index.md#sitesyaml)。

## 使用入口

- [认证、RBAC、幂等、限流与错误](auth-idempotency-errors.md)
- [gRPC service 索引](grpc-index.md)
- [开发者快速开始](../developer/quickstart.md)
- [插件与 Webhook](../developer/plugin-integration.md)
- [契约版本和生成检查](../developer/contract-checks.md)

OpenAPI 和 protobuf 是 wire contract 的唯一事实源。本文不生成另一套字段定义，
也不承诺 OpenAPI 中冻结的 operation 已完成生产接线；当前运行状态见
[`release-status.md`](../developer/release-status.md) 和功能矩阵。
