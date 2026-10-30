# 边缘发布关联与告警

## 目标

一次边缘发布从 Control API 进入事务 outbox 后，`request_id`、可选 `task_id`、W3C `traceparent` 和 `correlation_id` 原样进入 NATS 命令。Agent journal 持久保存完整命令与状态 protobuf，重启重放不会重新生成这些标识；Gateway 只在状态与持久消息及 NATS headers 精确一致时接受重放。

这些标识具有高基数，只能用于日志和追踪查询，禁止作为 Prometheus 标签。`/metrics` 只暴露无标签计数器；`/health/detail` 只暴露计数和稳定结果码，不返回原始标识或内部错误文本。

## 稳定结果码

| 结果码 | 中文含义 | 处置 |
| --- | --- | --- |
| `CORRELATION_OK` | 新状态已持久发布 | 无需操作 |
| `CORRELATION_REPLAYED` | 精确消息已存在，本次按重放返回 | 检查网络抖动或 PubAck 超时，不要重复执行发布 |
| `CORRELATION_METADATA_REJECTED` | 关联信息无效或与持久事实冲突 | 检查生产者契约和版本，禁止手工改写消息 |
| `CORRELATION_PUBLISH_FAILED` | JetStream 查询、发布或 PubAck 校验失败 | 检查 NATS 可用性、stream 和 consumer 配置 |
| `EDGE_ACTIVATION_SUCCEEDED` | 激活或显式回滚已进入成功终态 | 结合 active config identity 确认目标版本 |
| `EDGE_ACTIVATION_FAILED` | 激活或回滚已进入失败终态 | 读取状态中的安全错误码，暂停后续批次并按 LKG 回滚 |

`last_result_code` 只表示当前 Gateway 进程最近一次关联处理结果；趋势和告警必须使用计数器的 `rate()`，不能把它当作集群当前状态。

## Prometheus 与 OpenTelemetry

Helm 始终创建独立 ClusterIP metrics Service，并用 NetworkPolicy 仅允许同命名空间 Pod，以及带 `cdnca.io/metrics-access=true` 标签的监控命名空间访问 health 端口。不要把该 Service 改成 NodePort 或 LoadBalancer。

安装 Prometheus Operator 时，chart 自动创建 `ServiceMonitor` 和 `PrometheusRule`。没有 Operator 时，Prometheus 或 OpenTelemetry Collector 可按 Service annotations 抓取 `/metrics`。OpenTelemetry Collector 使用 Prometheus receiver 采集后，可按部署环境输出到 OTLP：

```yaml
receivers:
  prometheus:
    config:
      scrape_configs:
        - job_name: cdnca-agent-gateway-correlation
          kubernetes_sd_configs:
            - role: endpoints
          relabel_configs:
            - source_labels: [__meta_kubernetes_service_annotation_prometheus_io_scrape]
              regex: "true"
              action: keep
            - source_labels: [__meta_kubernetes_service_annotation_prometheus_io_path]
              target_label: __metrics_path__
exporters:
  otlp:
    endpoint: otel-gateway.monitoring.svc:4317
service:
  pipelines:
    metrics:
      receivers: [prometheus]
      exporters: [otlp]
```

跨命名空间抓取前，给监控命名空间添加 `cdnca.io/metrics-access=true` 标签。生产环境还必须限制谁能修改该 namespace 标签。

## 告警处理

1. 指标缺失：检查 metrics Service endpoints、NetworkPolicy 来源标签和 Gateway health server，不要先重启全部副本。
2. 持久发布失败：确认 `AGENT_DEPLOYMENT_STATUS` stream 可读写、PubAck stream/sequence 有效；故障期间保留 Agent journal，不删除未确认状态。
3. metadata rejected：按协议版本和生产者定位，日志查询可以使用 request/task/trace/correlation，但不得把这些值写入告警标签或通知正文。
4. 激活失败率高：按 rollout、节点和安全错误码查询，暂停后续批次；已有边缘配置继续使用 LKG，不因控制面告警中断流量。
