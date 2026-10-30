package urlauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

var metricReasonNames = []string{
	"signature_valid", "context_unavailable", "listen_port_mismatch", "client_address_invalid",
	"auth_parameters_invalid", "time_window_invalid", "method_invalid", "signature_invalid",
	"replay_state_unavailable", "signature_use_limit", "request_uri_invalid", "path_invalid",
	"query_invalid", "other",
}

type Metrics struct {
	Allow          uint64            `json:"allow"`
	Block          uint64            `json:"block"`
	Error          uint64            `json:"error"`
	ReloadRejected uint64            `json:"reload_rejected"`
	Reasons        map[string]uint64 `json:"reasons"`
}

type MetricAlert struct {
	Code  string
	Delta uint64
}

func DecodeMetricsJSON(raw []byte) (Metrics, error) {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return Metrics{}, invalid("invalid URL auth metrics")
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return Metrics{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var metrics Metrics
	if err := decoder.Decode(&metrics); err != nil {
		return Metrics{}, invalid("decode URL auth metrics: %v", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return Metrics{}, invalid("URL auth metrics have trailing data")
	}
	allowed := make(map[string]struct{}, len(metricReasonNames))
	for _, name := range metricReasonNames {
		allowed[name] = struct{}{}
	}
	for name := range metrics.Reasons {
		if _, ok := allowed[name]; !ok {
			return Metrics{}, invalid("URL auth metrics contain an unknown reason")
		}
	}
	return metrics, nil
}

func (metrics Metrics) Prometheus() string {
	var output strings.Builder
	writeMetric := func(name string, value uint64) {
		output.WriteString(name)
		output.WriteByte(' ')
		output.WriteString(strconv.FormatUint(value, 10))
		output.WriteByte('\n')
	}
	writeMetric("cdnca_url_auth_allow_total", metrics.Allow)
	writeMetric("cdnca_url_auth_block_total", metrics.Block)
	writeMetric("cdnca_url_auth_error_total", metrics.Error)
	writeMetric("cdnca_url_auth_reload_rejected_total", metrics.ReloadRejected)
	for _, reason := range metricReasonNames {
		if value, ok := metrics.Reasons[reason]; ok {
			fmt.Fprintf(&output, "cdnca_url_auth_reason_total{reason=%q} %d\n", reason, value)
		}
	}
	return output.String()
}

func (metrics Metrics) AlertsSince(previous Metrics) []MetricAlert {
	alerts := make([]MetricAlert, 0, 2)
	if metrics.Error > previous.Error {
		alerts = append(alerts, MetricAlert{Code: "URL_AUTH_DEPENDENCY_ERROR", Delta: metrics.Error - previous.Error})
	}
	if metrics.ReloadRejected > previous.ReloadRejected {
		alerts = append(alerts, MetricAlert{Code: "URL_AUTH_RELOAD_REJECTED", Delta: metrics.ReloadRejected - previous.ReloadRejected})
	}
	return alerts
}
