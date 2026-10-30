package main

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

type correlationAlertFile struct {
	Groups []struct {
		Name  string `json:"name"`
		Rules []struct {
			Alert       string            `json:"alert"`
			Expr        string            `json:"expr"`
			For         string            `json:"for"`
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations"`
		} `json:"rules"`
	} `json:"groups"`
}

func TestCorrelationObservabilityProductionContract(t *testing.T) {
	template := readCorrelationContractFile(t, "../../../../infra/helm/cdnca/templates/agent-gateway-observability.yaml")
	for _, required := range []string{
		"kind: Service", "prometheus.io/scrape", "targetPort: health",
		"kind: NetworkPolicy", "cdnca.io/metrics-access",
		`.Capabilities.APIVersions.Has "monitoring.coreos.com/v1/ServiceMonitor"`,
		"kind: ServiceMonitor", `.Capabilities.APIVersions.Has "monitoring.coreos.com/v1/PrometheusRule"`,
		"kind: PrometheusRule", `.Files.Get "files/agent-gateway-correlation-rules.json"`,
	} {
		if !strings.Contains(template, required) {
			t.Fatalf("Helm observability template is missing %q", required)
		}
	}

	rawRules := readCorrelationContractFile(t, "../../../../infra/helm/cdnca/files/agent-gateway-correlation-rules.json")
	var document correlationAlertFile
	if err := json.Unmarshal([]byte(rawRules), &document); err != nil {
		t.Fatalf("parse correlation alert rules: %v", err)
	}
	if len(document.Groups) != 1 || document.Groups[0].Name != "cdnca-agent-gateway-correlation" || len(document.Groups[0].Rules) != 4 {
		t.Fatalf("correlation alert groups = %+v", document.Groups)
	}
	wantAlerts := map[string]bool{
		"CDNCAAgentGatewayCorrelationMetricsAbsent":    false,
		"CDNCAAgentGatewayCorrelationPublishFailures":  false,
		"CDNCAAgentGatewayCorrelationMetadataRejected": false,
		"CDNCAEdgeActivationFailureRatioHigh":          false,
	}
	metricPrefix := "cdnca_agent_gateway_correlation_"
	chinese := regexp.MustCompile(`[\x{4e00}-\x{9fff}]`)
	for _, rule := range document.Groups[0].Rules {
		if _, exists := wantAlerts[rule.Alert]; !exists {
			t.Fatalf("unexpected correlation alert %q", rule.Alert)
		}
		wantAlerts[rule.Alert] = true
		if rule.Expr == "" || rule.For == "" || rule.Labels["severity"] == "" ||
			!strings.Contains(rule.Expr, metricPrefix) || strings.Contains(rule.Expr, "{") ||
			!chinese.MatchString(rule.Annotations["summary"]) || !chinese.MatchString(rule.Annotations["description"]) {
			t.Fatalf("unsafe or incomplete correlation alert %+v", rule)
		}
	}
	for alert, found := range wantAlerts {
		if !found {
			t.Fatalf("missing correlation alert %s", alert)
		}
	}

	runbook := readCorrelationContractFile(t, "../../../../docs/runbooks/edge-correlation-observability.md")
	for _, required := range []string{
		"CORRELATION_OK", "CORRELATION_REPLAYED", "CORRELATION_METADATA_REJECTED",
		"CORRELATION_PUBLISH_FAILED", "EDGE_ACTIVATION_SUCCEEDED", "EDGE_ACTIVATION_FAILED",
		"OpenTelemetry Collector", "Prometheus receiver", "cdnca.io/metrics-access",
	} {
		if !strings.Contains(runbook, required) {
			t.Fatalf("correlation runbook is missing %q", required)
		}
	}
}

func readCorrelationContractFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
