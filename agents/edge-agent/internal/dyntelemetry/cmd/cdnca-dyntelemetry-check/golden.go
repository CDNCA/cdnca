package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyntelemetry"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/siteindex"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// goldenFacts is the part of the access-logs scenario's site runtime document
// this check maps to a site object (the scenario has one site, one listener,
// one WAF policy, one origin).
type goldenFacts struct {
	ConfigurationScopeID string `json:"configuration_scope_id"`
	ConfigVersionID      string `json:"config_version_id"`
	Sites                []struct {
		ID        string   `json:"id"`
		Revision  int64    `json:"revision"`
		Domains   []string `json:"domains"`
		Listeners []struct {
			Port     int `json:"port"`
			Security struct {
				Policies []edgeconfig.SecurityPolicy `json:"policies"`
			} `json:"security"`
		} `json:"listeners"`
		OriginPools []struct {
			Origins []struct {
				Host string `json:"host"`
				Port int    `json:"port"`
			} `json:"origins"`
		} `json:"origin_pools"`
	} `json:"sites"`
}

func checkGolden(n *node) {
	ctx := context.Background()
	scenario, err := edgegolden.LoadScenario(filepath.Join(*golden, "scenarios", "access-logs.json"))
	if err != nil {
		check("golden-scenario", false, "%v", err)
		return
	}
	expected, found, err := edgegolden.ReadObservation(filepath.Join(*golden, "expected"), "access-logs")
	if err != nil || !found {
		check("golden-expected", false, "%v found=%v", err, found)
		return
	}
	var facts goldenFacts
	if err := json.Unmarshal(scenario.Facts.Document, &facts); err != nil || len(facts.Sites) != 1 {
		check("golden-facts", false, "%v", err)
		return
	}
	fact := facts.Sites[0]
	listener := fact.Listeners[0]
	origin := fact.OriginPools[0].Origins[0]
	tenant := scenario.Facts.Telemetry.TenantID
	site := baseSite(facts.ConfigurationScopeID, tenant, fact.ID, fact.Revision, fact.Domains[0], fact.Domains[1:],
		fmt.Sprintf("%s:%d", origin.Host, origin.Port), listener.Port)
	site.Telemetry.PackageSubscriptionID = scenario.Facts.Telemetry.Subscriptions[fact.ID]
	writePlan(fact.ID, listener.Security.Policies)
	stopOrigin := startOrigin(fmt.Sprintf("%s:%d", origin.Host, origin.Port), scenario.Origins[0].Name,
		map[string]int{"/missing": 404}, map[string]string{"/missing": "nf"})
	defer stopOrigin()
	n.versions = map[string]string{facts.ConfigurationScopeID: facts.ConfigVersionID}
	activation, err := n.activator.Activate(ctx, []siteindex.Object{encode(site)})
	check("golden-activate", err == nil, "gen %d %v", activation.Generation, err)
	if err != nil {
		return
	}
	// The scenario's steps, as the golden runner sends them.
	for _, step := range scenario.Steps {
		if step.Kind == "logs" {
			continue
		}
		method := step.Method
		if method == "" {
			method = "GET"
		}
		send(step.Port, step.Host, method, step.Path, step.Headers, step.Body)
	}
	// Unknown Host and node location on the same port: never logged.
	unknown := send(listener.Port, "nope.example.test", "GET", "/x", nil, "")
	probe := send(listener.Port, "nope.example.test", "GET", "/.well-known/cdnca-market-probe", nil, "")
	check("golden-unknown-host", unknown == 421 && probe == 204, "unknown %d probe %d", unknown, probe)
	time.Sleep(300 * time.Millisecond)

	sites := n.sites()
	var records []edgegolden.LogRecord
	for _, stream := range []string{"access", "security"} {
		for _, line := range n.lines(stream) {
			result, err := dyntelemetry.Normalize(line, n.registry, sites, nodeID)
			if err != nil {
				check("golden-normalize", false, "%s: %v\n%s", stream, err, line)
				continue
			}
			// The v7 tailer source line is what the golden records.
			fields := map[string]any{}
			decoder := json.NewDecoder(bytes.NewReader(result.Line))
			decoder.UseNumber()
			_ = decoder.Decode(&fields)
			// upstream_addr (fix-upstreamaddr) is newer than the v7 golden
			// (compare.json semantic change); checked by "upstream-addr".
			delete(fields, "upstream_addr")
			records = append(records, edgegolden.LogRecord{Stream: stream, Fields: mask(scenario, fields)})
		}
	}
	var want []edgegolden.LogRecord
	for _, step := range expected.Steps {
		if step.Kind == "logs" {
			want = step.Logs
		}
	}
	check("golden-line-count", len(records) == len(want), "dynamic %d v7 %d", len(records), len(want))
	differences := 0
	for index := range min(len(records), len(want)) {
		got, _ := json.Marshal(records[index])
		exp, _ := json.Marshal(normalizeNumbers(want[index]))
		if !bytes.Equal(got, exp) {
			differences++
			fmt.Printf("  line %d differs:\n    v7      %s\n    dynamic %s\n", index, exp, got)
			for _, key := range diffKeys(want[index].Fields, records[index].Fields) {
				fmt.Printf("    field %s: v7 %v dynamic %v\n", key, want[index].Fields[key], records[index].Fields[key])
			}
		}
	}
	check("golden-fields-identical", differences == 0 && len(records) == len(want), "%d differing lines", differences)
	// The raw line before normalization: v7 fields + attribution only.
	if err := os.WriteFile(filepath.Join(*stateRoot, "golden-observed.json"), mustJSON(records), 0o644); err == nil {
		fmt.Printf("  observed records written to %s\n", filepath.Join(*stateRoot, "golden-observed.json"))
	}
}

// mask applies the scenario's (and the runner's default) log masks.
func mask(scenario *edgegolden.Scenario, fields map[string]any) map[string]any {
	masked := map[string]any{}
	for key, value := range fields {
		if contains(scenario.Mask.LogFields, key) || contains(edgegolden.DefaultMask.LogFields, key) {
			masked[key] = "<masked>"
			continue
		}
		masked[key] = value
	}
	return masked
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

// normalizeNumbers re-encodes a golden record through the same decoder.
func normalizeNumbers(record edgegolden.LogRecord) edgegolden.LogRecord {
	raw, _ := json.Marshal(record.Fields)
	fields := map[string]any{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	_ = decoder.Decode(&fields)
	return edgegolden.LogRecord{Stream: record.Stream, Fields: fields}
}

func diffKeys(left, right map[string]any) []string {
	keys := map[string]bool{}
	for key := range left {
		keys[key] = true
	}
	for key := range right {
		keys[key] = true
	}
	var result []string
	for key := range keys {
		a, _ := json.Marshal(left[key])
		b, _ := json.Marshal(right[key])
		if !bytes.Equal(a, b) {
			result = append(result, key)
		}
	}
	sort.Strings(result)
	return result
}

func mustJSON(value any) []byte {
	raw, _ := json.MarshalIndent(value, "", " ")
	return raw
}
