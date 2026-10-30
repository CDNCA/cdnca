package nodemetrics

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
)

func TestMonitoringReaderCapability(t *testing.T) {
	if _, ok := reflect.TypeOf((*PostgresReader)(nil)).MethodByName("MonitoringLatest"); !ok {
		t.Fatal("probe-only monitoring snapshot capability is missing; host latest is not probe evidence")
	}
}

func TestMonitoringSampleClassification(t *testing.T) {
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	active, activatedAt := int64(7), now.Add(-time.Minute)
	configuration := systemconfig.MonitoringConfiguration{State: "active", HeadRevision: 8, ActiveRevision: &active,
		ActivatedAt: &activatedAt, Policy: &systemconfig.MonitoringPolicy{Enabled: true, ProbeIntervalMS: 10000, ProbeTimeoutMS: 3000}}
	baseline := MonitoringProbeSample{Source: "agent_local_tcp", ConfigRevision: 7, ActiveConfigRevision: 7,
		PublicationSequence: 1, ObservedAt: now, IngestedAt: now, ProbePort: 80}
	for _, test := range []struct {
		name, freshness, revision                                               string
		age                                                                     time.Duration
		noSample, noActive, oldRevision, beforeActivation, rolledBack, disabled bool
	}{
		{name: "no sample", noSample: true, freshness: "not_reported", revision: "unknown"},
		{name: "probe not load known", freshness: "fresh", revision: "current"},
		{name: "fresh inclusive edge", age: 43 * time.Second, freshness: "fresh", revision: "current"},
		{name: "expired", age: 43*time.Second + time.Nanosecond, freshness: "stale", revision: "current"},
		{name: "allowed clock margin", age: -5 * time.Second, freshness: "fresh", revision: "current"},
		{name: "future", age: -5*time.Second - time.Nanosecond, freshness: "clock_skew", revision: "current"},
		{name: "old config", oldRevision: true, freshness: "fresh", revision: "different"},
		{name: "before activation", beforeActivation: true, freshness: "stale", revision: "different"},
		{name: "rollback dominates", rolledBack: true, freshness: "fresh", revision: "rolled_back"},
		{name: "no active", noActive: true, freshness: "stale", revision: "unknown"},
		{name: "no active no sample", noActive: true, noSample: true, freshness: "not_reported", revision: "unknown"},
		{name: "old rollback", noActive: true, rolledBack: true, freshness: "stale", revision: "rolled_back"},
		{name: "disabled is not ack", disabled: true, freshness: "fresh", revision: "current"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, sample := configuration, baseline
			policy := *configuration.Policy
			config.Policy = &policy
			sample.ObservedAt = now.Add(-test.age)
			if test.noActive {
				config = systemconfig.MonitoringConfiguration{State: "unconfigured"}
			}
			if test.oldRevision {
				sample.ConfigRevision--
			}
			if test.beforeActivation {
				sample.ObservedAt = activatedAt.Add(-time.Nanosecond)
			}
			if test.rolledBack {
				sample.RolledBack = true
				sample.ConfigRevision++
			}
			if test.disabled {
				config.Policy.Enabled = false
			}
			item := MonitoringItem{NodeID: uuid.New(), Sample: &sample}
			if test.noSample {
				item.Sample = nil
			}
			classifyMonitoringSample(&item, config, now)
			if item.Freshness != test.freshness || item.RevisionState != test.revision || (item.StaleAfterMS == nil) != test.noActive || item.StaleAfterMS != nil && *item.StaleAfterMS != 43000 {
				t.Fatalf("wrong classification: %+v", item)
			}
		})
	}
	configuration.Policy.ProbeIntervalMS, configuration.Policy.ProbeTimeoutMS = 300000, 60000
	item := MonitoringItem{NodeID: uuid.New()}
	classifyMonitoringSample(&item, configuration, now)
	if item.StaleAfterMS == nil || *item.StaleAfterMS != 390000 {
		t.Fatal("maximum policy stale threshold changed")
	}
}

func TestMonitoringSampleValidation(t *testing.T) {
	valid := MonitoringProbeSample{Source: "agent_local_tcp", ConfigRevision: 7, ActiveConfigRevision: 7,
		PublicationSequence: math.MaxInt64, ObservedAt: time.Now().UTC(), IngestedAt: time.Now().UTC(),
		ProbePort: 80, ProbesTotal: math.MaxInt64, ProbeFailuresTotal: 9007199254740993}
	if !validMonitoringSample(valid) {
		t.Fatal("valid int64 probe rejected")
	}
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	for _, exact := range []string{`"publication_sequence":"9223372036854775807"`, `"probes_total":"9223372036854775807"`, `"probe_failures_total":"9007199254740993"`} {
		if !strings.Contains(string(raw), exact) {
			t.Fatalf("lossy integer JSON: %s", raw)
		}
	}
	for _, mutate := range []func(*MonitoringProbeSample){
		func(s *MonitoringProbeSample) { s.Source = "host_metric" },
		func(s *MonitoringProbeSample) { s.ConfigRevision = 0 },
		func(s *MonitoringProbeSample) { s.ActiveConfigRevision = 1 << 53 },
		func(s *MonitoringProbeSample) { s.ConfigRevision = 1 << 53 },
		func(s *MonitoringProbeSample) { s.PublicationSequence = 0 },
		func(s *MonitoringProbeSample) { s.PublicationSequence = math.MaxInt64 + 1 },
		func(s *MonitoringProbeSample) { s.ProbePort = 0 },
		func(s *MonitoringProbeSample) { s.ObservedAt = time.Time{} },
		func(s *MonitoringProbeSample) { s.IngestedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
		func(s *MonitoringProbeSample) { s.ConsecutiveFailures = 21 },
		func(s *MonitoringProbeSample) { s.ConsecutiveFailures, s.ConsecutiveSuccesses = 1, 1 },
		func(s *MonitoringProbeSample) { s.ProbesTotal = math.MaxInt64 + 1 },
		func(s *MonitoringProbeSample) { s.ProbeFailuresTotal = s.ProbesTotal + 1 },
		func(s *MonitoringProbeSample) { s.Recovered = true },
		func(s *MonitoringProbeSample) { s.RolledBack = true },
	} {
		changed := valid
		mutate(&changed)
		if validMonitoringSample(changed) {
			t.Fatalf("corrupt sample accepted: %+v", changed)
		}
	}
	valid.ConfigRevision, valid.ActiveConfigRevision, valid.RolledBack = 8, 7, true
	if !validMonitoringSample(valid) {
		t.Fatal("actual rollback evidence rejected")
	}
	for _, source := range []string{"agent_local_http", "agent_local_ping"} {
		valid.Source = source
		if !validMonitoringSample(valid) {
			t.Fatalf("%s probe evidence rejected", source)
		}
	}
}
