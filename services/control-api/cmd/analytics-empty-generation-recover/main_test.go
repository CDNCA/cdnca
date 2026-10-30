package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nats-io/nats.go"
)

func TestRecoveryCurrentAcceptsOnlyExactReleaseTargets(t *testing.T) {
	target := "releases/" + strings.Repeat("a", 64)
	for _, actual := range []string{target, filepath.Join(recoveryRoot, target)} {
		if !validRecoveryCurrentTarget(target, actual) {
			t.Fatalf("rejected exact current: %s", actual)
		}
	}
	for _, actual := range []string{"/elsewhere/" + target, "./" + target, target + "/", "releases/" + strings.Repeat("b", 64), "releases/../" + target} {
		if validRecoveryCurrentTarget(target, actual) {
			t.Fatalf("accepted changed current: %s", actual)
		}
	}
}

func TestRecoveryRejectsUnsafePlansAndJSON(t *testing.T) {
	p := recoveryPlan{Schema: "cdnca.analytics-empty-recovery/v1", InstallationID: "db09f72c-f074-403d-aa9b-cfe91c432bcc",
		OldHistory: "5ca7d529-11cc-4c47-b7c9-1fd81d342f3b", Stream: "ANALYTICS_INGEST_V1", Durable: "control_api_analytics_ingest_v1",
		StreamEpoch: 1791470842855461654, OldConsumerEpoch: 1791470843173093373, NewConsumerEpoch: 1791470843173247485,
		NATSVersion: "2.11.4", StateBucket: "AISTATE_2dcd3c381ead92f3", StreamRevision: 1, ConsumerRevision: 2,
		Current: "releases/" + strings.Repeat("a", 64), SourceCommit: strings.Repeat("b", 40), ControlVersion: "1.0.5",
		StreamConfigSHA256: strings.Repeat("c", 64), ConsumerConfigSHA256: strings.Repeat("d", 64), EnvSHA256: strings.Repeat("e", 64)}
	if err := validateRecoveryPlan(p); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*recoveryPlan){
		func(p *recoveryPlan) { p.NewConsumerEpoch = p.OldConsumerEpoch },
		func(p *recoveryPlan) { p.OldConsumerEpoch = p.StreamEpoch - 1 },
		func(p *recoveryPlan) { p.Current = "../../etc" },
		func(p *recoveryPlan) { p.Durable = "other" },
		func(p *recoveryPlan) { p.StateBucket = "wrong" },
		func(p *recoveryPlan) { p.ConsumerRevision = 3 },
		func(p *recoveryPlan) { p.InstallationID = "" },
	} {
		bad := p
		change(&bad)
		if validateRecoveryPlan(bad) == nil {
			t.Fatalf("accepted unsafe plan: %+v", bad)
		}
	}
	for _, data := range []string{`{"schema":"x","schema":"y"}`, `{"unknown":true}`, `{}`, `null`, `[]`, `{} {}`, `{"schema":{"x":1,"x":2}}`} {
		var parsed recoveryPlan
		err := decodeRecoveryJSON([]byte(data), &parsed)
		if err == nil {
			err = validateRecoveryPlan(parsed)
		}
		if err == nil {
			t.Errorf("accepted unsafe JSON %q", data)
		}
	}
	data, _ := json.Marshal(p)
	var parsed recoveryPlan
	if err := decodeRecoveryJSON(data, &parsed); err != nil || parsed != p {
		t.Fatalf("valid round trip: %v", err)
	}
}

func TestRecoveryPrivateFilesAndJournal(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "prepared.json")
	if err := writeRecoveryJournal(path, map[string]string{"state": "prepared"}); err != nil {
		t.Fatal(err)
	}
	var value map[string]string
	if _, err := readPrivateJSON(path, &value); err != nil || value["state"] != "prepared" {
		t.Fatalf("read: %v", err)
	}
	if writeRecoveryJournal(path, value) == nil {
		t.Fatal("overwrote existing journal")
	}
	link := filepath.Join(dir, "symlink")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateJSON(link, &value); err == nil {
		t.Fatal("accepted symlink")
	}
	hard := filepath.Join(dir, "hardlink")
	if err := os.Link(path, hard); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateJSON(path, &value); err == nil {
		t.Fatal("accepted multiply-linked journal")
	}
	if err := os.Remove(hard); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateJSON(path, &value); err == nil {
		t.Fatal("accepted public journal")
	}
}

func TestRecoveryRejectsNonemptyBroker(t *testing.T) {
	p := recoveryPlan{Stream: "S", Durable: "D", StreamEpoch: 100, NewConsumerEpoch: 200}
	s := nats.StreamInfo{Config: nats.StreamConfig{Name: "S"}, State: nats.StreamState{Consumers: 1}}
	c := nats.ConsumerInfo{Stream: "S", Name: "D", Config: nats.ConsumerConfig{Durable: "D", DeliverPolicy: nats.DeliverAllPolicy, AckPolicy: nats.AckExplicitPolicy, FilterSubject: "cdnca.analytics.ingest.v1.*"}}
	s.Created = epochRecoveryTime(p.StreamEpoch)
	c.Created = epochRecoveryTime(p.NewConsumerEpoch)
	if err := validateRecoveryBroker(p, s, c); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*nats.StreamInfo, *nats.ConsumerInfo){
		func(s *nats.StreamInfo, c *nats.ConsumerInfo) { s.State.LastSeq = 1 },
		func(s *nats.StreamInfo, c *nats.ConsumerInfo) { s.State.Msgs = 1 },
		func(s *nats.StreamInfo, c *nats.ConsumerInfo) { s.State.NumDeleted = 1 },
		func(s *nats.StreamInfo, c *nats.ConsumerInfo) { c.Delivered.Consumer = 1 },
		func(s *nats.StreamInfo, c *nats.ConsumerInfo) { c.NumWaiting = 1 },
		func(s *nats.StreamInfo, c *nats.ConsumerInfo) { c.NumAckPending = 1 },
		func(s *nats.StreamInfo, c *nats.ConsumerInfo) { c.NumPending = 1 },
	} {
		ss, cc := s, c
		change(&ss, &cc)
		if validateRecoveryBroker(p, ss, cc) == nil {
			t.Fatal("accepted nonempty broker")
		}
	}
}
