package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyntelemetry"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/telemetryclient"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// The node identity and the config version the market sites are bound
// under in the agent leg (the gateway leg authorises the same values).
const (
	minuteNodeID        = "0d9a0000-0000-4000-8000-0000000000a1"
	minuteConfigVersion = "0d9a0000-0000-4000-8000-0000000000a2"
	minuteInstallation  = "0d9a-d9-filters-installation"
)

// WireRecord is what the agent sends to the gateway for one minute.
type WireRecord struct {
	Kind        string `json:"kind"`
	MessageID   string `json:"message_id"`
	LastEventID string `json:"last_event_id"`
	Payload     string `json:"payload"` // base64
}

type captureSender struct{ records []telemetryclient.Record }

func (sender *captureSender) Send(_ context.Context, batch telemetryclient.Batch) (telemetryclient.SendAck, error) {
	sender.records = append(sender.records, batch.Records...)
	return telemetryclient.SendAck{Accepted: len(batch.Records)}, nil
}

// agentMinutes takes the finished minutes the way the agent does
// (dyntelemetry.SubscriptionMinutes over the control socket into a real
// event spool, flushed through the telemetry publisher), writes the wire
// records to -records and returns the minutes for the node-side checks.
func agentMinutes() []map[string]any {
	ctx := context.Background()
	root := filepath.Clean(filepath.Join(*stateRoot, "minute-spool"))
	if err := os.MkdirAll(root, 0o700); err != nil {
		check("market-minutes-agent", false, "spool dir: %v", err)
		return nil
	}
	spool, err := eventspool.New(eventspool.Config{Root: root, MaxEventBytes: 64 << 10, MaxSegmentBytes: 1 << 20,
		SoftLimitBytes: 8 << 20, HardLimitBytes: 16 << 20, MaxTenantBytes: 16 << 20, MaxBatchEvents: 1000,
		PressureMode: eventspool.PressureBackpressure, SoftAgeLimit: 24 * time.Hour, HardAgeLimit: 7 * 24 * time.Hour, Now: time.Now})
	if err != nil {
		check("market-minutes-agent", false, "spool: %v", err)
		return nil
	}
	var taken []dyntelemetry.NodeMinute
	source := &dyntelemetry.SubscriptionMinutes{NodeID: minuteNodeID,
		Take: func(ctx context.Context) ([]dyntelemetry.NodeMinute, error) {
			raw, err := controlGet(ctx, "/subscription-minutes")
			if err != nil {
				return nil, err
			}
			minutes, err := dynroute.ParseSubscriptionMinutes(raw)
			taken = append(taken, minutes...)
			return minutes, err
		},
		Sites: func() []dyntelemetry.MinuteSite {
			var sites []dyntelemetry.MinuteSite
			for _, site := range marketSites {
				sites = append(sites, dyntelemetry.MinuteSite{TenantID: tenant, SiteID: site.id, PackageSubscriptionID: site.sub,
					ConfigVersionID: minuteConfigVersion, InstallationID: minuteInstallation})
			}
			return sites
		}}
	if err := source.Sync(ctx, spool, 1000); err != nil {
		check("market-minutes-agent", false, "sync: %v", err)
		return nil
	}
	sender := &captureSender{}
	publisher, err := telemetryclient.NewPublisher(minuteNodeID, sender)
	if err != nil {
		check("market-minutes-agent", false, "publisher: %v", err)
		return nil
	}
	result, err := spool.Flush(ctx, publisher, 1000)
	check("market-minutes-agent", err == nil && len(taken) > 0 && result.Published == len(taken) && len(sender.records) == len(taken) &&
		source.Dropped() == 0, "taken %d, published %d, wire %d, dropped %d, %v", len(taken), result.Published, len(sender.records), source.Dropped(), err)
	again, err := spool.Flush(ctx, publisher, 1000)
	check("market-minutes-agent-acked", err == nil && again.Published == 0, "acknowledged records left the spool: %+v %v", again, err)
	file, err := os.Create(*recordsOut)
	if err == nil {
		encoder := json.NewEncoder(file)
		for _, record := range sender.records {
			err = encoder.Encode(WireRecord{Kind: record.Kind, MessageID: record.MessageID, LastEventID: record.LastEventID,
				Payload: base64.StdEncoding.EncodeToString(record.Payload)})
		}
		err = errors.Join(err, file.Close())
	}
	// the node side's maxima per subscription, for the ClickHouse check
	expect := map[string]map[string]int64{}
	for _, minute := range taken {
		e := expect[minute.SubscriptionID]
		if e == nil {
			e = map[string]int64{}
			expect[minute.SubscriptionID] = e
		}
		e["max_connections"] = max(e["max_connections"], minute.MaxConnections)
		e["max_new_cps"] = max(e["max_new_cps"], minute.MaxNewCPS)
		e["max_qps"] = max(e["max_qps"], minute.MaxQPS)
		e["bytes_out"] += minute.BytesOut
	}
	if err == nil {
		encoded, _ := json.Marshal(expect)
		err = os.WriteFile(filepath.Join(filepath.Dir(*recordsOut), "expect.json"), encoded, 0o644)
	}
	check("market-minutes-records", err == nil, "write %s: %v", *recordsOut, err)
	// the minutes as the node handed them out, for the node-side checks
	var out []map[string]any
	for _, minute := range taken {
		encoded, _ := json.Marshal(struct {
			SubscriptionID string `json:"subscription_id"`
			Minute         int64  `json:"minute"`
			edgeconfig.SubscriptionMinuteCounters
		}{minute.SubscriptionID, minute.Minute.Unix(), minute.SubscriptionMinuteCounters})
		var record map[string]any
		_ = json.Unmarshal(encoded, &record)
		out = append(out, record)
	}
	return out
}

func controlGet(ctx context.Context, location string) ([]byte, error) {
	client := http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(*stateRoot, "run", "cdnca-site-admin.sock"))
		}}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://control"+location, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil || response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %d %v", location, response.StatusCode, err)
	}
	return raw, nil
}
