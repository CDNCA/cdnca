package l4forward

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

func TestNormalizeFieldsPackageRuntimeContract(t *testing.T) {
	fields := validFields()
	if err := normalizeFields(&fields); err != nil {
		t.Fatalf("valid package/runtime fields rejected: %v", err)
	}

	for _, test := range []struct {
		name  string
		field string
		value any
	}{
		{name: "zero connection limit", field: "MaxConnectionsPerClient", value: 0},
		{name: "connection limit above maximum", field: "MaxConnectionsPerClient", value: 10001},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := fields
			invalid.MaxConnectionsPerClient = test.value.(int)
			if err := normalizeFields(&invalid); err == nil {
				t.Fatalf("normalizeFields accepted %s=%v", test.field, test.value)
			}
		})
	}
	for _, limit := range []int{1, 10000} {
		boundary := fields
		boundary.MaxConnectionsPerClient = limit
		if err := normalizeFields(&boundary); err != nil {
			t.Errorf("max_connections_per_client boundary %d rejected: %v", limit, err)
		}
	}
}

func TestL4WriteDigestBindsPackageAndConnectionLimit(t *testing.T) {
	fields := validFields()
	base, err := digestRequest(struct {
		Fields Fields `json:"fields"`
	}{Fields: fields})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"PackageSubscriptionID", "MaxConnectionsPerClient"} {
		t.Run(field, func(t *testing.T) {
			changed := fields
			if field == "PackageSubscriptionID" {
				changed.PackageSubscriptionID = new(uuid.New())
			} else {
				changed.MaxConnectionsPerClient = 101
			}
			digest, err := digestRequest(struct {
				Fields Fields `json:"fields"`
			}{Fields: changed})
			if err != nil {
				t.Fatal(err)
			}
			if digest == base {
				t.Fatalf("write digest does not bind %s", field)
			}
		})
	}
}

func TestNormalizeFieldsCanonicalStreamContract(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*Fields)
		wantHost string
		wantErr  bool
	}{
		{name: "canonical IPv4", wantHost: "192.0.2.10"},
		{name: "canonical IPv6", mutate: func(fields *Fields) { fields.UpstreamAddress = "2001:0db8::10" }, wantHost: "2001:db8::10"},
		{name: "noncanonical protocol case", mutate: func(fields *Fields) { fields.Protocol = "TCP" }, wantErr: true},
		{name: "noncanonical protocol whitespace", mutate: func(fields *Fields) { fields.Protocol = " tcp " }, wantErr: true},
		{name: "invalid UTF-8 name", mutate: func(fields *Fields) { fields.Name = string([]byte{'a', 0xff, 'b'}) }, wantErr: true},
		{name: "control character name", mutate: func(fields *Fields) { fields.Name = "edge\nstream" }, wantErr: true},
		{name: "unspecified IPv4", mutate: func(fields *Fields) { fields.UpstreamAddress = "0.0.0.0" }, wantErr: true},
		{name: "unspecified IPv6", mutate: func(fields *Fields) { fields.UpstreamAddress = "::" }, wantErr: true},
		{name: "multicast IPv4", mutate: func(fields *Fields) { fields.UpstreamAddress = "224.0.0.1" }, wantErr: true},
		{name: "multicast IPv6", mutate: func(fields *Fields) { fields.UpstreamAddress = "ff02::1" }, wantErr: true},
		{name: "IPv4 mapped IPv6", mutate: func(fields *Fields) { fields.UpstreamAddress = "::ffff:192.0.2.10" }, wantErr: true},
		{name: "DNS requires migration", mutate: func(fields *Fields) { fields.UpstreamAddress = "origin.example.test" }, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fields := validFields()
			if test.mutate != nil {
				test.mutate(&fields)
			}
			err := normalizeFields(&fields)
			if test.wantErr {
				if err == nil {
					t.Fatalf("normalizeFields(%+v) succeeded", fields)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeFields(%+v): %v", fields, err)
			}
			if fields.UpstreamAddress != test.wantHost || fields.ListenAddress != "*" || fields.Protocol != ProtocolTCP {
				t.Fatalf("normalized fields=%+v want host=%q wildcard TCP", fields, test.wantHost)
			}
		})
	}
}

func TestNormalizeFieldsNameContract(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantName string
		wantErr  bool
	}{
		{name: "trimmed Chinese one-rune boundary", input: "  中  ", wantName: "中"},
		{name: "Chinese 128-rune boundary", input: strings.Repeat("界", 128), wantName: strings.Repeat("界", 128)},
		{name: "over 128 runes", input: strings.Repeat("界", 129), wantErr: true},
		{name: "invalid UTF-8", input: string([]byte{'a', 0xff, 'b'}), wantErr: true},
		{name: "embedded control", input: "中\n文", wantErr: true},
		{name: "leading control", input: "\t中文", wantErr: true},
		{name: "trailing control", input: "中文\n", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fields := validFields()
			fields.Name = test.input
			err := normalizeFields(&fields)
			if test.wantErr {
				if err == nil {
					t.Fatalf("normalizeFields accepted name with %d runes", len([]rune(test.input)))
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeFields rejected valid name: %v", err)
			}
			if fields.Name != test.wantName {
				t.Fatalf("normalized name=%q want %q", fields.Name, test.wantName)
			}
		})
	}
}

func TestNormalizeFieldsProxyProtocolV1Contract(t *testing.T) {
	tcp := validFields()
	tcp.ProxyProtocolV1 = true
	if err := normalizeFields(&tcp); err != nil {
		t.Fatalf("TCP Proxy Protocol v1 rejected: %v", err)
	}
	udp := validFields()
	udp.Protocol = ProtocolUDP
	udp.ProxyProtocolV1 = true
	if err := normalizeFields(&udp); err == nil {
		t.Fatal("UDP Proxy Protocol v1 accepted")
	}
	udp.ProxyProtocolV1 = false
	if err := normalizeFields(&udp); err != nil {
		t.Fatalf("UDP without Proxy Protocol rejected: fields=%+v err=%v", udp, err)
	}
}

func TestNormalizeFieldsRejectsNonCanonicalListenerSurface(t *testing.T) {
	for _, address := range []string{"", "  ", " * ", "0.0.0.0", "::", "127.0.0.1", " edge "} {
		fields := validFields()
		fields.ListenAddress = address
		if err := normalizeFields(&fields); err == nil {
			t.Fatalf("listen_address=%q accepted", address)
		}
	}
}

func validFields() Fields {
	return Fields{
		PackageSubscriptionID: new(uuid.New()), MaxConnectionsPerClient: 100,
		Name: "edge stream", Protocol: ProtocolTCP, ListenAddress: "*", ListenPort: 18080,
		UpstreamAddress: "192.0.2.10", UpstreamPort: 8080,
		ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30000, Enabled: true,
	}
}

func TestTLSPassthroughFieldsNormalizeAndKeepPlainDigests(t *testing.T) {
	plain := Fields{Protocol: ProtocolTCP}
	encoded, err := json.Marshal(plain)
	if err != nil || strings.Contains(string(encoded), "tls_passthrough") || strings.Contains(string(encoded), "server_names") {
		t.Fatalf("plain fields digest input changed: %s %v", encoded, err)
	}
	listeners := []AdditionalListener{{Protocol: ProtocolTCP}}
	fields := Fields{Protocol: ProtocolTCP, TLSPassthrough: true, AdditionalListeners: &listeners,
		ServerNames: []string{" B.example.com ", "*.example.com", "a.example.com"}}
	if err := normalizeTLSPassthrough(&fields); err != nil ||
		strings.Join(fields.ServerNames, ",") != "*.example.com,a.example.com,b.example.com" {
		t.Fatalf("names=%v err=%v", fields.ServerNames, err)
	}
	for name, change := range map[string]func(*Fields){
		"names without passthrough": func(f *Fields) { f.TLSPassthrough = false },
		"no names":                  func(f *Fields) { f.ServerNames = nil },
		"udp":                       func(f *Fields) { f.Protocol = ProtocolUDP },
		"udp extra listener":        func(f *Fields) { (*f.AdditionalListeners)[0].Protocol = ProtocolUDP },
		"duplicate after folding":   func(f *Fields) { f.ServerNames = []string{"a.example.com", "A.example.com"} },
		"inner wildcard":            func(f *Fields) { f.ServerNames = []string{"a.*.example.com"} },
		"wildcard on a TLD":         func(f *Fields) { f.ServerNames = []string{"*.com"} },
		"single label":              func(f *Fields) { f.ServerNames = []string{"localhost"} },
		"trailing dot":              func(f *Fields) { f.ServerNames = []string{"a.example.com."} },
		"too many": func(f *Fields) {
			f.ServerNames = nil
			for index := 0; index <= maxServerNames; index++ {
				f.ServerNames = append(f.ServerNames, fmt.Sprintf("n%d.example.com", index))
			}
		},
	} {
		listeners := []AdditionalListener{{Protocol: ProtocolTCP}}
		fields := Fields{Protocol: ProtocolTCP, TLSPassthrough: true, AdditionalListeners: &listeners,
			ServerNames: []string{"a.example.com"}}
		change(&fields)
		if err := normalizeTLSPassthrough(&fields); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if encoded, err := json.Marshal(Forward{}); err != nil || !strings.Contains(string(encoded), `"server_names":[]`) {
		t.Fatalf("stream response must always carry server_names: %s %v", encoded, err)
	}
}

// 单 IP 新建连接速率: 0 is unlimited (and keeps request digests and runtime
// intents unchanged); burst and ban need a rate; the bounds are edgeconfig's.
func TestNewConnectionRateFieldsNormalizeAndReachTheRuntimeIntent(t *testing.T) {
	encoded, err := json.Marshal(Fields{Protocol: ProtocolTCP})
	if err != nil || strings.Contains(string(encoded), "new_connection") {
		t.Fatalf("unlimited fields digest input changed: %s %v", encoded, err)
	}
	for _, valid := range []func(*Fields){
		func(f *Fields) {},
		func(f *Fields) { f.MaxNewConnectionsPerClientPerSecond = 1 },
		func(f *Fields) {
			f.MaxNewConnectionsPerClientPerSecond, f.NewConnectionBurst, f.NewConnectionBanSeconds = 100_000, 100_000, 86_400
		},
		func(f *Fields) {
			f.Protocol = ProtocolUDP
			f.MaxNewConnectionsPerClientPerSecond = 50
			f.NewConnectionBanSeconds = 60
		},
	} {
		fields := validFields()
		valid(&fields)
		if err := normalizeFields(&fields); err != nil {
			t.Fatalf("valid rate %+v rejected: %v", fields, err)
		}
	}
	for name, invalid := range map[string]func(*Fields){
		"negative rate":      func(f *Fields) { f.MaxNewConnectionsPerClientPerSecond = -1 },
		"rate over limit":    func(f *Fields) { f.MaxNewConnectionsPerClientPerSecond = 100_001 },
		"negative burst":     func(f *Fields) { f.MaxNewConnectionsPerClientPerSecond = 1; f.NewConnectionBurst = -1 },
		"burst over limit":   func(f *Fields) { f.MaxNewConnectionsPerClientPerSecond = 1; f.NewConnectionBurst = 100_001 },
		"ban over limit":     func(f *Fields) { f.MaxNewConnectionsPerClientPerSecond = 1; f.NewConnectionBanSeconds = 86_401 },
		"negative ban":       func(f *Fields) { f.MaxNewConnectionsPerClientPerSecond = 1; f.NewConnectionBanSeconds = -1 },
		"burst without rate": func(f *Fields) { f.NewConnectionBurst = 5 },
		"ban without rate":   func(f *Fields) { f.NewConnectionBanSeconds = 60 },
	} {
		fields := validFields()
		invalid(&fields)
		if err := normalizeFields(&fields); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: %v", name, err)
		}
	}

	item := Forward{ID: uuid.New(), ScopeID: uuid.New(), Protocol: ProtocolTCP, ListenAddress: "*",
		ListenPort: 9000, UpstreamAddress: "192.0.2.10", UpstreamPort: 9000, MaxConnectionsPerClient: 100, Revision: 1}
	plain, err := json.Marshal(runtimeSpec(item))
	if err != nil || strings.Contains(string(plain), "new_conn_rate") {
		t.Fatalf("unlimited stream intent changed: %s %v", plain, err)
	}
	item.MaxNewConnectionsPerClientPerSecond, item.NewConnectionBurst, item.NewConnectionBanSeconds = 20, 5, 60
	limited, err := json.Marshal(runtimeSpec(item))
	if err != nil || !strings.Contains(string(limited), `"new_conn_rate":{"rate_per_second":20,"burst":5,"ban_seconds":60}`) {
		t.Fatalf("limited stream intent: %s %v", limited, err)
	}
	var wire edgeconfig.L4StreamRuntimeV2
	if err := json.Unmarshal(limited, &wire); err != nil || wire.NewConnRate == nil ||
		*wire.NewConnRate != (edgeconfig.L4NewConnRateV2{RatePerSecond: 20, Burst: 5, BanSeconds: 60}) {
		t.Fatalf("intent does not decode into the edge contract: %+v %v", wire.NewConnRate, err)
	}
	if encoded, err := json.Marshal(Forward{}); err != nil || !strings.Contains(string(encoded), `"max_new_connections_per_client_per_second":0`) {
		t.Fatalf("stream response must always carry the rate: %s %v", encoded, err)
	}
}

// 会话日志 (migration 328): the runtime intent carries session_log only when
// enabled, in the edge contract's place; the request omits it when false.
func TestSessionLogReachesTheRuntimeIntent(t *testing.T) {
	item := Forward{ID: uuid.New(), ScopeID: uuid.New(), Protocol: ProtocolTCP, ListenAddress: "*",
		ListenPort: 9000, UpstreamAddress: "192.0.2.10", UpstreamPort: 9000, MaxConnectionsPerClient: 100, Revision: 1,
		MaxNewConnectionsPerClientPerSecond: 5}
	plain, err := json.Marshal(runtimeSpec(item))
	if err != nil || strings.Contains(string(plain), "session_log") {
		t.Fatalf("unlogged stream intent changed: %s %v", plain, err)
	}
	item.SessionLogEnabled = true
	logged, err := json.Marshal(runtimeSpec(item))
	if err != nil || !strings.Contains(string(logged), `"ban_seconds":0},"session_log":true`) {
		t.Fatalf("logged stream intent: %s %v", logged, err)
	}
	var wire edgeconfig.L4StreamRuntimeV2
	if err := json.Unmarshal(logged, &wire); err != nil || !wire.SessionLog {
		t.Fatalf("intent does not decode into the edge contract: %v", err)
	}
	if encoded, err := json.Marshal(Fields{}); err != nil || strings.Contains(string(encoded), "session_log") {
		t.Fatalf("request digest changed: %s %v", encoded, err)
	}
	if encoded, err := json.Marshal(Forward{}); err != nil || !strings.Contains(string(encoded), `"session_log_enabled":false`) {
		t.Fatalf("stream response must carry the session log flag: %s %v", encoded, err)
	}
}

// Community edition: a forward needs no package; an explicit zero id reads as none.
func TestNormalizeFieldsAcceptsForwardWithoutPackage(t *testing.T) {
	for name, value := range map[string]*uuid.UUID{"absent": nil, "zero": new(uuid.Nil)} {
		fields := validFields()
		fields.PackageSubscriptionID = value
		if err := normalizeFields(&fields); err != nil || fields.PackageSubscriptionID != nil {
			t.Fatalf("%s: normalizeFields = %v, package = %v; want accepted without a package", name, err, fields.PackageSubscriptionID)
		}
	}
}
