package nodesshinstall

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// Batch install: each "IP port user password" line is its own login.
func TestCreateBodyPerHostLogins(t *testing.T) {
	batch := uuid.NewString()
	request, ok := createBody{BatchID: batch, RestrictSSH: true, Targets: []targetBody{
		{Host: "203.0.113.7", Port: 2222, Username: "root", Password: "a"},
		{Host: "203.0.113.8", Username: "deploy", Password: "b"},
	}}.createRequest()
	if !ok || len(request.Targets) != 2 || request.BatchID.String() != batch || !request.RestrictSSH {
		t.Fatalf("request = %+v %v", request, ok)
	}
	request.ControlPlane = "https://cdnca.com"
	if err := normalizeCreate(&request, defaultBlocked); err != nil {
		t.Fatal(err)
	}
	if got := request.credentialOf(request.Targets[1]); got.Username != "deploy" || got.Password != "b" ||
		request.Targets[1].Port != 22 || request.Targets[0].Port != 2222 {
		t.Fatalf("targets = %+v", request.Targets)
	}
	for name, body := range map[string]createBody{
		"mixed shared":  {Hosts: []string{"203.0.113.9"}, Targets: []targetBody{{Host: "203.0.113.7", Username: "root", Password: "a"}}},
		"shared secret": {Password: "x", Targets: []targetBody{{Host: "203.0.113.7", Username: "root", Password: "a"}}},
		"bad batch":     {BatchID: "nope", Hosts: []string{"203.0.113.7"}},
		"nil batch":     {BatchID: uuid.Nil.String(), Hosts: []string{"203.0.113.7"}},
		"names":         {Hosts: []string{"203.0.113.7"}, Names: []string{"a", "b"}},
	} {
		if _, ok := body.createRequest(); ok {
			t.Errorf("%s accepted", name)
		}
	}
	// One bad line refuses the whole batch (the console marks it before sending).
	bad, _ := createBody{Targets: []targetBody{{Host: "203.0.113.7", Username: "root", Password: "a"},
		{Host: "203.0.113.8", Username: "root"}}}.createRequest()
	bad.ControlPlane = "https://cdnca.com"
	if err := normalizeCreate(&bad, defaultBlocked); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("line without secret accepted")
	}
}

func TestControllerEgressConfig(t *testing.T) {
	if config, err := NewAccessConfig(nil); err != nil || config != nil {
		t.Fatalf("empty = %v %v", config, err)
	}
	config, err := NewAccessConfig([]string{"203.0.113.7", "198.51.100.0/24", "203.0.113.7/32", "2001:db8::1"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"198.51.100.0/24", "2001:db8::1/128", "203.0.113.7/32"}
	if len(config.ControllerCIDRs) != len(want) {
		t.Fatalf("cidrs = %v", config.ControllerCIDRs)
	}
	for index := range want {
		if config.ControllerCIDRs[index] != want[index] {
			t.Fatalf("cidrs = %v", config.ControllerCIDRs)
		}
	}
	for _, bad := range []string{"0.0.0.0/0", "10.0.0.0/8", "::/0", "fe80::1%eth0", "not-an-ip", "224.0.0.1"} {
		if _, err := NewAccessConfig([]string{bad}); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s accepted", bad)
		}
	}
	// Without a known egress, "only the controller" cannot be turned on.
	service := &Service{}
	if cidrs, source := service.ControllerEgress(context.Background()); len(cidrs) != 0 || source != "" {
		t.Fatal("egress without config")
	}
	// unconfigured, the detected public address is used; the configured list wins.
	service.UseEgressDetector(func(context.Context) []string { return []string{"203.0.113.9"} })
	if cidrs, source := service.ControllerEgress(context.Background()); len(cidrs) != 1 || cidrs[0] != "203.0.113.9/32" ||
		source != EgressDetected {
		t.Fatalf("detected = %v %s", cidrs, source)
	}
	service.access = config
	if cidrs, source := service.ControllerEgress(context.Background()); len(cidrs) != 3 || source != EgressConfigured {
		t.Fatalf("configured = %v %s", cidrs, source)
	}
	// A detector returning junk is ignored.
	service.access = nil
	service.UseEgressDetector(func(context.Context) []string { return []string{"not-an-ip"} })
	if cidrs, source := service.ControllerEgress(context.Background()); len(cidrs) != 0 || source != "" {
		t.Fatalf("junk detected = %v %s", cidrs, source)
	}
}

func TestDetectEgress(t *testing.T) {
	interfaces := func(values ...string) func() ([]net.Addr, error) {
		return func() ([]net.Addr, error) {
			out := []net.Addr{}
			for _, value := range values {
				ip, network, err := net.ParseCIDR(value)
				if err != nil {
					t.Fatal(err)
				}
				network.IP = ip
				out = append(out, network)
			}
			return out, nil
		}
	}
	for name, test := range map[string]struct {
		gateway    string
		interfaces func() ([]net.Addr, error)
		want       string
	}{
		// install-control.sh writes the host's public IP as the local Gateway address.
		"gateway public ip":       {"203.0.113.7:20407", interfaces("198.51.100.4/24"), "203.0.113.7"},
		"gateway ipv6":            {"[2001:db8::7]:20407", nil, "2001:db8::7"},
		"gateway domain ignored":  {"gateway.example.com:20407", interfaces("10.0.0.5/8", "198.51.100.4/24"), "198.51.100.4"},
		"gateway private ignored": {"10.0.0.5:20407", interfaces("127.0.0.1/8", "172.16.3.4/12", "100.64.1.2/10", "fe80::1/64"), ""},
		"nothing":                 {"", nil, ""},
		"interfaces error":        {"", func() ([]net.Addr, error) { return nil, errors.New("x") }, ""},
	} {
		got := strings.Join(DetectEgress(test.gateway, test.interfaces), ",")
		if got != test.want {
			t.Errorf("%s: %q, want %q", name, got, test.want)
		}
	}
}
