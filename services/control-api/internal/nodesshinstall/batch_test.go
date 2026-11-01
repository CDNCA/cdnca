package nodesshinstall

import (
	"errors"
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
	if len(service.ControllerEgress()) != 0 {
		t.Fatal("egress without config")
	}
}
