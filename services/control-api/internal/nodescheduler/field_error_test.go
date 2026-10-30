package nodescheduler

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
)

// fix-fielderr-be: a line group refusal names the request field (index in the
// request's endpoints order) and still matches ErrInvalidInput.
func TestNormalizeLineGroupLocatesField(t *testing.T) {
	endpoint := func() Endpoint {
		return Endpoint{ID: uuid.New(), NodeID: uuid.New(), Address: "198.51.100.10", Port: 443, Weight: 1}
	}
	tests := map[string]struct {
		change        func(*PutGroupRequest)
		field, reason string
	}{
		"empty name":      {func(r *PutGroupRequest) { r.Name = " " }, "name", fielderr.Required},
		"long region":     {func(r *PutGroupRequest) { r.Region = strings.Repeat("区", 65) }, "region", fielderr.TooLong},
		"long note":       {func(r *PutGroupRequest) { r.Note = strings.Repeat("x", 513) }, "note", fielderr.TooLong},
		"resolved value":  {func(r *PutGroupRequest) { r.ResolvedValue = "bad value" }, "resolved_value", fielderr.InvalidFormat},
		"ipv4 resolved":   {func(r *PutGroupRequest) { r.IPv4ResolvedValue = "bad value" }, "ipv4_resolved_value", fielderr.InvalidFormat},
		"failover":        {func(r *PutGroupRequest) { r.FailoverMode = "interval" }, "failover_mode", fielderr.Invalid},
		"sort order":      {func(r *PutGroupRequest) { r.SortOrder = -1 }, "sort_order", fielderr.OutOfRange},
		"endpoint port":   {func(r *PutGroupRequest) { r.Endpoints[1].Port = 0 }, "endpoints[1].port", fielderr.OutOfRange},
		"endpoint weight": {func(r *PutGroupRequest) { r.Endpoints[0].Weight = 0 }, "endpoints[0].weight", fielderr.OutOfRange},
		"endpoint addr":   {func(r *PutGroupRequest) { r.Endpoints[1].Address = "not-ip" }, "endpoints[1].address", fielderr.InvalidFormat},
		"duplicate addr": {func(r *PutGroupRequest) { r.Endpoints[1].Address = r.Endpoints[0].Address },
			"endpoints[1].address", fielderr.Duplicate},
		"carrier": {func(r *PutGroupRequest) { r.Endpoints[0].Carrier = strings.Repeat("x", 65) }, "endpoints[0].carrier", fielderr.TooLong},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			second := endpoint()
			second.Address = "198.51.100.11"
			request := PutGroupRequest{GroupID: uuid.New(), Name: "华东", Endpoints: []Endpoint{endpoint(), second},
				IdempotencyKey: "key-1", RequestID: "request-1"}
			test.change(&request)
			_, err := normalizePutRequest(request)
			located, ok := fielderr.As(err)
			if !errors.Is(err, ErrInvalidInput) || !ok || located.Field != test.field || located.Reason != test.reason {
				t.Fatalf("normalizePutRequest() = %v, want %s/%s", err, test.field, test.reason)
			}
		})
	}
}
