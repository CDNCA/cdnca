package httpapi

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestNodeInstallationTicketsQuery(t *testing.T) {
	first, second := uuid.NewString(), uuid.NewString()
	ids, err := nodeInstallationTicketsQuery(httptest.NewRequest("GET", "/v1/nodes/installation-tickets?node_id="+first+"&node_id="+second, nil))
	if err != nil || len(ids) != 2 || ids[0].String() != first || ids[1].String() != second {
		t.Fatalf("valid query = %v %v", ids, err)
	}
	tooMany := ""
	for i := 0; i < 301; i++ {
		tooMany += "node_id=" + uuid.NewString() + "&"
	}
	for name, query := range map[string]string{
		"empty": "", "duplicate": "node_id=" + first + "&node_id=" + first, "upper": "node_id=" + strings.ToUpper(first),
		"nil": "node_id=" + uuid.Nil.String(), "extra": "node_id=" + first + "&limit=1", "too many": strings.TrimSuffix(tooMany, "&"),
	} {
		if _, err := nodeInstallationTicketsQuery(httptest.NewRequest("GET", "/v1/nodes/installation-tickets?"+query, nil)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
