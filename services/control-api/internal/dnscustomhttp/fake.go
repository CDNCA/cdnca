package dnscustomhttp

import (
	"crypto/hmac"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FakeEndpoint is a reference implementation of the endpoint side of the
// protocol, holding records in memory. Tests (here and in the DNS adapters)
// serve it with httptest; operators can read it as the server contract:
// signature and timestamp checks, nonce replay rejection, the five actions.
type FakeEndpoint struct {
	Secret string
	Zone   string
	Now    func() time.Time

	mu      sync.Mutex
	records []Record
	nonces  map[string]struct{}
	next    int
	// Calls counts requests per action.
	Calls map[string]int
}

func (fake *FakeEndpoint) Records() []Record {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return append([]Record(nil), fake.records...)
}

func (fake *FakeEndpoint) Seed(records ...Record) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for _, record := range records {
		fake.next++
		if record.ID == "" {
			record.ID = "r" + strconv.Itoa(fake.next)
		}
		fake.records = append(fake.records, record)
	}
}

func (fake *FakeEndpoint) reply(writer http.ResponseWriter, status int, ok bool, code string, data any) {
	body := map[string]any{"protocol": Protocol, "ok": ok}
	if code != "" {
		body["error"] = map[string]string{"code": code, "message": "fake endpoint"}
	}
	if data != nil {
		body["data"] = data
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(body)
}

func (fake *FakeEndpoint) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	now := time.Now
	if fake.Now != nil {
		now = fake.Now
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 1<<20))
	if err != nil || request.Method != http.MethodPost {
		fake.reply(writer, http.StatusBadRequest, false, "bad_request", nil)
		return
	}
	timestamp, nonce := request.Header.Get(HeaderTimestamp), request.Header.Get(HeaderNonce)
	unix, err := strconv.ParseInt(timestamp, 10, 64)
	want := Sign([]byte(fake.Secret), timestamp, nonce, body)
	if err != nil || nonce == "" || !hmac.Equal([]byte(want), []byte(request.Header.Get(HeaderSignature))) ||
		now().Unix()-unix > 300 || unix-now().Unix() > 300 {
		fake.reply(writer, http.StatusUnauthorized, false, "bad_signature", nil)
		return
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.nonces == nil {
		fake.nonces, fake.Calls = map[string]struct{}{}, map[string]int{}
	}
	if _, replayed := fake.nonces[nonce]; replayed {
		fake.reply(writer, http.StatusUnauthorized, false, "replayed", nil)
		return
	}
	fake.nonces[nonce] = struct{}{}
	var input struct {
		Protocol string `json:"protocol"`
		Action   string `json:"action"`
		Zone     string `json:"zone"`
		Name     string `json:"name"`
		ID       string `json:"id"`
		Record   Record `json:"record"`
	}
	if json.Unmarshal(body, &input) != nil || input.Protocol != Protocol {
		fake.reply(writer, http.StatusBadRequest, false, "bad_request", nil)
		return
	}
	fake.Calls[input.Action]++
	if input.Action != "verify" && input.Zone != fake.Zone {
		fake.reply(writer, http.StatusOK, false, "zone_not_found", nil)
		return
	}
	switch input.Action {
	case "verify":
		fake.reply(writer, http.StatusOK, true, "", map[string]any{})
	case "list_records":
		var records []Record
		for _, record := range fake.records {
			if input.Name == "" || strings.EqualFold(record.Name, strings.TrimSuffix(input.Name, ".")) {
				records = append(records, record)
			}
		}
		if records == nil {
			records = []Record{}
		}
		fake.reply(writer, http.StatusOK, true, "", map[string]any{"records": records})
	case "create_record":
		fake.next++
		input.Record.ID = "r" + strconv.Itoa(fake.next)
		fake.records = append(fake.records, input.Record)
		fake.reply(writer, http.StatusOK, true, "", map[string]string{"id": input.Record.ID})
	case "update_record", "delete_record":
		id := input.ID
		if input.Action == "update_record" {
			id = input.Record.ID
		}
		for index, record := range fake.records {
			if record.ID != id {
				continue
			}
			if input.Action == "delete_record" {
				fake.records = append(fake.records[:index], fake.records[index+1:]...)
			} else {
				fake.records[index] = input.Record
			}
			fake.reply(writer, http.StatusOK, true, "", map[string]any{})
			return
		}
		fake.reply(writer, http.StatusOK, false, "not_found", nil)
	default:
		fake.reply(writer, http.StatusOK, false, "unknown_action", nil)
	}
}
