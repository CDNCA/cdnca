package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestControlBackupRoutesReachTheirHandler(t *testing.T) {
	var paths []string
	probe := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		paths = append(paths, request.Method+" "+request.URL.Path)
		response.WriteHeader(http.StatusNoContent)
	})
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), ControlBackupHandler: probe}).Handler()
	for _, route := range []string{"GET /v1/admin/control-backup", "PUT /v1/admin/control-backup/settings",
		"POST /v1/admin/control-backup/backups", "POST /v1/admin/control-backup/migrations",
		"GET /v1/admin/control-backup/backups/20261017T030000Z-abcdefgh/restore-commands"} {
		method, path, _ := cutSpace(route)
		recorder := httptest.NewRecorder()
		api.ServeHTTP(recorder, httptest.NewRequest(method, path, nil))
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("%s = %d", route, recorder.Code)
		}
	}
	if len(paths) != 5 {
		t.Fatalf("paths = %v", paths)
	}
}

func cutSpace(value string) (string, string, bool) {
	for index := range value {
		if value[index] == ' ' {
			return value[:index], value[index+1:], true
		}
	}
	return value, "", false
}
