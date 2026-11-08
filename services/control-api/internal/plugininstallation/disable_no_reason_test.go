package plugininstallation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// 安装记录类插件暂停（disable）不再带原因；卸载仍必须带 1–500 字原因。
func TestServiceDisableTakesNoReasonUninstallStillDoes(t *testing.T) {
	now := time.Date(2032, 4, 5, 6, 7, 8, 0, time.UTC)
	store := newMemoryStore()
	service := Service{Store: store, Verifier: &recordingVerifier{}, Now: func() time.Time { return now }}
	install := testCommand(uuid.New(), uuid.New(), uuid.New(), uuid.New())
	install.Action = ActionConfirm
	install.NewPermissionsConfirmed = true
	install.Facts = []SignedRuntimeFact{{Scope: "plugin.read", RequestID: "fact-install"}}
	installed, err := service.Apply(context.Background(), install)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	withReason := protectiveCommand(installed.Installation, ActionDisable, "旧页面带来的原因", "pause-reason")
	if _, err := service.Apply(context.Background(), withReason); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("disable with reason err=%v, want invalid input", err)
	}
	paused, err := service.Apply(context.Background(), protectiveCommand(installed.Installation, ActionDisable, "", "pause-1"))
	if err != nil || paused.Installation.Status != StatusDisabled || paused.Receipt.Reason != "" ||
		paused.Receipt.Result != ReceiptDisabled {
		t.Fatalf("disable without reason=%+v err=%v", paused, err)
	}
	if _, err := service.Apply(context.Background(), protectiveCommand(paused.Installation, ActionUninstall, "", "remove-1")); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("uninstall without reason err=%v, want invalid input", err)
	}
	removed, err := service.Apply(context.Background(), protectiveCommand(paused.Installation, ActionUninstall, "不再使用", "remove-2"))
	if err != nil || removed.Installation.Status != StatusUninstalled || removed.Receipt.Reason != "不再使用" {
		t.Fatalf("uninstall with reason=%+v err=%v", removed, err)
	}
}

func TestHandlerDisableTakesEmptyBodyUninstallKeepsReason(t *testing.T) {
	tenantID, authorizationID := uuid.New(), uuid.New()
	view := handlerTestView(tenantID, authorizationID)
	domain := &handlerTestDomain{mutationResult: view, getResult: view}
	handler := newHandlerForTest(t, tenantID, domain)
	path := "/v1/tenant-scopes/" + tenantID.String() + "/plugin-installations/" + authorizationID.String()
	send := func(action, body, key string) *httptest.ResponseRecorder {
		request := authenticatedHandlerRequest(http.MethodPost, path+"/"+action, bytes.NewBufferString(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("If-Match", `"7"`)
		request.Header.Set("Idempotency-Key", key)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	if response := send("disable", `{}`, "plugin-disable-1"); response.Code != http.StatusOK ||
		domain.lastMutation.Action != ActionDisable || domain.lastMutation.Reason != "" {
		t.Fatalf("disable status=%d body=%s mutation=%+v", response.Code, response.Body.String(), domain.lastMutation)
	}
	// 旧页面仍带 reason 的请求按严格解码拒绝（与 645 本机停用、resume 同一规则）。
	for name, body := range map[string]string{"reason": `{"reason":"containment"}`, "empty": ``, "array": `[]`} {
		assertHandlerError(t, send("disable", body, "plugin-disable-"+name), http.StatusBadRequest, "invalid_request")
	}
	for name, body := range map[string]string{"no reason": `{}`, "blank": `{"reason":" "}`} {
		assertHandlerError(t, send("uninstall", body, "plugin-uninstall-"+strings.ReplaceAll(name, " ", "-")),
			http.StatusBadRequest, "invalid_request")
	}
	if response := send("uninstall", `{"reason":"customer removal"}`, "plugin-uninstall-ok"); response.Code != http.StatusOK ||
		domain.lastMutation.Reason != "customer removal" {
		t.Fatalf("uninstall status=%d mutation=%+v", response.Code, domain.lastMutation)
	}
}

// 上报授权端的暂停回执不带 reason 字段（授权端 158 起接受；旧主控带原因的回执照常收下）。
func TestLifecycleReportOmitsEmptyReason(t *testing.T) {
	payload, err := json.Marshal(lifecycleReportRequestPayload{Schema: lifecycleReceiptRequestSchema,
		Action: ActionDisable, Status: StatusDisabled, OccurredAt: time.Date(2032, 4, 5, 6, 7, 8, 0, time.UTC)})
	if err != nil || bytes.Contains(payload, []byte(`"reason"`)) {
		t.Fatalf("disable report payload=%s err=%v", payload, err)
	}
}
