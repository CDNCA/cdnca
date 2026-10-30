package controlupgrade

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func licenseResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}
}

func TestLicenseClientRequestedArtifactUsesProofV2(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize))
	installationID := uuid.MustParse("00000000-0000-4000-8000-000000000071")
	requested := "00000000-0000-4000-8000-0000000000a1"
	transport := roundTripUpgradeFunc(func(request *http.Request) (*http.Response, error) {
		var body struct {
			Component           string `json:"component"`
			CurrentVersion      string `json:"current_version"`
			ProtocolVersion     int    `json:"protocol_version"`
			Proof               string `json:"proof"`
			RequestedArtifactID string `json:"requested_artifact_id"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body.RequestedArtifactID != requested {
			t.Fatalf("body = %#v, %v", body, err)
		}
		proof, _ := base64.RawURLEncoding.DecodeString(body.Proof)
		message := upgradeLengthPrefixedDigest("cdnca-upgrade-grant-request-proof/v2", request.Header.Get("Idempotency-Key"),
			installationID.String(), body.Component, body.CurrentVersion, strconv.Itoa(body.ProtocolVersion), requested)
		if !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), message, proof) {
			t.Fatal("v2 proof does not bind the requested artifact")
		}
		return licenseResponse(http.StatusConflict, `{"code":"upgrade_target_blocked","reason_code":"schema_downgrade","request_id":"r"}`+"\n"), nil
	})
	client, err := NewLicenseClient("https://license.example.test", transport, installationID, privateKey, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.IssueParentGrant(context.Background(), ParentGrantRequest{IdempotencyKey: "parent-v2", Component: "control-api",
		CurrentVersion: "1.0.35", ProtocolVersion: 1, RequestedArtifactID: requested})
	var blocked *UpgradeTargetBlockedError
	if !errors.As(err, &blocked) || blocked.Reason != "schema_downgrade" || !errors.Is(err, ErrResourceUnavailable) {
		t.Fatalf("blocked error = %v", err)
	}
	if _, err := client.IssueParentGrant(context.Background(), ParentGrantRequest{IdempotencyKey: "parent-v2", Component: "control-api",
		CurrentVersion: "1.0.35", ProtocolVersion: 1, RequestedArtifactID: "not-a-uuid"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid requested artifact = %v", err)
	}
}

func TestLicenseClientListUpgradeOptions(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x72}, ed25519.SeedSize))
	installationID := uuid.MustParse("00000000-0000-4000-8000-000000000072")
	now := time.Unix(1_800_000_000, 0)
	reply := func(status int, body string) roundTripUpgradeFunc {
		return func(request *http.Request) (*http.Response, error) {
			payload, _ := io.ReadAll(request.Body)
			if request.URL.Path != "/activation/v1/installations/"+installationID.String()+"/upgrade-options:list" ||
				string(payload) != `{"schema":"cdnca.upgrade.options.request/v1","component":"control-api","current_version":"1.0.35","protocol_version":1}` {
				t.Fatalf("request = %s %s", request.URL.Path, payload)
			}
			proof, _ := base64.RawURLEncoding.DecodeString(request.Header.Get("X-CDNCA-Proof"))
			message := upgradeLengthPrefixedDigest("cdnca-upgrade-options-request-proof/v1", http.MethodPost, request.URL.Path,
				request.Header.Get("Idempotency-Key"), installationID.String(), request.Header.Get("X-CDNCA-Requested-At"),
				base64.RawURLEncoding.EncodeToString(sha256Bytes(payload)))
			if !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), message, proof) ||
				request.Header.Get("X-CDNCA-Requested-At") != strconv.FormatInt(now.Unix(), 10) {
				t.Fatal("options proof invalid")
			}
			return licenseResponse(status, body), nil
		}
	}
	input := UpgradeOptionsRequest{IdempotencyKey: "options-1", Component: "control-api", CurrentVersion: "1.0.35", ProtocolVersion: 1}
	good := `{"schema":"cdnca.upgrade.options/v1","installation_id":"` + installationID.String() + `","component":"control-api",` +
		`"current_version":"1.0.35","current_schema_head":300,"target_mode":"follow_channel","items":[` +
		`{"artifact_id":"00000000-0000-4000-8000-0000000000b1","version":"1.0.36","release_notes":"n","published_at":1,"operation":"upgrade","control_schema_head":301,"channel_target":true,"pinned":false,"selectable":true,"reason":""},` +
		`{"artifact_id":"00000000-0000-4000-8000-0000000000b0","version":"1.0.35","release_notes":"","published_at":1,"operation":"reinstall","control_schema_head":300,"channel_target":false,"pinned":false,"selectable":false,"reason":"same_version"}]}` + "\n"
	client, _ := NewLicenseClient("https://license.example.test", reply(http.StatusOK, good), installationID, privateKey, func() time.Time { return now })
	options, err := client.ListUpgradeOptions(context.Background(), input)
	if err != nil || len(options.Items) != 2 || !options.Items[0].Selectable || options.Items[1].Reason != "same_version" {
		t.Fatalf("options = %#v, %v", options, err)
	}
	for name, test := range map[string]struct {
		status int
		body   string
		want   error
	}{
		// No fallback for a license service without the list: it is an error.
		"no list route":          {http.StatusNotFound, `{"code":"not_found"}`, ErrLicenseUnavailable},
		"list method refused":    {http.StatusMethodNotAllowed, `{}`, ErrLicenseUnavailable},
		"foreign installation":   {http.StatusOK, strings.Replace(good, installationID.String(), uuid.NewString(), 1), ErrLicenseUnavailable},
		"selectable with reason": {http.StatusOK, strings.Replace(good, `"selectable":true,"reason":""`, `"selectable":true,"reason":"x"`, 1), ErrLicenseUnavailable},
		"unavailable":            {http.StatusServiceUnavailable, `{}`, ErrLicenseUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			client, _ := NewLicenseClient("https://license.example.test", reply(test.status, test.body), installationID, privateKey,
				func() time.Time { return now })
			if _, err := client.ListUpgradeOptions(context.Background(), input); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestLicenseIssueErrorKeepsBusinessRefusalCode(t *testing.T) {
	var refused *LicenseRefusalError
	if err := licenseIssueError(http.StatusConflict, []byte(`{"code":"upgrade_plan_artifact_bundle_unavailable","request_id":"x"}`)); !errors.As(err, &refused) ||
		refused.Code != "upgrade_plan_artifact_bundle_unavailable" || !errors.Is(err, ErrResourceUnavailable) {
		t.Fatalf("409 refusal = %v", err)
	}
	if err := licenseIssueError(http.StatusForbidden, []byte(`{"code":"installation_banned","request_id":"x"}`)); !errors.As(err, &refused) ||
		refused.Code != "installation_banned" || !errors.Is(err, ErrGrantInvalid) {
		t.Fatalf("403 refusal = %v", err)
	}
	var blocked *UpgradeTargetBlockedError
	if err := licenseIssueError(http.StatusConflict, []byte(`{"code":"upgrade_target_blocked","reason_code":"same_version","request_id":"x"}`)); !errors.As(err, &blocked) ||
		blocked.Reason != "same_version" {
		t.Fatalf("blocked = %v", err)
	}
	for _, test := range []struct {
		status int
		body   string
		want   error
	}{
		{http.StatusServiceUnavailable, `{"code":"signer_unavailable"}`, ErrLicenseUnavailable},
		{http.StatusInternalServerError, `{"code":"internal_error"}`, ErrLicenseUnavailable},
		{http.StatusGatewayTimeout, `{"code":"timeout"}`, ErrLicenseOutcomeUnknown},
		{http.StatusConflict, `not json`, ErrResourceUnavailable},
		{http.StatusConflict, `{"code":"Bad Code!"}`, ErrResourceUnavailable},
	} {
		err := licenseIssueError(test.status, []byte(test.body))
		if errors.As(err, &refused) || !errors.Is(err, test.want) {
			t.Fatalf("%d %s = %v, want %v", test.status, test.body, err, test.want)
		}
	}
}
