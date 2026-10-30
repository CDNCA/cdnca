package artifactsync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/entitlement/enginemodule/enginemoduletest"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/google/uuid"
)

var testInstallationID = uuid.MustParse("00000000-0000-4000-8000-0000000000a1")

type testSigner struct{ key ed25519.PrivateKey }

func (signer testSigner) KeyID() string { return "artifact-key" }
func (signer testSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.key, payload), nil
}

func testRuleEntry(t *testing.T) (artifactcatalog.Entry, []byte) {
	t.Helper()
	entry, content, err := artifactcatalog.RulesetEntry(rulecatalog.CurrentSeed()[0], "", true)
	if err != nil {
		t.Fatal(err)
	}
	return entry, content
}

func testSigned(t *testing.T, entries []artifactcatalog.Entry) artifactcatalog.Signed {
	t.Helper()
	now := time.Now()
	signed, err := artifactcatalog.Sign(t.Context(), artifactcatalog.Envelope{DeliveryID: uuid.NewString(),
		InstallationID: testInstallationID.String(), ScopeRevision: 1, SignedAt: now.Unix(),
		ValidFrom: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix()},
		artifactcatalog.Catalog{Schema: artifactcatalog.CatalogSchema, Entries: entries},
		testSigner{ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// The client signs both requests with the installation key, accepts only the
// exact response shapes and never reads more bytes than the entry declares.
func TestClientResolveAndFetch(t *testing.T) {
	installation := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32))
	entry, content := testRuleEntry(t)
	signed := testSigned(t, []artifactcatalog.Entry{entry})
	var handler func(http.ResponseWriter, *http.Request, []byte)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		handler(response, request, body)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient("http://license.test", nil); err == nil {
		t.Fatal("plain http base URL accepted")
	}
	resolveReply := func(override func(map[string]any)) func(http.ResponseWriter, *http.Request, []byte) {
		return func(response http.ResponseWriter, request *http.Request, body []byte) {
			var resolve artifactcatalog.ResolveRequest
			if request.URL.Path != artifactcatalog.ResolvePath || json.Unmarshal(body, &resolve) != nil {
				t.Errorf("resolve request %s %s", request.URL.Path, body)
			}
			proof, _ := base64.RawURLEncoding.DecodeString(resolve.Proof)
			if !ed25519.Verify(installation.Public().(ed25519.PublicKey), artifactcatalog.ResolveProofMessage(resolve), proof) {
				t.Error("resolve proof does not verify")
			}
			reply := map[string]any{"schema": artifactcatalog.ResolveResponseSchema, "request_id": resolve.RequestID,
				"installation_id": resolve.InstallationID, "resolved_at": 1, "not_modified": false, "delivery": signed}
			if override != nil {
				override(reply)
			}
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(reply)
		}
	}
	resolve := func() (artifactcatalog.ResolveResponse, error) {
		return client.Resolve(t.Context(), testInstallationID, "1.0.35", nil, installation, time.Now())
	}

	handler = resolveReply(nil)
	if got, err := resolve(); err != nil || got.Delivery == nil || got.Delivery.Envelope.DeliveryID != signed.Envelope.DeliveryID {
		t.Fatalf("resolve = %+v, %v", got, err)
	}
	handler = resolveReply(func(reply map[string]any) { reply["not_modified"], reply["delivery"] = true, nil })
	if got, err := resolve(); err != nil || !got.NotModified || got.Delivery != nil {
		t.Fatalf("not modified = %+v, %v", got, err)
	}
	for name, override := range map[string]func(map[string]any){
		"both":          func(reply map[string]any) { reply["not_modified"] = true },
		"neither":       func(reply map[string]any) { reply["delivery"] = nil },
		"other request": func(reply map[string]any) { reply["request_id"] = "other" },
		"unknown field": func(reply map[string]any) { reply["extra"] = 1 },
		"bad delivery":  func(reply map[string]any) { reply["delivery"] = map[string]any{"envelope": 1} },
	} {
		handler = resolveReply(override)
		if _, err := resolve(); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
	handler = func(response http.ResponseWriter, _ *http.Request, _ []byte) {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusForbidden)
		_, _ = response.Write([]byte(`{"code":"installation_denied"}`))
	}
	var serviceErr *ServiceError
	if _, err := resolve(); !errors.As(err, &serviceErr) || serviceErr.StatusCode != 403 || serviceErr.Code != "installation_denied" {
		t.Fatalf("service error = %v", err)
	}

	fetchReply := func(payload []byte, mediaType string) func(http.ResponseWriter, *http.Request, []byte) {
		return func(response http.ResponseWriter, request *http.Request, body []byte) {
			var fetch artifactcatalog.FetchRequest
			if request.URL.Path != artifactcatalog.FetchPath || json.Unmarshal(body, &fetch) != nil ||
				fetch.ArtifactID != entry.ArtifactID || fetch.Revision != entry.Revision || fetch.SHA256 != entry.SHA256 {
				t.Errorf("fetch request %s %s", request.URL.Path, body)
			}
			proof, _ := base64.RawURLEncoding.DecodeString(fetch.Proof)
			if !ed25519.Verify(installation.Public().(ed25519.PublicKey), artifactcatalog.FetchProofMessage(fetch), proof) {
				t.Error("fetch proof does not verify")
			}
			response.Header().Set("Content-Type", mediaType)
			_, _ = response.Write(payload)
		}
	}
	fetch := func() ([]byte, error) {
		return client.Fetch(t.Context(), testInstallationID, entry, installation, time.Now())
	}
	handler = fetchReply(content, artifactcatalog.FetchMediaType)
	if got, err := fetch(); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("fetch = %d bytes, %v", len(got), err)
	}
	handler = fetchReply(append(append([]byte(nil), content...), 'x'), artifactcatalog.FetchMediaType)
	if _, err := fetch(); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("oversized fetch error = %v", err)
	}
	handler = fetchReply(content, "application/json")
	if _, err := fetch(); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("wrong media type error = %v", err)
	}
}

// Bytes are checked against their signed entry and must decode to what it
// names; anything else is a content mismatch the syncer rejects.
func TestVerifyArtifact(t *testing.T) {
	entry, content := testRuleEntry(t)
	if err := VerifyArtifact(entry, content); err != nil {
		t.Fatalf("valid ruleset rejected: %v", err)
	}
	tampered := bytes.Clone(content)
	tampered[len(tampered)/2] ^= 1
	if err := VerifyArtifact(entry, tampered); !errors.Is(err, artifactcatalog.ErrContentMismatch) {
		t.Fatalf("tampered bytes error = %v", err)
	}
	other := entry
	other.Kind = "dataset"
	if err := VerifyArtifact(other, content); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unknown kind error = %v", err)
	}
	// Engine modules: structure and identity only (the node judges the
	// platform signature, so an untrusted signer still passes here).
	seed := sha256.Sum256([]byte("any release key"))
	module := enginemoduletest.Encoded(t, []enginemoduletest.Signer{{KeyID: "release-x", Private: ed25519.NewKeyFromSeed(seed[:])}},
		enginemoduletest.Options{})
	moduleEntry, err := artifactcatalog.EngineModuleEntry(module, 1, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifact(moduleEntry, module); err != nil {
		t.Fatalf("engine module rejected: %v", err)
	}
	if err := VerifyArtifact(moduleEntry, content); !errors.Is(err, artifactcatalog.ErrContentMismatch) {
		t.Fatalf("engine module entry with other bytes error = %v", err)
	}
	if RejectionCode(artifactcatalog.ErrDigestMismatch) != CodeDigestMismatch ||
		RejectionCode(errors.Join(artifactcatalog.ErrInvalidSignature, errors.New("x"))) != CodeInvalidSignature {
		t.Fatal("rejection codes")
	}
}
