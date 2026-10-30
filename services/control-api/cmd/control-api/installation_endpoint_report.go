package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementsync"
	"github.com/google/uuid"
)

const installationEndpointSchema = "cdnca.installation-endpoint-report/v1"

type installationEndpointRequest struct {
	Schema         string `json:"schema"`
	RequestID      string `json:"request_id"`
	InstallationID string `json:"installation_id"`
	ControlURL     string `json:"control_url"`
	GatewayHost    string `json:"gateway_host"`
	EnrollmentPort int    `json:"enrollment_port"`
	ControlPort    int    `json:"control_port"`
	ObservedAt     string `json:"observed_at"`
}

func installationEndpointProofMessage(request installationEndpointRequest) []byte {
	hash := sha256.New()
	var size [4]byte
	for _, field := range []string{"cdnca-installation-endpoint-report-proof/v1", request.Schema, request.RequestID,
		request.InstallationID, request.ControlURL, request.GatewayHost, strconv.Itoa(request.EnrollmentPort),
		strconv.Itoa(request.ControlPort), request.ObservedAt} {
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(field))
	}
	return hash.Sum(nil)
}

func decodeInstallationEndpointJSON(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return errors.New("invalid endpoint JSON object")
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return errors.New("duplicate or invalid endpoint JSON field")
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("invalid endpoint JSON value")
		}
	}
	if _, err := decoder.Token(); err != nil {
		return errors.New("invalid endpoint JSON")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing endpoint JSON")
	}
	decoder = json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return errors.New("invalid endpoint JSON fields")
	}
	return nil
}

func validateInstallationEndpointRequest(request installationEndpointRequest) error {
	installationID, installationErr := uuid.Parse(request.InstallationID)
	requestID, requestErr := uuid.Parse(request.RequestID)
	observed, observedErr := time.Parse(time.RFC3339, request.ObservedAt)
	control, controlErr := url.Parse(request.ControlURL)
	if request.Schema != installationEndpointSchema || installationErr != nil || installationID == uuid.Nil || installationID.String() != request.InstallationID ||
		requestErr != nil || requestID == uuid.Nil || requestID.String() != request.RequestID || observedErr != nil || observed.Unix() <= 0 || observed.Nanosecond() != 0 || observed.UTC().Format(time.RFC3339) != request.ObservedAt ||
		controlErr != nil || control.Scheme != "https" || control.Hostname() == "" || control.User != nil || control.Opaque != "" || control.Path != "" || control.RawPath != "" ||
		control.RawQuery != "" || control.ForceQuery || control.Fragment != "" || control.String() != request.ControlURL || len(request.ControlURL) > 2048 ||
		request.GatewayHost == "" || len(request.GatewayHost) > 253 || strings.ContainsAny(request.GatewayHost, "/@?#\\ \t\r\n") ||
		request.EnrollmentPort < 1 || request.EnrollmentPort > 65535 || request.ControlPort < 1 || request.ControlPort > 65535 || request.EnrollmentPort == request.ControlPort {
		return errors.New("invalid installation endpoint request")
	}
	return nil
}

func runReportInstallationEndpoints(args []string) error {
	flags := flag.NewFlagSet("report-installation-endpoints", flag.ContinueOnError)
	licenseService := flags.String("license-service", "", "HTTPS authorization-service origin")
	installationKey := flags.String("installation-key", "", "owner-only Ed25519 installation private key")
	requestFile := flags.String("request-file", "", "owner-only persistent endpoint request JSON")
	refresh := flags.Bool("refresh-request", false, "explicitly recapture endpoints with a new request ID and observation time, preserving the old request")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *licenseService == "" || *installationKey == "" || *requestFile == "" {
		return errors.New("usage: control-api report-installation-endpoints --license-service URL --installation-key FILE --request-file FILE [--refresh-request]")
	}
	base, err := url.Parse(*licenseService)
	if err != nil || base.Scheme != "https" || base.Hostname() == "" || base.User != nil || base.Opaque != "" || base.Path != "" || base.RawPath != "" || base.RawQuery != "" || base.ForceQuery || base.Fragment != "" {
		return errors.New("authorization server must be an HTTPS origin without credentials or path")
	}
	info, err := os.Lstat(*requestFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 16<<10 {
		return errors.New("endpoint request must be a private regular file no larger than 16 KiB")
	}
	owner, owned := info.Sys().(*syscall.Stat_t)
	if !owned || owner.Uid != uint32(os.Geteuid()) {
		return errors.New("endpoint request must be owned by the current user")
	}
	file, err := os.Open(*requestFile)
	if err != nil {
		return errors.New("cannot open endpoint request")
	}
	defer file.Close()
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, opened) {
		return errors.New("endpoint request changed while opening")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, (16<<10)+1))
	if err != nil || len(encoded) > 16<<10 {
		return errors.New("cannot read endpoint request")
	}
	var request installationEndpointRequest
	if decodeInstallationEndpointJSON(encoded, &request) != nil || validateInstallationEndpointRequest(request) != nil {
		return errors.New("invalid endpoint request file")
	}
	key, err := entitlementsync.LoadPrivateKey(*installationKey)
	if err != nil {
		return errors.New("cannot load private installation signing key")
	}
	defer clear(key)
	if *refresh {
		backup, err := os.OpenFile(*requestFile+"."+request.RequestID+".previous", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return errors.New("cannot preserve previous endpoint request")
		}
		_, writeErr := backup.Write(encoded)
		syncErr := backup.Sync()
		closeErr := backup.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			return errors.New("cannot preserve previous endpoint request")
		}
		request.RequestID, request.ObservedAt = uuid.NewString(), time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
		encoded, err = json.Marshal(request)
		if err != nil {
			return err
		}
		temporary, err := os.CreateTemp(filepath.Dir(*requestFile), ".endpoint-request-*")
		if err != nil {
			return errors.New("cannot prepare endpoint request")
		}
		defer os.Remove(temporary.Name())
		_, writeErr = temporary.Write(encoded)
		syncErr, closeErr = temporary.Sync(), temporary.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil || os.Rename(temporary.Name(), *requestFile) != nil {
			return errors.New("cannot persist refreshed endpoint request")
		}
		directory, err := os.Open(filepath.Dir(*requestFile))
		if err != nil {
			return errors.New("cannot sync refreshed endpoint request directory")
		}
		syncErr, closeErr = directory.Sync(), directory.Close()
		if syncErr != nil || closeErr != nil {
			return errors.New("cannot sync refreshed endpoint request directory")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if err := reportInstallationEndpoints(ctx, client, base.String(), request, key); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "installation endpoint report accepted")
	return nil
}

func reportInstallationEndpoints(ctx context.Context, client *http.Client, origin string, request installationEndpointRequest, key ed25519.PrivateKey) error {
	if validateInstallationEndpointRequest(request) != nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid endpoint report input")
	}
	body, err := json.Marshal(struct {
		installationEndpointRequest
		Signature string `json:"signature"`
	}{request, base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, installationEndpointProofMessage(request)))})
	if err != nil {
		return err
	}
	target := origin + "/activation/v1/installations/" + request.InstallationID + "/endpoints:report"
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return errors.New("invalid endpoint report URL")
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Idempotency-Key", request.RequestID)
	transport := *client
	transport.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := transport.Do(httpRequest)
	if err != nil {
		return errors.New("endpoint report transport failed; retry the same private request file")
	}
	defer response.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(response.Body, (16<<10)+1))
	if err != nil || len(encoded) > 16<<10 {
		return errors.New("invalid endpoint report response")
	}
	if response.StatusCode != http.StatusOK {
		var failure struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(encoded, &failure)
		if failure.Code == "request_expired" {
			return errors.New("endpoint request expired; verify addresses and use --refresh-request explicitly")
		}
		return fmt.Errorf("endpoint report rejected (HTTP %d); retry the same private request file", response.StatusCode)
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	var receipt struct {
		installationEndpointRequest
		ReceivedAt string `json:"received_at"`
	}
	if mediaErr != nil || mediaType != "application/json" || decodeInstallationEndpointJSON(encoded, &receipt) != nil || receipt.installationEndpointRequest != request {
		return errors.New("endpoint report receipt did not match the signed request")
	}
	receivedAt, err := time.Parse(time.RFC3339Nano, receipt.ReceivedAt)
	observedAt, _ := time.Parse(time.RFC3339, request.ObservedAt)
	if err != nil || receivedAt.IsZero() || receivedAt.Before(observedAt.Add(-5*time.Minute)) || receivedAt.After(time.Now().Add(5*time.Minute)) || !strings.HasSuffix(receipt.ReceivedAt, "Z") {
		return errors.New("invalid endpoint report receipt time")
	}
	return nil
}
