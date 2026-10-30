package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

// bindOptions drive `agent-gateway bind` (ADR 0013 §3.2, GW-10): the
// gateway installer runs it once with the one-time token from the control
// plane's Gateway page.
type bindOptions struct {
	controlOrigin  string
	token          string
	rootCAFile     string
	outputDir      string
	enrollmentPort int
	agentPort      int
	version        string
	httpClient     *http.Client
}

type bindResponse struct {
	GatewayID            string `json:"gateway_id"`
	InstallationID       string `json:"installation_id"`
	WorkloadURISAN       string `json:"workload_uri_san"`
	ClientCertificatePEM string `json:"client_certificate_pem"`
	ServerCertificatePEM string `json:"server_certificate_pem"`
	RootCAPEM            string `json:"root_ca_pem"`
	NodeCAPEM            string `json:"node_ca_pem"`
	Endpoints            struct {
		ControlInternalAddress    string `json:"control_internal_address"`
		ControlInternalServerName string `json:"control_internal_server_name"`
		RedisURL                  string `json:"redis_url"`
		NATSURL                   string `json:"nats_url"`
		TelemetryNATSURL          string `json:"telemetry_nats_url"`
	} `json:"endpoints"`
}

// runBindCommand parses `agent-gateway bind` flags; the token is read from
// stdin so it never appears in a process argument list.
func runBindCommand(ctx context.Context, args []string, stdin io.Reader) error {
	flags := flag.NewFlagSet("bind", flag.ContinueOnError)
	var options bindOptions
	flags.StringVar(&options.controlOrigin, "control", "", "control-plane HTTPS origin")
	flags.StringVar(&options.rootCAFile, "root-ca", "", "installation root CA downloaded from <control>/downloads/gateway-ca.pem")
	flags.StringVar(&options.outputDir, "output", "", "directory for keys, certificates and binding.env")
	flags.IntVar(&options.enrollmentPort, "enrollment-port", 0, "Gateway enrollment port")
	flags.IntVar(&options.agentPort, "agent-port", 0, "Gateway agent channel port")
	flags.StringVar(&options.version, "version", "", "Gateway version")
	if err := flags.Parse(args); err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, 1024))
	if err != nil {
		return err
	}
	options.token = strings.TrimSpace(string(raw))
	return runBind(ctx, options)
}

func runBind(ctx context.Context, options bindOptions) error {
	origin, err := url.Parse(options.controlOrigin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || strings.Trim(origin.Path, "/") != "" || origin.RawQuery != "" {
		return errors.New("--control must be an https origin")
	}
	if options.enrollmentPort < 1 || options.enrollmentPort > 65535 || options.agentPort < 1 || options.agentPort > 65535 ||
		options.enrollmentPort == options.agentPort || !validVersion(options.version) || options.outputDir == "" {
		return errors.New("invalid bind options")
	}
	rootPEM, err := os.ReadFile(options.rootCAFile)
	if err != nil {
		return fmt.Errorf("read root CA: %w", err)
	}
	root, err := singleCertificate(rootPEM)
	if err != nil || !root.IsCA {
		return errors.New("root CA file is not a CA certificate")
	}
	// The token carries the root CA fingerprint: a control address that
	// serves a different root (hijacked DNS, wrong host) is refused before
	// anything is sent.
	parts := strings.Split(options.token, ".")
	sum := sha256.Sum256(root.Raw)
	if len(parts) != 4 || parts[0] != "gwt1" || subtle.ConstantTimeCompare([]byte(parts[2]), []byte(hex.EncodeToString(sum[:16]))) != 1 {
		return errors.New("binding token does not belong to the control plane that served this root CA")
	}
	clientKey, clientCSR, err := newEd25519CSR()
	if err != nil {
		return err
	}
	serverKey, serverCSR, err := newP256CSR()
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{"token": options.token, "client_csr_der": clientCSR, "server_csr_der": serverCSR,
		"enrollment_port": options.enrollmentPort, "agent_port": options.agentPort, "version": options.version})
	client := options.httpClient
	if client == nil {
		// Public certificate (Let's Encrypt) or the installation root CA.
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		pool.AddCert(root)
		client = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(origin.String(), "/")+"/v1/gateway-bindings/complete", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("binding request failed: %w", err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		var envelope struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(payload, &envelope)
		return fmt.Errorf("binding refused: HTTP %d %s", response.StatusCode, envelope.Error.Code)
	}
	var result bindResponse
	if err := json.Unmarshal(payload, &result); err != nil {
		return errors.New("binding response is not valid JSON")
	}
	if err := validateBindResponse(result, root, clientKey.Public(), &serverKey.PublicKey); err != nil {
		return err
	}
	return writeBinding(options, result, clientKey, serverKey)
}

func validateBindResponse(result bindResponse, root *x509.Certificate, clientPublic, serverPublic any) error {
	id, err := uuid.Parse(result.GatewayID)
	if err != nil || id.String() != result.GatewayID || result.WorkloadURISAN != boundGatewayURIPrefix+result.GatewayID {
		return errors.New("binding response has an invalid Gateway identity")
	}
	client, err := singleCertificate([]byte(result.ClientCertificatePEM))
	if err != nil || !publicKeyMatches(client.PublicKey, clientPublic) {
		return errors.New("binding response client certificate does not match the generated key")
	}
	// The client certificate comes from the Gateway client CA (ControlInternal
	// verifies it); the server certificate must chain to the root nodes trust.
	server, err := singleCertificate([]byte(result.ServerCertificatePEM))
	if err != nil || !publicKeyMatches(server.PublicKey, serverPublic) {
		return errors.New("binding response server certificate does not match the generated key")
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := server.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return errors.New("binding response server certificate is not signed by the installation root CA")
	}
	e := result.Endpoints
	if e.ControlInternalAddress == "" || !validServerName(e.ControlInternalServerName) || e.RedisURL == "" || e.NATSURL == "" || e.TelemetryNATSURL == "" {
		return errors.New("binding response has incomplete endpoints")
	}
	for _, value := range []string{e.ControlInternalAddress, e.ControlInternalServerName, e.RedisURL, e.NATSURL, e.TelemetryNATSURL, result.InstallationID} {
		if strings.ContainsAny(value, "\r\n") {
			return errors.New("binding response contains invalid characters")
		}
	}
	return nil
}

func writeBinding(options bindOptions, result bindResponse, clientKey ed25519.PrivateKey, serverKey *ecdsa.PrivateKey) error {
	if err := os.MkdirAll(options.outputDir, 0o700); err != nil {
		return err
	}
	clientDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		return err
	}
	serverDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return err
	}
	dir := options.outputDir
	env := strings.Join([]string{
		"CDNCA_GATEWAY_INSTANCE_ID=" + result.GatewayID,
		"CDNCA_CONTROL_ADDRESS=" + result.Endpoints.ControlInternalAddress,
		"CDNCA_CONTROL_SERVER_NAME=" + result.Endpoints.ControlInternalServerName,
		"CDNCA_CONTROL_CLIENT_CERT_FILE=" + filepath.Join(dir, "control-client.pem"),
		"CDNCA_CONTROL_CLIENT_KEY_FILE=" + filepath.Join(dir, "control-client-key.pem"),
		"CDNCA_CONTROL_SERVER_CA_FILE=" + filepath.Join(dir, "root-ca.pem"),
		"CDNCA_CONTROL_CLIENT_WORKLOAD_URI_SAN=" + result.WorkloadURISAN,
		"CDNCA_GATEWAY_TLS_CERT_FILE=" + filepath.Join(dir, "server.pem"),
		"CDNCA_GATEWAY_TLS_KEY_FILE=" + filepath.Join(dir, "server-key.pem"),
		"CDNCA_GATEWAY_AGENT_CLIENT_CA_FILE=" + filepath.Join(dir, "node-ca.pem"),
		"CDNCA_REDIS_URL=" + result.Endpoints.RedisURL,
		"CDNCA_NATS_URL=" + result.Endpoints.NATSURL,
		"CDNCA_TELEMETRY_NATS_URL=" + result.Endpoints.TelemetryNATSURL,
	}, "\n") + "\n"
	for _, file := range []struct {
		name     string
		contents []byte
		mode     os.FileMode
	}{
		{"control-client-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientDER}), 0o600},
		{"server-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverDER}), 0o600},
		{"control-client.pem", []byte(result.ClientCertificatePEM), 0o644},
		{"server.pem", []byte(result.ServerCertificatePEM), 0o644},
		{"root-ca.pem", []byte(result.RootCAPEM), 0o644},
		{"node-ca.pem", []byte(result.NodeCAPEM), 0o644},
		{"binding.env", []byte(env), 0o600},
	} {
		if err := writeFileAtomic(filepath.Join(dir, file.name), file.contents, file.mode); err != nil {
			return err
		}
	}
	return nil
}

func newEd25519CSR() (ed25519.PrivateKey, []byte, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "cdnca-agent-gateway"}}, key)
	return key, csr, err
}

func newP256CSR() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "cdnca-agent-gateway"}}, key)
	return key, csr, err
}

func singleCertificate(contents []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(contents)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected one PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func base64Std(value string) ([]byte, error) { return base64.StdEncoding.DecodeString(value) }
