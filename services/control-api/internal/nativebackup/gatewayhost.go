package nativebackup

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/gatewayregistry"
)

// Gateway host move: nodes that dial the Gateway by IP do not
// follow a DNS switch. A migration or a restore onto a host with another IP
// moves the co-located Gateway to the new address before the services start:
// the Gateway server certificate gets the new name in its SAN (same key,
// same root, so every node keeps verifying it with the migrated Gateway CA),
// and gateway.env, control.env (CDNCA_GATEWAY_LOCAL_*: the GatewayHello
// endpoint list), node-install-defaults and runtime-config.js name it. The
// old address stays in the SAN so a node still on it is not refused.

const (
	gatewayEnvFile   = ConfigDirectory + "/gateway.env"
	gatewayPublicKey = "CDNCA_GATEWAY_AGENT_PUBLIC_ENDPOINT"
)

// ValidGatewayHost accepts a lower-case DNS name or a canonical IP address.
func ValidGatewayHost(value string) bool {
	if ip := net.ParseIP(value); ip != nil {
		return ip.String() == value
	}
	return hostBindDomain.MatchString(value)
}

// GatewayHostResult names what RetargetGatewayHost changed.
type GatewayHostResult struct {
	Previous string   `json:"previous_gateway_host"`
	Current  string   `json:"gateway_host"`
	SAN      []string `json:"gateway_san"`
	Changed  bool     `json:"changed"`
}

// RetargetGatewayHost points the co-located Gateway at host. An unchanged
// host, or an installation without a co-located Gateway, changes nothing.
func RetargetGatewayHost(layout Layout, host string, now time.Time) (GatewayHostResult, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if !ValidGatewayHost(host) {
		return GatewayHostResult{}, fmt.Errorf("invalid Gateway host %q", host)
	}
	gateway, err := ReadEnvironmentFile(layout.Path(gatewayEnvFile))
	if errors.Is(err, os.ErrNotExist) {
		return GatewayHostResult{}, nil
	}
	if err != nil {
		return GatewayHostResult{}, err
	}
	previous, agentPort, err := net.SplitHostPort(gateway[gatewayPublicKey])
	if err != nil {
		return GatewayHostResult{}, fmt.Errorf("gateway.env %s is invalid", gatewayPublicKey)
	}
	result := GatewayHostResult{Previous: previous, Current: host}
	if previous == host {
		return result, nil
	}
	read := func(path string) ([]byte, error) { return os.ReadFile(layout.Path(path)) }
	certPEM, err := read(hostBindGatewayCert)
	if err != nil {
		return result, err
	}
	keyPEM, err := read(hostBindGatewayKey)
	if err != nil {
		return result, err
	}
	rootPEM, err := read(hostBindRootCert)
	if err != nil {
		return result, err
	}
	rootKeyPEM, err := read(hostBindRootKey)
	if err != nil {
		return result, err
	}
	reissued, san, err := addGatewaySAN(certPEM, keyPEM, rootPEM, rootKeyPEM, host, now)
	if err != nil {
		return result, err
	}
	result.SAN = san
	if reissued != nil {
		if err := writeKeepingOwner(layout.Path(hostBindGatewayCert), reissued, 0o444); err != nil {
			return result, err
		}
	}
	bracketed := bracketHost(host)
	if err := rewriteEnvironmentFile(layout.Path(gatewayEnvFile), map[string]string{gatewayPublicKey: bracketed + ":" + agentPort}); err != nil {
		return result, err
	}
	control, err := ReadEnvironmentFile(layout.Path(hostBindControlEnv))
	if err != nil {
		return result, err
	}
	enrollmentPort := portOf(control["CDNCA_GATEWAY_LOCAL_ENROLLMENT_ADDRESS"])
	if enrollmentPort == "" {
		enrollmentPort = portOf(gateway["CDNCA_GATEWAY_ENROLLMENT_ADDR"])
	}
	if local := control["CDNCA_GATEWAY_LOCAL_ADDRESS"]; local != "" {
		if err := rewriteEnvironmentFile(layout.Path(hostBindControlEnv), map[string]string{
			"CDNCA_GATEWAY_LOCAL_ADDRESS": bracketed + ":" + portOf(local), "CDNCA_GATEWAY_LOCAL_SERVER_NAME": host,
			"CDNCA_GATEWAY_LOCAL_ENROLLMENT_ADDRESS": bracketed + ":" + enrollmentPort}); err != nil {
			return result, err
		}
	}
	defaults := map[string]string{"gateway_address": bracketed + ":" + agentPort,
		"gateway_enrollment_address": bracketed + ":" + enrollmentPort, "gateway_server_name": host}
	// the one gateway writer (gatewayregistry, Q20) moves
	// the co-located Gateway and keeps CDN/page entries.
	oldLocal := gatewayregistry.Entrypoint{Address: control["CDNCA_GATEWAY_LOCAL_ADDRESS"],
		ServerName: control["CDNCA_GATEWAY_LOCAL_SERVER_NAME"], EnrollmentAddress: control["CDNCA_GATEWAY_LOCAL_ENROLLMENT_ADDRESS"]}
	if oldLocal.Address == "" {
		oldLocal.Address, oldLocal.ServerName = bracketHost(previous)+":"+agentPort, previous
	}
	newLocal := gatewayregistry.Entrypoint{Address: defaults["gateway_address"], ServerName: host,
		EnrollmentAddress: defaults["gateway_enrollment_address"]}
	if current, readErr := os.ReadFile(layout.Path(NodeInstallDefaultsFile)); readErr == nil {
		moved := gatewayregistry.ParseNodeGatewayDefaults(current).MoveLocalGateway(oldLocal, newLocal)
		if _, err := gatewayregistry.WriteNodeGatewayDefaults(layout.Path(NodeInstallDefaultsFile), moved); err != nil {
			return result, err
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return result, readErr
	}
	runtime := map[string]string{"ADDRESS": defaults["gateway_address"], "ENROLLMENT_ADDRESS": defaults["gateway_enrollment_address"], "SERVER_NAME": host}
	if _, err := rewriteIfPresent(layout.Path(WebRuntimeConfigFile), func(content []byte) []byte {
		return runtimeGateway.ReplaceAllFunc(content, func(line []byte) []byte {
			name := runtimeGateway.FindSubmatch(line)[1]
			return []byte(`window.__CDNCA_GATEWAY_` + string(name) + `__ = "` + runtime[string(name)] + `";`)
		})
	}); err != nil {
		return result, err
	}
	result.Changed = true
	return result, nil
}

var environmentKey = regexp.MustCompile(`^[A-Z0-9_]+$`)

// rewriteEnvironmentFile replaces existing KEY= lines only (keeping owner and mode).
func rewriteEnvironmentFile(path string, values map[string]string) error {
	for key := range values {
		if !environmentKey.MatchString(key) {
			return fmt.Errorf("invalid environment key %q", key)
		}
	}
	return rewriteRegularFile(path, func(content []byte) []byte {
		lines := strings.Split(string(content), "\n")
		for index, line := range lines {
			if name, _, found := strings.Cut(line, "="); found {
				if value, ok := values[name]; ok {
					lines[index] = name + "=" + value
				}
			}
		}
		return []byte(strings.Join(lines, "\n"))
	})
}

// addGatewaySAN re-signs the Gateway certificate with the same key and root,
// adding host (DNS name or IP) to the SAN. nil when it is already named.
func addGatewaySAN(certPEM, keyPEM, caCertPEM, caKeyPEM []byte, host string, now time.Time) ([]byte, []string, error) {
	current, err := parseCertificatePEM(certPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("gateway certificate: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return MergeGatewaySAN(certPEM, keyPEM, caCertPEM, caKeyPEM, host, now)
	}
	if slices.ContainsFunc(current.IPAddresses, ip.Equal) {
		return nil, sanList(current), nil
	}
	key, err := parsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("gateway key: %w", err)
	}
	ca, err := parseCertificatePEM(caCertPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("root CA: %w", err)
	}
	caKey, err := parsePrivateKeyPEM(caKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("root CA key: %w", err)
	}
	if err := current.CheckSignatureFrom(ca); err != nil {
		return nil, nil, errors.New("the gateway certificate is not issued by the installation root CA")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: current.Subject.CommonName},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(825 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, DNSNames: current.DNSNames,
		IPAddresses: append(append([]net.IP(nil), current.IPAddresses...), ip), URIs: current.URIs,
	}
	if ca.NotAfter.Before(template.NotAfter) {
		template.NotAfter = ca.NotAfter
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), caKey)
	if err != nil {
		return nil, nil, err
	}
	issued, _ := x509.ParseCertificate(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), sanList(issued), nil
}
