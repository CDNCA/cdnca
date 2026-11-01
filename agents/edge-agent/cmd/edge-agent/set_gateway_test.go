package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
)

func writeSetGatewayFixture(t *testing.T) (configPath, journal string) {
	t.Helper()
	root := secureConfigTempDir(t)
	config := validFileConfig()
	config.JournalDir = filepath.Join(root, "journal")
	config.DeploymentRoot = filepath.Join(root, "deployments")
	config.CertificateRuntime.StateRoot = filepath.Join(root, "certificates")
	config.Gateway.Address = "203.0.113.10:19444"
	config.Gateway.ServerName = "203.0.113.10"
	config.Gateway.EnrollmentAddress = "203.0.113.10:29443"
	content, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeConfig(content); err != nil {
		t.Fatalf("fixture configuration: %v", err)
	}
	configDir := filepath.Join(root, "etc")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath = filepath.Join(configDir, "config.json")
	if err := os.WriteFile(configPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath, config.JournalDir
}

func TestSetGatewayRewritesAddressAndActiveEndpointKeepingTheRest(t *testing.T) {
	configPath, journal := writeSetGatewayFixture(t)
	// The daemon already ran once: the active endpoint record exists.
	store, err := gatewayclient.NewFileGatewayEndpointStateStore(filepath.Join(journal, "gateway-endpoint"),
		gatewayclient.GatewayEndpointState{Address: "203.0.113.10:19444", ServerName: "203.0.113.10"})
	if err != nil {
		t.Fatal(err)
	}
	_ = store
	before, _ := os.ReadFile(configPath)
	var stdout, stderr bytes.Buffer
	code := setGatewayCommand([]string{"--config", configPath, "--address", "198.51.100.7:19444"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	after, _ := os.ReadFile(configPath)
	decoded, _, err := decodeConfig(after)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Gateway.Address != "198.51.100.7:19444" || decoded.Gateway.ServerName != "198.51.100.7" ||
		decoded.Gateway.EnrollmentAddress != "198.51.100.7:29443" {
		t.Fatalf("gateway after set-gateway: %+v", decoded.Gateway)
	}
	original, _, _ := decodeConfig(before)
	original.Gateway.Address, original.Gateway.ServerName, original.Gateway.EnrollmentAddress =
		decoded.Gateway.Address, decoded.Gateway.ServerName, decoded.Gateway.EnrollmentAddress
	left, _ := json.Marshal(original)
	right, _ := json.Marshal(decoded)
	if !bytes.Equal(left, right) {
		t.Fatal("set-gateway changed configuration fields other than the gateway address")
	}
	reopened, err := gatewayclient.NewFileGatewayEndpointStateStore(filepath.Join(journal, "gateway-endpoint"),
		gatewayclient.GatewayEndpointState{Address: "unused:1", ServerName: "unused"})
	if err != nil {
		t.Fatal(err)
	}
	if active := reopened.Active(); active.Address != "198.51.100.7:19444" || active.ServerName != "198.51.100.7" {
		t.Fatalf("active endpoint %+v", active)
	}
	// Repeating it changes nothing.
	stdout.Reset()
	if code := setGatewayCommand([]string{"--config", configPath, "--address", "198.51.100.7:19444"}, nil, &stdout, &stderr); code != 0 ||
		!strings.Contains(stdout.String(), "unchanged") {
		t.Fatalf("second run: %d %s %s", code, stdout.String(), stderr.String())
	}
}

func TestSetGatewayWithDomainAndExplicitEnrollment(t *testing.T) {
	configPath, _ := writeSetGatewayFixture(t)
	var stdout, stderr bytes.Buffer
	code := setGatewayCommand([]string{"--config", configPath, "--address", "gw.example.com:19444",
		"--enrollment-address", "gw.example.com:19443"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	content, _ := os.ReadFile(configPath)
	decoded, _, _ := decodeConfig(content)
	if decoded.Gateway.ServerName != "gw.example.com" || decoded.Gateway.EnrollmentAddress != "gw.example.com:19443" {
		t.Fatalf("gateway %+v", decoded.Gateway)
	}
}

func TestSetGatewayRejectsBadInputWithoutWriting(t *testing.T) {
	configPath, _ := writeSetGatewayFixture(t)
	before, _ := os.ReadFile(configPath)
	for _, args := range [][]string{
		{"--config", configPath},
		{"--config", configPath, "--address", "no-port"},
		{"--config", configPath, "--address", "https://x:1"},
		{"--config", configPath, "--address", "x.example.com:0"},
	} {
		var stdout, stderr bytes.Buffer
		if code := setGatewayCommand(args, nil, &stdout, &stderr); code == 0 {
			t.Fatalf("%v accepted", args)
		}
	}
	after, _ := os.ReadFile(configPath)
	if !bytes.Equal(before, after) {
		t.Fatal("a rejected set-gateway changed the configuration")
	}
}
