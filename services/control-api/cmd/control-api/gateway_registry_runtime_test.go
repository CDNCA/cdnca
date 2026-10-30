package main

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/gatewayregistry"
)

// K1: the co-located Gateway's public node channel comes from control.env.
func TestGatewayRegistryRuntimeConfigReadsTheLocalGateway(t *testing.T) {
	env := map[string]string{
		"CDNCA_GATEWAY_CLIENT_CA_CERT_FILE": "/pki/c.pem", "CDNCA_GATEWAY_CLIENT_CA_KEY_FILE": "/pki/c-key.pem",
		"CDNCA_GATEWAY_ROOT_CA_CERT_FILE": "/pki/r.pem", "CDNCA_GATEWAY_ROOT_CA_KEY_FILE": "/pki/r-key.pem",
		"CDNCA_GATEWAY_LOCAL_ADDRESS": "control.example.com:9444", "CDNCA_GATEWAY_LOCAL_SERVER_NAME": "control.example.com",
		"CDNCA_GATEWAY_LOCAL_ENROLLMENT_ADDRESS": "control.example.com:9443",
	}
	const id = "00000000-0000-4000-8000-0000000000aa"
	c, enabled, err := loadGatewayRegistryRuntimeConfig(func(key string) string { return env[key] }, id, "/pki/node.pem")
	if err != nil || !enabled || c.localGateway != (gatewayregistry.Entrypoint{Address: "control.example.com:9444", ServerName: "control.example.com",
		Transport: gatewayregistry.TransportGRPC, EnrollmentAddress: "control.example.com:9443"}) {
		t.Fatalf("local gateway = %+v %v %v", c.localGateway, enabled, err)
	}
	delete(env, "CDNCA_GATEWAY_LOCAL_SERVER_NAME")
	if _, _, err := loadGatewayRegistryRuntimeConfig(func(key string) string { return env[key] }, id, "/pki/node.pem"); err == nil {
		t.Fatal("partial local Gateway accepted")
	}
	delete(env, "CDNCA_GATEWAY_LOCAL_ADDRESS")
	delete(env, "CDNCA_GATEWAY_LOCAL_ENROLLMENT_ADDRESS")
	if c, _, err := loadGatewayRegistryRuntimeConfig(func(key string) string { return env[key] }, id, "/pki/node.pem"); err != nil || c.localGateway.Address != "" {
		t.Fatalf("unset local gateway = %+v %v", c.localGateway, err)
	}
}
