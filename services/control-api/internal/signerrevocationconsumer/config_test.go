package signerrevocationconsumer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testInstallationID = "d664f802-e4e9-44c2-a644-31af828aefbb"

func TestLoadConfigDisabledByDefaultAndStrictBoolean(t *testing.T) {
	unsetEnv(t, consumerEnvPrefix+"ENABLED")
	config, err := LoadConfig()
	if err != nil || config.Enabled {
		t.Fatalf("LoadConfig() missing ENABLED = %#v, %v", config, err)
	}

	t.Setenv(consumerEnvPrefix+"ENABLED", "false")
	t.Setenv(consumerEnvPrefix+"OFFLINE_ROOT_PUBLIC_KEY_BASE64", "not-a-key")
	config, err = LoadConfig()
	if err != nil || config.Enabled {
		t.Fatalf("LoadConfig() disabled = %#v, %v", config, err)
	}

	for _, value := range []string{"", "TRUE", "False", "1", " true"} {
		t.Run("reject_"+strings.ReplaceAll(value, " ", "space"), func(t *testing.T) {
			t.Setenv(consumerEnvPrefix+"ENABLED", value)
			if _, err := LoadConfig(); err == nil {
				t.Fatalf("LoadConfig() accepted ENABLED=%q", value)
			}
		})
	}
}

func TestLoadConfigEnabledDefaults(t *testing.T) {
	rootKey := bytes.Repeat([]byte{7}, ed25519.PublicKeySize)
	setValidConsumerEnv(t, rootKey)
	t.Setenv("ENTITLEMENT_TRUSTED_KEYS_FILE", "/does/not/exist-and-must-not-be-read.json")
	config, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if !config.Enabled || config.BaseURL != "https://license.example.test" ||
		config.InstallationID.String() != testInstallationID || config.InstallationPrivateKeyFile != "/run/secrets/control-key.pem" ||
		config.RefreshInterval != defaultRefreshInterval || config.RequestTimeout != defaultRequestTimeout ||
		config.StartupTimeout != defaultStartupTimeout || config.ShutdownTimeout != defaultShutdownTimeout ||
		config.TLSConfig == nil || config.TLSConfig.MinVersion != tls.VersionTLS12 || config.TLSConfig.InsecureSkipVerify ||
		config.OfflineRootKeyID != "offline-root" || config.OfflineRootGeneration != 7 ||
		!bytes.Equal(config.OfflineRootPublicKey, rootKey) {
		t.Fatalf("LoadConfig() = %#v", config)
	}
	rootKey[0] ^= 0xff
	if config.OfflineRootPublicKey[0] == rootKey[0] {
		t.Fatal("LoadConfig() retained caller public-key storage")
	}
}

func TestLoadConfigRejectsInvalidRequiredAndOfflineRootFields(t *testing.T) {
	validKey := bytes.Repeat([]byte{8}, ed25519.PublicKeySize)
	nonCanonicalKey := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	nonCanonicalKey = nonCanonicalKey[:len(nonCanonicalKey)-1] + "B"
	tests := []struct {
		name  string
		field string
		value string
	}{
		{name: "missing URL", field: "LICENSE_SERVICE_URL", value: ""},
		{name: "HTTP URL", field: "LICENSE_SERVICE_URL", value: "http://license.example.test"},
		{name: "URL path", field: "LICENSE_SERVICE_URL", value: "https://license.example.test/"},
		{name: "URL credentials", field: "LICENSE_SERVICE_URL", value: "https://user:secret@license.example.test"},
		{name: "nil installation", field: "CONTROL_INSTALLATION_ID", value: "00000000-0000-0000-0000-000000000000"},
		{name: "noncanonical installation", field: "CONTROL_INSTALLATION_ID", value: strings.ToUpper(testInstallationID)},
		{name: "missing key file", field: "CONTROL_INSTALLATION_PRIVATE_KEY_FILE", value: ""},
		{name: "invalid root ID", field: consumerEnvPrefix + "OFFLINE_ROOT_KEY_ID", value: "root key"},
		{name: "zero generation", field: consumerEnvPrefix + "OFFLINE_ROOT_GENERATION", value: "0"},
		{name: "leading-zero generation", field: consumerEnvPrefix + "OFFLINE_ROOT_GENERATION", value: "07"},
		{name: "signed generation", field: consumerEnvPrefix + "OFFLINE_ROOT_GENERATION", value: "+7"},
		{name: "overflow generation", field: consumerEnvPrefix + "OFFLINE_ROOT_GENERATION", value: "18446744073709551616"},
		{name: "short public key", field: consumerEnvPrefix + "OFFLINE_ROOT_PUBLIC_KEY_BASE64", value: base64.RawURLEncoding.EncodeToString(validKey[:31])},
		{name: "padded public key", field: consumerEnvPrefix + "OFFLINE_ROOT_PUBLIC_KEY_BASE64", value: base64.URLEncoding.EncodeToString(validKey)},
		{name: "standard public key", field: consumerEnvPrefix + "OFFLINE_ROOT_PUBLIC_KEY_BASE64", value: base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32))},
		{name: "noncanonical public key", field: consumerEnvPrefix + "OFFLINE_ROOT_PUBLIC_KEY_BASE64", value: nonCanonicalKey},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setValidConsumerEnv(t, validKey)
			t.Setenv(test.field, test.value)
			if _, err := LoadConfig(); err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("LoadConfig() error = %v", err)
			}
		})
	}
}

func TestLoadConfigDurationRanges(t *testing.T) {
	validKey := bytes.Repeat([]byte{9}, ed25519.PublicKeySize)
	tests := []struct {
		field   string
		value   string
		want    time.Duration
		invalid bool
	}{
		{consumerEnvPrefix + "REFRESH_INTERVAL", "1m", time.Minute, false},
		{consumerEnvPrefix + "REFRESH_INTERVAL", "24h", 24 * time.Hour, false},
		{consumerEnvPrefix + "REFRESH_INTERVAL", "59.999999999s", 0, true},
		{consumerEnvPrefix + "REFRESH_INTERVAL", "24h1ns", 0, true},
		{consumerEnvPrefix + "REQUEST_TIMEOUT", "1s", time.Second, false},
		{consumerEnvPrefix + "REQUEST_TIMEOUT", "30s", 30 * time.Second, false},
		{consumerEnvPrefix + "REQUEST_TIMEOUT", "999.999999ms", 0, true},
		{consumerEnvPrefix + "REQUEST_TIMEOUT", "30s1ns", 0, true},
		{consumerEnvPrefix + "STARTUP_TIMEOUT", "1s", time.Second, false},
		{consumerEnvPrefix + "STARTUP_TIMEOUT", "30s", 30 * time.Second, false},
		{consumerEnvPrefix + "STARTUP_TIMEOUT", "999ms", 0, true},
		{consumerEnvPrefix + "STARTUP_TIMEOUT", "30s1ns", 0, true},
		{consumerEnvPrefix + "SHUTDOWN_TIMEOUT", "1s", time.Second, false},
		{consumerEnvPrefix + "SHUTDOWN_TIMEOUT", "30s", 30 * time.Second, false},
		{consumerEnvPrefix + "SHUTDOWN_TIMEOUT", "999ms", 0, true},
		{consumerEnvPrefix + "SHUTDOWN_TIMEOUT", "30s1ns", 0, true},
		{consumerEnvPrefix + "REFRESH_INTERVAL", "", 0, true},
		{consumerEnvPrefix + "REQUEST_TIMEOUT", "", 0, true},
		{consumerEnvPrefix + "STARTUP_TIMEOUT", "", 0, true},
		{consumerEnvPrefix + "SHUTDOWN_TIMEOUT", "", 0, true},
		{consumerEnvPrefix + "REQUEST_TIMEOUT", " 10s", 0, true},
		{consumerEnvPrefix + "REQUEST_TIMEOUT", "invalid", 0, true},
	}
	for _, test := range tests {
		t.Run(test.field+"_"+test.value, func(t *testing.T) {
			setValidConsumerEnv(t, validKey)
			t.Setenv(test.field, test.value)
			config, err := LoadConfig()
			if test.invalid {
				if err == nil {
					t.Fatalf("LoadConfig() accepted %s=%q", test.field, test.value)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadConfig() error = %v", err)
			}
			var got time.Duration
			switch test.field {
			case consumerEnvPrefix + "REFRESH_INTERVAL":
				got = config.RefreshInterval
			case consumerEnvPrefix + "REQUEST_TIMEOUT":
				got = config.RequestTimeout
			case consumerEnvPrefix + "STARTUP_TIMEOUT":
				got = config.StartupTimeout
			case consumerEnvPrefix + "SHUTDOWN_TIMEOUT":
				got = config.ShutdownTimeout
			}
			if got != test.want {
				t.Fatalf("loaded duration = %v, want %v", got, test.want)
			}
		})
	}
}

func TestLoadConfigValidatesTLSCAFile(t *testing.T) {
	validKey := bytes.Repeat([]byte{10}, ed25519.PublicKeySize)
	certificatePEM, rawSubject := testCACertificate(t)
	directory := t.TempDir()
	validPath := filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(validPath, append(append([]byte("\n"), certificatePEM...), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	setValidConsumerEnv(t, validKey)
	t.Setenv(consumerEnvPrefix+"TLS_CA_FILE", validPath)
	config, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() valid CA error = %v", err)
	}
	found := false
	for _, subject := range config.TLSConfig.RootCAs.Subjects() {
		found = found || bytes.Equal(subject, rawSubject)
	}
	if !found {
		t.Fatal("configured CA was not installed")
	}
	exactMaximumPath := filepath.Join(directory, "exact-maximum.pem")
	exactMaximum := append(append([]byte(nil), certificatePEM...), bytes.Repeat([]byte{' '}, maximumCAFileBytes-len(certificatePEM))...)
	if err := os.WriteFile(exactMaximumPath, exactMaximum, 0o600); err != nil {
		t.Fatal(err)
	}
	multiplePath := filepath.Join(directory, "multiple.pem")
	if err := os.WriteFile(multiplePath, append(append([]byte(nil), certificatePEM...), certificatePEM...), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{exactMaximumPath, multiplePath} {
		setValidConsumerEnv(t, validKey)
		t.Setenv(consumerEnvPrefix+"TLS_CA_FILE", path)
		if _, err := LoadConfig(); err != nil {
			t.Fatalf("LoadConfig() valid TLS_CA_FILE=%q error = %v", path, err)
		}
	}

	groupWritable := filepath.Join(directory, "group-writable.pem")
	if err := os.WriteFile(groupWritable, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(groupWritable, 0o620); err != nil {
		t.Fatal(err)
	}
	otherWritable := filepath.Join(directory, "other-writable.pem")
	if err := os.WriteFile(otherWritable, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(otherWritable, 0o602); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(directory, "ca-link.pem")
	if err := os.Symlink(validPath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	junkPath := filepath.Join(directory, "junk.pem")
	if err := os.WriteFile(junkPath, append(append([]byte(nil), certificatePEM...), []byte("junk")...), 0o600); err != nil {
		t.Fatal(err)
	}
	wrongBlockPath := filepath.Join(directory, "key.pem")
	if err := os.WriteFile(wrongBlockPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}), 0o600); err != nil {
		t.Fatal(err)
	}
	headerPath := filepath.Join(directory, "header.pem")
	if err := os.WriteFile(headerPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Header": "value"}, Bytes: certificatePEM}), 0o600); err != nil {
		t.Fatal(err)
	}
	invalidCertificatePath := filepath.Join(directory, "invalid-certificate.pem")
	if err := os.WriteFile(invalidCertificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}), 0o600); err != nil {
		t.Fatal(err)
	}
	emptyPath := filepath.Join(directory, "empty.pem")
	if err := os.WriteFile(emptyPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	oversizedPath := filepath.Join(directory, "oversized.pem")
	if err := os.WriteFile(oversizedPath, bytes.Repeat([]byte{'x'}, maximumCAFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []string{
		filepath.Base(validPath), directory + "/./ca.pem", symlinkPath, directory,
		groupWritable, otherWritable, junkPath, wrongBlockPath, headerPath, invalidCertificatePath,
		emptyPath, oversizedPath, validPath + " ",
	}
	for _, path := range tests {
		t.Run(filepath.Base(path), func(t *testing.T) {
			setValidConsumerEnv(t, validKey)
			t.Setenv(consumerEnvPrefix+"TLS_CA_FILE", path)
			if _, err := LoadConfig(); err == nil {
				t.Fatalf("LoadConfig() accepted TLS_CA_FILE=%q", path)
			}
		})
	}
}

func TestLoadConfigAcceptsMaximumRootGeneration(t *testing.T) {
	setValidConsumerEnv(t, bytes.Repeat([]byte{11}, ed25519.PublicKeySize))
	t.Setenv(consumerEnvPrefix+"OFFLINE_ROOT_GENERATION", "18446744073709551615")
	config, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if config.OfflineRootGeneration != ^uint64(0) {
		t.Fatalf("OfflineRootGeneration = %d", config.OfflineRootGeneration)
	}
}

func setValidConsumerEnv(t *testing.T, rootKey []byte) {
	t.Helper()
	t.Setenv(consumerEnvPrefix+"ENABLED", "true")
	t.Setenv("LICENSE_SERVICE_URL", "https://license.example.test")
	t.Setenv("CONTROL_INSTALLATION_ID", testInstallationID)
	t.Setenv("CONTROL_INSTALLATION_PRIVATE_KEY_FILE", "/run/secrets/control-key.pem")
	unsetEnv(t, consumerEnvPrefix+"REFRESH_INTERVAL")
	unsetEnv(t, consumerEnvPrefix+"REQUEST_TIMEOUT")
	unsetEnv(t, consumerEnvPrefix+"STARTUP_TIMEOUT")
	unsetEnv(t, consumerEnvPrefix+"SHUTDOWN_TIMEOUT")
	t.Setenv(consumerEnvPrefix+"TLS_CA_FILE", "")
	t.Setenv(consumerEnvPrefix+"OFFLINE_ROOT_KEY_ID", "offline-root")
	t.Setenv(consumerEnvPrefix+"OFFLINE_ROOT_GENERATION", "7")
	t.Setenv(consumerEnvPrefix+"OFFLINE_ROOT_PUBLIC_KEY_BASE64", base64.RawURLEncoding.EncodeToString(rootKey))
}

func unsetEnv(t *testing.T, name string) {
	t.Helper()
	old, present := os.LookupEnv(name)
	if err := os.Unsetenv(name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if present {
			_ = os.Setenv(name, old)
		} else {
			_ = os.Unsetenv(name)
		}
	})
}

func testCACertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "consumer-test-root"},
		NotBefore: time.Unix(1, 0), NotAfter: time.Unix(4102444800, 0), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded}), certificate.RawSubject
}
