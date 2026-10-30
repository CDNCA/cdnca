package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

const (
	migration117UpSHA118   = "9fa028cf6c6c65883f0289f8f12a305104e5438a10888c7970cccb08db2adccc"
	migration117DownSHA118 = "a5000b0e0561875b9533022fac293755d24a3950412aed3e2649f499c3fd4904"
	migration118UpSHA118   = "7190a136a8c7685eb20538f86c67541a183d5631b9924d16aeb2cba511a72499"
	migration118DownSHA118 = "a9535f404e8f4630bb1c0c02fca4c3ace0612021ca023603fe6ac9af76be5f1a"
)

func TestCertificatePublicationClaimsMigration118Contract(t *testing.T) {
	up := readMigration118Contract(t, "118_certificate_publication_claims.up.sql")
	down := readMigration118Contract(t, "118_certificate_publication_claims.down.sql")

	assertMigration118SHA(t, "117_api_key_ip_allowlist.up.sql", migration117UpSHA118)
	assertMigration118SHA(t, "117_api_key_ip_allowlist.down.sql", migration117DownSHA118)
	assertMigration118SHA(t, "118_certificate_publication_claims.up.sql", migration118UpSHA118)
	assertMigration118SHA(t, "118_certificate_publication_claims.down.sql", migration118DownSHA118)

	for name, sql := range map[string]string{"118 up": up, "118 down": down} {
		compact := strings.Join(strings.Fields(sql), " ")
		if !strings.Contains(compact, "9fa028cf6c6c65883f0289f8f12a305104e5438a10888c7970cccb08db2adccc") {
			t.Errorf("%s is missing the current 117 up checksum", name)
		}
		if !strings.Contains(compact, "a5000b0e0561875b9533022fac293755d24a3950412aed3e2649f499c3fd4904") {
			t.Errorf("%s is missing the frozen 117 down checksum", name)
		}
		if strings.Contains(compact, "8e216725fa6c6a7f295d1a217c30806e3b37be4cc047853cc10bdeea7e464673") {
			t.Errorf("%s still pins the superseded 117 up checksum", name)
		}
	}
	if !strings.Contains(strings.Join(strings.Fields(down), " "), "checksum_sha256='"+migration118UpSHA118+"'") {
		t.Fatal("118 down does not pin the current 118 up checksum")
	}
}

func readMigration118Contract(t *testing.T, name string) string {
	t.Helper()
	content, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func assertMigration118SHA(t *testing.T, name, want string) {
	t.Helper()
	content, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(content)); got != want {
		t.Fatalf("%s SHA-256=%s, want %s", name, got, want)
	}
}
