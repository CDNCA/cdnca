package migrations

import (
	"bytes"
	"testing"
)

func TestNodeConfigurationHPKEMigrationContract(t *testing.T) {
	up, err := FS.ReadFile("170_node_configuration_hpke.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("170_node_configuration_hpke.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte("migration 170 requires the exact verified 169 release head"),
		[]byte("e881ea03620506c0773bc8e22fa6fe93aff9b3bd5fae60feca8fafa0c0df254a"),
		[]byte("8426afd3af006fe6210de725ce39b03dab8d2c49469f85980187c05cb9e13daa"),
		[]byte("configuration_artifacts_kind_encryption_check"),
		[]byte("kind = 'configuration'"),
		[]byte("hpke_x25519_hkdf_sha256_aes_256_gcm"),
		[]byte("recipient_key_id IS NOT NULL"),
	} {
		if !bytes.Contains(up, required) {
			t.Fatalf("up migration missing %q", required)
		}
	}
	for _, required := range [][]byte{
		[]byte("migration 170 rollback requires the exact verified 170 head"),
		[]byte("140d1689a8d3ce17e34cc8bc46598711364d9fe129ec36bb3e5f591c71f8f089"),
		[]byte("migration 170 rollback would discard encrypted configuration compatibility"),
	} {
		if !bytes.Contains(down, required) {
			t.Fatalf("down migration missing %q", required)
		}
	}
	if !bytes.Contains(down, []byte("kind = 'configuration' AND encryption_algorithm = 'none'")) {
		t.Fatal("down migration does not restore legacy configuration constraint")
	}
}
