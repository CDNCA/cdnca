//go:build integration

package edgepublish

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// Origin forwarding end to end in PG (migration 376): a site's forwarding
// settings reach the signed v2 document, and its custom origin CA travels
// as the publication object <sha256> (scope file origin-trust/<sha256>.pem).
func TestSiteRuntimeV2PublishCarriesOriginForwarding(t *testing.T) {
	fixture := newPublishFixture(t)
	site := fixture.createSiteWithPortSets(t, "runtime-v2-forwarding.example.test", []string{"80"}, []string{}, false)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "forwarding CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	digest := sha256.Sum256([]byte(ca))
	if _, err := fixture.pool.Exec(t.Context(), `
		UPDATE site_origin_pools SET balance_method='sticky',sticky_source='cookie',sticky_name='sid',
			request_host_mode='custom',request_host='bucket.origin.test',origin_scheme='https',
			tls_sni='bucket.origin.test',tls_trust='custom',tls_ca_pem=$2,tls_ca_sha256=$3,
			websocket_allowed_origins=ARRAY['https://app.example.test'],trusted_proxy_cidrs=ARRAY['10.0.0.0/8']::cidr[]
		WHERE site_id=$1`, site.Site.ID, ca, digest[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO site_origin_trust_bundles(sha256,pem) VALUES($1,$2)`, digest[:], ca); err != nil {
		t.Fatal(err)
	}
	nodeKey := seedV2DefaultNode(t, fixture, fixture.nodeID)
	result, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(
		fixture, "runtime-v2-forwarding", fixture.nodeID, siteRuntimeV2Schema))
	if err != nil {
		t.Fatal(err)
	}
	var canonical string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT convert_from(canonical_snapshot,'UTF8') FROM config_versions WHERE id=$1`,
		result.ConfigVersionID).Scan(&canonical); err != nil {
		t.Fatal(err)
	}
	trust := "sha256:" + hex.EncodeToString(digest[:])
	for _, want := range []string{
		`"algorithm":"sticky"`, `"sticky":{"name":"sid","source":"cookie"}`,
		`"request_host":{"mode":"custom","value":"bucket.origin.test"}`,
		`"scheme":"https"`, `"sni":"bucket.origin.test"`, `"trust_ref":"` + trust + `"`,
		`"forwarding":{"trusted_proxy_cidrs":["10.0.0.0/8"],"websocket_origins":["https://app.example.test"]}`,
	} {
		if !strings.Contains(canonical, want) {
			t.Fatalf("published document lacks %s:\n%s", want, canonical)
		}
	}
	// The CA reaches the node as the publication object named by the anchor.
	release := receivedV2Release(t, fixture, result, fixture.nodeID, nodeKey)
	if got := string(release.Objects[hex.EncodeToString(digest[:])]); got != ca {
		t.Fatalf("the node's release lacks the origin CA (objects %v)", keysOf(release.Objects))
	}
}

func keysOf(files map[string][]byte) []string {
	result := make([]string, 0, len(files))
	for path := range files {
		result = append(result, path)
	}
	return result
}
