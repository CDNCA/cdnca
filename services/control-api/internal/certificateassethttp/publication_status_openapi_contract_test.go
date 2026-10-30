package certificateassethttp

import (
	"bytes"
	"os"
	"testing"
)

func TestCertificatePublicationStatusOpenAPIContract48(t *testing.T) {
	fragment, err := os.ReadFile("../../../../api/control-certificate-publications.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.ReadFile("../../../../api/openapi/v1/control.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte("security:\n  - bearerAuth: []"),
		[]byte("  /v1/certificate-publications:"),
		[]byte("      operationId: listCertificatePublicationStatuses"),
		[]byte("  /v1/certificate-publications/{site_id}/revisions/{revision}:"),
		[]byte("      operationId: getCertificatePublicationStatus"),
		[]byte("      x-required-permissions: [certificates.read]"),
		[]byte("enum: [pending, leased, retry_wait, succeeded, permanent_failed]"),
		[]byte("enum: [publish, unpublish]"),
		[]byte("required: [items, snapshot_at]"),
		[]byte("required: [current, history]"),
		[]byte("certificate_publication_invalid_cursor"),
		[]byte("certificate_publication_permission_denied"),
		[]byte("certificate_publication_internal_error"),
	} {
		if !bytes.Contains(fragment, required) {
			t.Fatalf("certificate publication OpenAPI fragment missing %q", required)
		}
	}
	for _, required := range [][]byte{
		[]byte("  /v1/certificate-publications:\n    $ref: '../../control-certificate-publications.openapi.yaml#/paths/~1v1~1certificate-publications'"),
		[]byte("  /v1/certificate-publications/{site_id}/revisions/{revision}:\n    $ref: '../../control-certificate-publications.openapi.yaml#/paths/~1v1~1certificate-publications~1{site_id}~1revisions~1{revision}'"),
	} {
		if !bytes.Contains(root, required) {
			t.Fatalf("canonical control contract missing %q", required)
		}
	}
	for _, forbidden := range [][]byte{
		[]byte("private_key"),
		[]byte("lease_owner"),
		[]byte("lease_token"),
		[]byte("last_error"),
	} {
		if bytes.Contains(fragment, forbidden) {
			t.Fatalf("certificate publication status contract exposes internal field %q", forbidden)
		}
	}
}
