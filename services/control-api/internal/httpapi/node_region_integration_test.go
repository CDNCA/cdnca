package httpapi

import (
	"net/http"
	"strings"
	"testing"

	nodedomain "github.com/cdnca/cdnca/services/control-api/internal/node"
	"github.com/google/uuid"
)

// D8: a node that registers through the install script must be able to join
// a line group. Line groups use catalogued regions, so a registered node is
// put into the only catalogued region automatically, an administrator can
// pick the region when initializing, and a node already used by a line group
// cannot be moved to a different region behind that group's back.

func seedCatalogRegions(t *testing.T, env registrationTestEnv, names ...string) {
	t.Helper()
	for _, name := range names {
		if _, err := env.pool.Exec(t.Context(), `INSERT INTO region_catalog(id,platform_scope_id,name) VALUES($1,$2,$3)`,
			uuid.New(), env.scopeID, name); err != nil {
			t.Fatal(err)
		}
	}
}

func storedNodeRegion(t *testing.T, env registrationTestEnv, nodeID uuid.UUID) string {
	t.Helper()
	var region string
	if err := env.pool.QueryRow(t.Context(), `SELECT region FROM nodes WHERE id=$1`, nodeID).Scan(&region); err != nil {
		t.Fatal(err)
	}
	return region
}

func TestNodeRegistrationUsesTheOnlyCatalogRegion(t *testing.T) {
	env := newRegistrationTestEnv(t)
	seedCatalogRegions(t, env, "默认区域")
	credential := env.credential(t, http.MethodGet, "/v1/nodes/registration-credential")
	created := env.register(t, env.url, registrationBody(credential.Credential, strings.Repeat("d4", 32), "edge-d8"), http.StatusCreated)
	if created.Node.Region != "默认区域" || storedNodeRegion(t, env, created.Node.ID) != "默认区域" {
		t.Fatalf("registered node region = %q, want the only catalogued region", created.Node.Region)
	}
}

func TestNodeRegistrationLeavesRegionEmptyWithSeveralCatalogRegions(t *testing.T) {
	env := newRegistrationTestEnv(t)
	seedCatalogRegions(t, env, "华东", "华南")
	credential := env.credential(t, http.MethodGet, "/v1/nodes/registration-credential")
	created := env.register(t, env.url, registrationBody(credential.Credential, strings.Repeat("e5", 32), "edge-d8"), http.StatusCreated)
	if created.Node.Region != "" {
		t.Fatalf("registered node region = %q, want empty with several catalogued regions", created.Node.Region)
	}
}

func TestNodeInitializationRegion(t *testing.T) {
	env := newRegistrationTestEnv(t)
	credential := env.credential(t, http.MethodGet, "/v1/nodes/registration-credential")
	fingerprints := []string{strings.Repeat("f6", 32), strings.Repeat("a7", 32)}
	nodes := make([]nodedomain.Node, len(fingerprints))
	for index, fingerprint := range fingerprints {
		nodes[index] = env.register(t, env.url, registrationBody(credential.Credential, fingerprint, "edge-init"), http.StatusCreated).Node
		if nodes[index].Region != "" {
			t.Fatalf("node registered before any region = %q", nodes[index].Region)
		}
		seedRegisteredNodeCertificate(t, env, nodes[index].ID)
	}

	// Registered before the region existed: initializing puts it into the
	// only catalogued region.
	seedCatalogRegions(t, env, "默认区域")
	path := env.url + "/v1/nodes/" + nodes[0].ID.String()
	response := nodeWriteRequest(t, env.client, http.MethodPatch, path, map[string]any{"admin_state": "active"},
		env.admin, "init-only-region", `"1"`, "init-only-region")
	var initialized nodedomain.Node
	decodeResponse(t, response, http.StatusOK, &initialized)
	if initialized.AdminState != nodedomain.StateActive || initialized.Region != "默认区域" {
		t.Fatalf("initialized node = %+v, want active in the only catalogued region", initialized)
	}

	// With several regions the administrator chooses one in the same request.
	seedCatalogRegions(t, env, "华南")
	path = env.url + "/v1/nodes/" + nodes[1].ID.String()
	response = nodeWriteRequest(t, env.client, http.MethodPatch, path, map[string]any{"admin_state": "active", "region": "华南"},
		env.admin, "init-chosen-region", `"1"`, "init-chosen-region")
	decodeResponse(t, response, http.StatusOK, &initialized)
	if initialized.AdminState != nodedomain.StateActive || initialized.Region != "华南" {
		t.Fatalf("initialized node = %+v, want active in the chosen region", initialized)
	}
}

func TestNodeBatchInitializationUsesTheOnlyCatalogRegion(t *testing.T) {
	env := newRegistrationTestEnv(t)
	credential := env.credential(t, http.MethodGet, "/v1/nodes/registration-credential")
	item := env.register(t, env.url, registrationBody(credential.Credential, strings.Repeat("d1", 32), "edge-batch"), http.StatusCreated).Node
	seedRegisteredNodeCertificate(t, env, item.ID)
	seedCatalogRegions(t, env, "默认区域")
	response := nodeWriteRequest(t, env.client, http.MethodPost, env.url+"/v1/nodes/batch-admin-state",
		map[string]any{"admin_state": "active", "items": []map[string]any{{"id": item.ID, "expected_revision": item.Revision}}},
		env.admin, "batch-init-region", "", "batch-init-region")
	var result nodedomain.BatchAdminStateResult
	decodeResponse(t, response, http.StatusOK, &result)
	if len(result.Items) != 1 || result.Items[0].Status != "updated" || storedNodeRegion(t, env, item.ID) != "默认区域" {
		t.Fatalf("batch initialization = %+v, region %q", result, storedNodeRegion(t, env, item.ID))
	}
}

func TestNodeRegionChangeKeepsLineGroupsConsistent(t *testing.T) {
	env := newRegistrationTestEnv(t)
	credential := env.credential(t, http.MethodGet, "/v1/nodes/registration-credential")
	item := env.register(t, env.url, registrationBody(credential.Credential, strings.Repeat("b8", 32), "edge-grouped"), http.StatusCreated).Node
	free := env.register(t, env.url, registrationBody(credential.Credential, strings.Repeat("c9", 32), "edge-free"), http.StatusCreated).Node
	// seedLineGroupEndpoint creates a line group in region "" using the node
	// at 192.0.2.10, so the node must own that address.
	if _, err := env.pool.Exec(t.Context(), `UPDATE nodes SET ipv4='192.0.2.10' WHERE id=$1`, item.ID); err != nil {
		t.Fatal(err)
	}
	seedLineGroupEndpoint(t, env, item.ID)

	path := env.url + "/v1/nodes/" + item.ID.String()
	moved := nodeWriteRequest(t, env.client, http.MethodPatch, path, map[string]any{"region": "华东"},
		env.admin, "region-move-grouped", `"1"`, "region-move-grouped")
	assertError(t, moved, http.StatusConflict, "node_region_in_use", "")
	if region := storedNodeRegion(t, env, item.ID); region != "" {
		t.Fatalf("refused region change was stored: %q", region)
	}
	// Other fields of a grouped node, and its unchanged region, still save.
	same := nodeWriteRequest(t, env.client, http.MethodPatch, path, map[string]any{"region": "", "description": "kept"},
		env.admin, "region-same-grouped", `"1"`, "region-same-grouped")
	decodeResponse(t, same, http.StatusOK, &nodedomain.Node{})

	// A node in no line group moves freely.
	freePath := env.url + "/v1/nodes/" + free.ID.String()
	response := nodeWriteRequest(t, env.client, http.MethodPatch, freePath, map[string]any{"region": "华东"},
		env.admin, "region-move-free", `"1"`, "region-move-free")
	var updated nodedomain.Node
	decodeResponse(t, response, http.StatusOK, &updated)
	if updated.Region != "华东" {
		t.Fatalf("free node region = %q", updated.Region)
	}
}
