package certificateasset

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type certificateOpenAPIOperation struct {
	operationID      string
	permission       string
	bearerAuth       bool
	securityOverride bool
	responses        map[string]struct{}
}

type certificateYAMLDocument struct {
	paths    map[string]*yaml.Node
	security *yaml.Node
}

func TestCertificateAssetOpenAPIContract(t *testing.T) {
	repositoryRoot := filepath.Join("..", "..", "..", "..")
	root := readCertificateYAML(t, filepath.Join(repositoryRoot, "api", "openapi", "v1", "control.yaml"))
	fragment := readCertificateYAML(t, filepath.Join(repositoryRoot, "api", "control-certificate-assets.openapi.yaml"))

	rootPaths := certificatePathItems(root.paths)
	fragmentPaths := certificatePathItems(fragment.paths)
	problems := exactCertificatePathSetProblems(rootPaths)
	problems = append(problems, exactCertificatePathSetProblems(fragmentPaths)...)
	dereferenced := make(map[string]*yaml.Node, len(rootPaths))
	for path, wantRef := range expectedCertificateRootReferences() {
		pathItem, ok := rootPaths[path]
		if !ok {
			continue
		}
		fields, err := yamlMapping(pathItem)
		if err != nil {
			problems = append(problems, path+": "+err.Error())
			continue
		}
		ref, ok := scalar(fields["$ref"])
		if len(fields) != 1 || !ok || ref != wantRef {
			problems = append(problems, path+": root path item must be the exact certificate fragment reference")
			continue
		}
		resolved, ok := fragmentPaths[path]
		if !ok {
			problems = append(problems, path+": referenced fragment path is missing")
			continue
		}
		dereferenced[path] = resolved
	}
	problems = append(problems, certificateOperationProblems(
		dereferenced, root.security,
	)...)
	if len(problems) != 0 {
		t.Fatalf("root certificate OpenAPI problems: %s", strings.Join(problems, "; "))
	}
}

func TestCertificateAssetOpenAPIOperationMatrix(t *testing.T) {
	t.Parallel()
	repositoryRoot := filepath.Join("..", "..", "..", "..")
	for _, relative := range []string{
		filepath.Join("api", "openapi", "v1", "dns-acme.yaml"),
		filepath.Join("api", "control-certificate-assets.openapi.yaml"),
	} {
		t.Run(filepath.Base(relative), func(t *testing.T) {
			document := readCertificateYAML(t, filepath.Join(repositoryRoot, relative))
			problems := exactCertificatePathSetProblems(certificatePathItems(document.paths))
			problems = append(problems, certificateOperationProblems(
				certificatePathItems(document.paths), document.security,
			)...)
			if len(problems) != 0 {
				t.Fatalf("certificate OpenAPI problems: %s", strings.Join(problems, "; "))
			}
		})
	}
}

func TestCertificateAssetOpenAPIRejectsAdversarialMutations(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "api", "control-certificate-assets.openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	contract := string(source)
	extraOperation := "    put:\n      operationId: unexpectedCertificateAssetPut\n      x-required-permissions: [certificates.manage]\n      security:\n        - bearerAuth: []\n      responses:\n        '200': {description: unexpected}\n"
	tests := []struct {
		name     string
		contract string
	}{
		{name: "extra method", contract: strings.Replace(contract, "    get:\n", extraOperation+"    get:\n", 1)},
		{name: "duplicate operationId", contract: strings.Replace(contract,
			"operationId: uploadCertificateAsset", "operationId: listCertificateAssets", 1)},
		{name: "security override", contract: strings.Replace(contract,
			"      x-required-permissions: [certificates.read]\n", "      x-required-permissions: [certificates.read]\n      security: [{cdncaKeyAuth: []}]\n", 1)},
		{name: "wrong permission", contract: strings.Replace(contract,
			"      x-required-permissions: [certificates.read]", "      x-required-permissions: [certificates.manage]", 1)},
		{name: "response object duplicate key", contract: strings.Replace(contract,
			"    AssetListOK:\n      description: Certificate assets\n",
			"    AssetListOK:\n      description: Certificate assets\n      description: Duplicate certificate assets\n", 1)},
		{name: "nested schema duplicate key", contract: strings.Replace(contract,
			"    RequestMetadata:\n      type: string\n",
			"    RequestMetadata:\n      type: string\n      type: string\n", 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if problems := certificateOpenAPIProblems([]byte(test.contract)); len(problems) == 0 {
				t.Fatal("adversarial contract passed validation")
			}
		})
	}

	withoutOverrides := strings.ReplaceAll(contract, "      security:\n        - bearerAuth: []\n", "")
	for key, operation := range expectedCertificateOpenAPIOperations() {
		t.Run("matching security override "+operation.operationID, func(t *testing.T) {
			anchor := "      operationId: " + operation.operationID + "\n"
			mutated := strings.Replace(withoutOverrides, anchor, anchor+"      security: [{bearerAuth: []}]\n", 1)
			if mutated == withoutOverrides {
				t.Fatal("operationId mutation anchor is missing")
			}
			wantProblem := key + ": operation security override is forbidden"
			problems := certificateOpenAPIProblems([]byte(mutated))
			for _, problem := range problems {
				if problem == wantProblem {
					return
				}
			}
			t.Fatalf("matching security override was not rejected for the target operation: %v", problems)
		})
	}
}

func certificateOpenAPIProblems(source []byte) []string {
	document, err := parseCertificateYAML(source)
	if err != nil {
		return []string{err.Error()}
	}
	paths := certificatePathItems(document.paths)
	problems := exactCertificatePathSetProblems(paths)
	return append(problems, certificateOperationProblems(
		paths, document.security,
	)...)
}

func readCertificateYAML(t *testing.T, path string) certificateYAMLDocument {
	t.Helper()
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	document, err := parseCertificateYAML(source)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func parseCertificateYAML(source []byte) (certificateYAMLDocument, error) {
	var document yaml.Node
	if err := yaml.Unmarshal(source, &document); err != nil {
		return certificateYAMLDocument{}, err
	}
	if err := rejectDuplicateYAMLMappingKeys(&document); err != nil {
		return certificateYAMLDocument{}, err
	}
	root, err := yamlMapping(&document)
	if err != nil {
		return certificateYAMLDocument{}, err
	}
	paths, err := yamlMapping(root["paths"])
	if err != nil {
		return certificateYAMLDocument{}, fmt.Errorf("paths: %w", err)
	}
	return certificateYAMLDocument{paths: paths, security: root["security"]}, nil
}

func rejectDuplicateYAMLMappingKeys(document *yaml.Node) error {
	visited := make(map[*yaml.Node]struct{})
	var visit func(*yaml.Node) error
	visit = func(node *yaml.Node) error {
		if node == nil {
			return nil
		}
		if _, ok := visited[node]; ok {
			return nil
		}
		visited[node] = struct{}{}
		switch node.Kind {
		case yaml.DocumentNode, yaml.SequenceNode:
			for _, child := range node.Content {
				if err := visit(child); err != nil {
					return err
				}
			}
		case yaml.MappingNode:
			fields, err := yamlMapping(node)
			if err != nil {
				return err
			}
			for _, child := range fields {
				if err := visit(child); err != nil {
					return err
				}
			}
		case yaml.AliasNode:
			return visit(node.Alias)
		}
		return nil
	}
	return visit(document)
}

func yamlMapping(node *yaml.Node) (map[string]*yaml.Node, error) {
	if node == nil {
		return nil, fmt.Errorf("mapping is missing")
	}
	if node.Kind == yaml.DocumentNode {
		if len(node.Content) != 1 {
			return nil, fmt.Errorf("document must contain one root node")
		}
		node = node.Content[0]
	}
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected mapping node")
	}
	result := make(map[string]*yaml.Node, len(node.Content)/2)
	for index := 0; index < len(node.Content); index += 2 {
		keyNode, valueNode := node.Content[index], node.Content[index+1]
		if keyNode.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("mapping key must be scalar")
		}
		if _, duplicate := result[keyNode.Value]; duplicate {
			return nil, fmt.Errorf("duplicate mapping key %q", keyNode.Value)
		}
		result[keyNode.Value] = valueNode
	}
	return result, nil
}

func scalar(node *yaml.Node) (string, bool) {
	if node == nil || node.Kind != yaml.ScalarNode {
		return "", false
	}
	return node.Value, true
}

func certificatePathItems(paths map[string]*yaml.Node) map[string]*yaml.Node {
	result := make(map[string]*yaml.Node)
	for path, pathItem := range paths {
		if strings.HasPrefix(path, "/v1/certificate-assets") || path == "/v1/sites/{site_id}/certificate-binding" {
			result[path] = pathItem
		}
	}
	return result
}

func exactCertificatePathSetProblems(paths map[string]*yaml.Node) []string {
	expected := expectedCertificateRootReferences()
	problems := make([]string, 0)
	if len(paths) != len(expected) {
		problems = append(problems, fmt.Sprintf("certificate path count=%d want=%d", len(paths), len(expected)))
	}
	for path := range paths {
		if _, ok := expected[path]; !ok {
			problems = append(problems, "unexpected certificate path "+path)
		}
	}
	for path := range expected {
		if _, ok := paths[path]; !ok {
			problems = append(problems, "missing certificate path "+path)
		}
	}
	return problems
}

func certificateOperationProblems(
	paths map[string]*yaml.Node,
	defaultSecurity *yaml.Node,
) []string {
	expected := expectedCertificateOpenAPIOperations()
	actual := make(map[string]certificateOpenAPIOperation)
	problems := make([]string, 0)
	methods := map[string]struct{}{
		"get": {}, "put": {}, "post": {}, "delete": {}, "options": {}, "head": {}, "patch": {}, "trace": {},
	}
	for path, pathItem := range paths {
		fields, err := yamlMapping(pathItem)
		if err != nil {
			problems = append(problems, path+": "+err.Error())
			continue
		}
		for method, operationNode := range fields {
			if _, ok := methods[method]; !ok {
				continue
			}
			key := strings.ToUpper(method) + " " + path
			operation, operationProblems := parseCertificateOperation(operationNode, defaultSecurity)
			for _, problem := range operationProblems {
				problems = append(problems, key+": "+problem)
			}
			actual[key] = operation
		}
	}
	if len(actual) != len(expected) {
		problems = append(problems, fmt.Sprintf("certificate operation count=%d want=%d", len(actual), len(expected)))
	}
	operationIDs := make(map[string]string, len(actual))
	for key, operation := range actual {
		if previous, duplicate := operationIDs[operation.operationID]; duplicate {
			problems = append(problems, "duplicate operationId "+operation.operationID+" at "+previous+" and "+key)
		}
		operationIDs[operation.operationID] = key
		want, ok := expected[key]
		if !ok {
			problems = append(problems, "unexpected operation "+key)
			continue
		}
		if operation.operationID != want.operationID {
			problems = append(problems, key+": operationId="+operation.operationID+" want="+want.operationID)
		}
		if operation.permission != want.permission {
			problems = append(problems, key+": permission="+operation.permission+" want="+want.permission)
		}
		if !operation.bearerAuth {
			problems = append(problems, key+": Bearer authentication is not exact")
		}
		if operation.securityOverride {
			problems = append(problems, key+": operation security override is forbidden")
		}
		if !sameCertificateResponseSet(operation.responses, want.responses) {
			problems = append(problems, key+": response set differs")
		}
	}
	for key := range expected {
		if _, ok := actual[key]; !ok {
			problems = append(problems, "missing operation "+key)
		}
	}
	return problems
}

func parseCertificateOperation(node, defaultSecurity *yaml.Node) (certificateOpenAPIOperation, []string) {
	fields, err := yamlMapping(node)
	if err != nil {
		return certificateOpenAPIOperation{}, []string{err.Error()}
	}
	operationID, operationIDOK := scalar(fields["operationId"])
	permission, permissionOK := singleScalarSequence(fields["x-required-permissions"])
	security, securityOverride := fields["security"]
	if !securityOverride {
		security = defaultSecurity
	}
	responses, responseErr := yamlMapping(fields["responses"])
	problems := make([]string, 0)
	if !operationIDOK || operationID == "" {
		problems = append(problems, "operationId must be a non-empty scalar")
	}
	if !permissionOK {
		problems = append(problems, "x-required-permissions must contain exactly one scalar")
	}
	if responseErr != nil {
		problems = append(problems, "responses: "+responseErr.Error())
	}
	responseSet := make(map[string]struct{}, len(responses))
	for code := range responses {
		responseSet[code] = struct{}{}
	}
	return certificateOpenAPIOperation{
		operationID:      operationID,
		permission:       permission,
		bearerAuth:       exactBearerAuthSecurity(security),
		securityOverride: securityOverride,
		responses:        responseSet,
	}, problems
}

func singleScalarSequence(node *yaml.Node) (string, bool) {
	if node == nil || node.Kind != yaml.SequenceNode || len(node.Content) != 1 {
		return "", false
	}
	return scalar(node.Content[0])
}

func exactBearerAuthSecurity(node *yaml.Node) bool {
	if node == nil || node.Kind != yaml.SequenceNode || len(node.Content) != 1 {
		return false
	}
	requirement, err := yamlMapping(node.Content[0])
	if err != nil || len(requirement) != 1 {
		return false
	}
	scopes, ok := requirement["bearerAuth"]
	return ok && scopes.Kind == yaml.SequenceNode && len(scopes.Content) == 0
}

func expectedCertificateRootReferences() map[string]string {
	const fragment = "../../control-certificate-assets.openapi.yaml#/paths/"
	return map[string]string{
		"/v1/certificate-assets": fragment + "~1v1~1certificate-assets",
		"/v1/certificate-assets/{asset_id}": fragment +
			"~1v1~1certificate-assets~1{asset_id}",
		"/v1/certificate-assets/{asset_id}/auto-renew": fragment +
			"~1v1~1certificate-assets~1{asset_id}~1auto-renew",
		"/v1/certificate-assets/{asset_id}/disabled": fragment +
			"~1v1~1certificate-assets~1{asset_id}~1disabled",
		"/v1/certificate-assets/{asset_id}/download": fragment +
			"~1v1~1certificate-assets~1{asset_id}~1download",
		"/v1/certificate-assets/{asset_id}/versions/{version_id}/activate": fragment +
			"~1v1~1certificate-assets~1{asset_id}~1versions~1{version_id}~1activate",
		"/v1/certificate-assets/{asset_id}/bindings": fragment +
			"~1v1~1certificate-assets~1{asset_id}~1bindings",
		"/v1/certificate-assets/{asset_id}/bindings/{site_id}": fragment +
			"~1v1~1certificate-assets~1{asset_id}~1bindings~1{site_id}",
		"/v1/sites/{site_id}/certificate-binding": fragment +
			"~1v1~1sites~1{site_id}~1certificate-binding",
	}
}

func expectedCertificateOpenAPIOperations() map[string]certificateOpenAPIOperation {
	return map[string]certificateOpenAPIOperation{
		"GET /v1/certificate-assets": {
			operationID: "listCertificateAssets", permission: "certificates.read",
			responses: certificateResponseSet("200", "400", "401", "403", "405", "500"),
		},
		"POST /v1/certificate-assets": {
			operationID: "uploadCertificateAsset", permission: "certificates.manage",
			responses: certificateResponseSet("201", "400", "401", "403", "405", "409", "413", "415", "500", "503"),
		},
		"GET /v1/certificate-assets/{asset_id}": {
			operationID: "getCertificateAsset", permission: "certificates.read",
			responses: certificateResponseSet("200", "400", "401", "403", "404", "405", "500"),
		},
		"DELETE /v1/certificate-assets/{asset_id}": {
			operationID: "deleteCertificateAsset", permission: "certificates.manage",
			responses: certificateResponseSet("200", "400", "401", "403", "404", "405", "409", "413", "415", "500"),
		},
		"PATCH /v1/certificate-assets/{asset_id}/auto-renew": {
			operationID: "setCertificateAssetAutoRenew", permission: "certificates.manage",
			responses: certificateResponseSet("200", "400", "401", "403", "404", "405", "409", "413", "415", "500"),
		},
		"PATCH /v1/certificate-assets/{asset_id}/disabled": {
			operationID: "setCertificateAssetDisabled", permission: "certificates.manage",
			responses: certificateResponseSet("200", "400", "401", "403", "404", "405", "409", "413", "415", "500"),
		},
		"GET /v1/certificate-assets/{asset_id}/download": {
			operationID: "downloadCertificateAsset", permission: "certificates.manage",
			responses: certificateResponseSet("200", "400", "401", "403", "404", "405", "409", "500", "503"),
		},
		"POST /v1/certificate-assets/{asset_id}/versions/{version_id}/activate": {
			operationID: "activateCertificateAssetVersion", permission: "certificates.manage",
			responses: certificateResponseSet("200", "400", "401", "403", "404", "405", "409", "413", "415", "500"),
		},
		"GET /v1/certificate-assets/{asset_id}/bindings": {
			operationID: "listCertificateAssetBindings", permission: "certificates.read",
			responses: certificateResponseSet("200", "400", "401", "403", "404", "405", "500"),
		},
		"POST /v1/certificate-assets/{asset_id}/bindings": {
			operationID: "bindCertificateAsset", permission: "certificates.manage",
			responses: certificateResponseSet("200", "400", "401", "403", "404", "405", "409", "413", "415", "500"),
		},
		"DELETE /v1/certificate-assets/{asset_id}/bindings/{site_id}": {
			operationID: "unbindCertificateAsset", permission: "certificates.manage",
			responses: certificateResponseSet("200", "400", "401", "403", "404", "405", "409", "413", "415", "500"),
		},
		"GET /v1/sites/{site_id}/certificate-binding": {
			operationID: "getCertificateSiteBinding", permission: "certificates.read",
			responses: certificateResponseSet("200", "400", "401", "403", "404", "405", "500"),
		},
	}
}

func certificateResponseSet(codes ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(codes))
	for _, code := range codes {
		result[code] = struct{}{}
	}
	return result
}

func sameCertificateResponseSet(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for code := range left {
		if _, ok := right[code]; !ok {
			return false
		}
	}
	return true
}
