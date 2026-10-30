package controlbackuphistoryhttp

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestBackupHistoryCanonicalOpenAPIRef(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test path")
	}
	root := filepath.Join(filepath.Dir(filename), "../../../../api")
	canonical := readBackupHistoryOpenAPITest(t, filepath.Join(root, "openapi/v1/control.yaml"))
	fragment := readBackupHistoryOpenAPITest(t, filepath.Join(root, "control-backup-history.openapi.yaml"))
	const path = "/v1/admin/system-backup-runs"
	const wantRef = "../../control-backup-history.openapi.yaml#/paths/~1v1~1admin~1system-backup-runs"
	if item, ok := canonical.Paths[path]; !ok || item.Ref != wantRef {
		t.Fatalf("canonical path %s ref=%q, want %q", path, item.Ref, wantRef)
	}
	item, ok := fragment.Paths[path]
	if !ok {
		t.Fatalf("backup history fragment omits %s", path)
	}
	var limits []any
	for _, parameter := range item.Get.Parameters {
		if parameter.Name == "limit" {
			limits = parameter.Schema.Enum
		}
	}
	if !reflect.DeepEqual(limits, []any{10, 30, 100, 300}) {
		t.Fatalf("limit enum=%v", limits)
	}
	if fragment.Components.Schemas["BackupRunHistoryPage"].Properties["items"].MaxItems != 300 {
		t.Fatal("history page must bound its items to 300")
	}
}

type backupHistoryOpenAPITestDocument struct {
	Paths map[string]struct {
		Ref string `yaml:"$ref"`
		Get struct {
			Parameters []struct {
				Name   string `yaml:"name"`
				Schema struct {
					Enum []any `yaml:"enum"`
				} `yaml:"schema"`
			} `yaml:"parameters"`
		} `yaml:"get"`
	} `yaml:"paths"`
	Components struct {
		Schemas map[string]struct {
			Properties map[string]struct {
				MaxItems int `yaml:"maxItems"`
			} `yaml:"properties"`
		} `yaml:"schemas"`
	} `yaml:"components"`
}

func readBackupHistoryOpenAPITest(t *testing.T, path string) backupHistoryOpenAPITestDocument {
	t.Helper()
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document backupHistoryOpenAPITestDocument
	if err := yaml.Unmarshal(source, &document); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return document
}
