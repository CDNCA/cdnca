package originauthcontrol

import (
	"bufio"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

var openAPIResponseStatusPattern = regexp.MustCompile(`^        '([0-9]{3})':`)

func TestPublicationOpenAPIResponseMatrix(t *testing.T) {
	source, err := os.ReadFile("../../../../api/control-origin-auth.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		operationID string
		want        []string
	}{
		{"getLatestOriginAuthPublication", []string{"200", "400", "401", "403", "404", "405", "503"}},
		{"createOriginAuthPublication", []string{"201", "400", "401", "403", "404", "405", "409", "412", "422", "503"}},
	} {
		t.Run(test.operationID, func(t *testing.T) {
			block := openAPIOperationBlock(t, string(source), test.operationID)
			var got []string
			scanner := bufio.NewScanner(strings.NewReader(block))
			for scanner.Scan() {
				match := openAPIResponseStatusPattern.FindStringSubmatch(scanner.Text())
				if match != nil {
					got = append(got, match[1])
				}
			}
			if err := scanner.Err(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("response statuses = %v, want %v", got, test.want)
			}
		})
	}
}

func openAPIOperationBlock(t *testing.T, source, operationID string) string {
	t.Helper()
	marker := "      operationId: " + operationID
	start := strings.Index(source, marker)
	if start < 0 {
		t.Fatalf("operationId %q not found", operationID)
	}
	remainder := source[start+len(marker):]
	end := len(remainder)
	for _, boundary := range []string{"\n    get:", "\n    post:", "\ncomponents:"} {
		if index := strings.Index(remainder, boundary); index >= 0 && index < end {
			end = index
		}
	}
	return remainder[:end]
}
