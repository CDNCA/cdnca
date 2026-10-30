// Command crscorpus turns the OWASP CRS regression tests (tests/regression/tests
// of the pinned CRS source) into the attack corpus of cdnca-waf-check -only eval:
// every test whose first stage expects its own rule to fire, in the rule groups
// the WAF tiers cover. Raw/encoded requests are skipped (they test the HTTP
// parser, not the rules). Output: JSON array on stdout.
//
//	crscorpus <tests dir> <rules dir>
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type sample struct {
	ID      string            `json:"id"`
	Rule    int               `json:"rule"`
	PL      int               `json:"pl"`
	Method  string            `json:"method"`
	URI     string            `json:"uri"`
	Headers map[string]string `json:"headers"`
	Data    string            `json:"data"`
}

type testFile struct {
	RuleID int `yaml:"rule_id"`
	Tests  []struct {
		TestID int `yaml:"test_id"`
		Stages []struct {
			Input struct {
				Method  string            `yaml:"method"`
				URI     string            `yaml:"uri"`
				Headers map[string]string `yaml:"headers"`
				Data    any               `yaml:"data"`
				Encoded string            `yaml:"encoded_request"`
			} `yaml:"input"`
			Output struct {
				Log struct {
					ExpectIDs []int `yaml:"expect_ids"`
				} `yaml:"log"`
			} `yaml:"output"`
		} `yaml:"stages"`
	} `yaml:"tests"`
}

var groups = []string{"930", "931", "932", "933", "934", "941", "942", "944"}

// paranoia reads each rule's paranoia level tag from the CRS rule files.
func paranoia(dir string) map[int]int {
	levels := map[int]int{}
	files, _ := filepath.Glob(filepath.Join(dir, "REQUEST-9*.conf"))
	rule := regexp.MustCompile(`id:(9[0-9]{5})`)
	tag := regexp.MustCompile(`paranoia-level/([1-4])`)
	for _, file := range files {
		raw, _ := os.ReadFile(file)
		text := strings.ReplaceAll(string(raw), "\\\n", " ")
		for _, block := range regexp.MustCompile(`\n(?:SecRule|SecAction)`).Split(text, -1) {
			id, level := rule.FindStringSubmatch(block), tag.FindStringSubmatch(block)
			if id != nil && level != nil {
				n, _ := strconv.Atoi(id[1])
				levels[n], _ = strconv.Atoi(level[1])
			}
		}
	}
	return levels
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: crscorpus <tests dir> <rules dir>")
		os.Exit(2)
	}
	levels := paranoia(os.Args[2])
	out := []sample{}
	seen := map[string]bool{}
	for _, group := range groups {
		dirs, _ := filepath.Glob(filepath.Join(os.Args[1], "REQUEST-"+group+"-*"))
		for _, dir := range dirs {
			files, _ := filepath.Glob(filepath.Join(dir, "*.yaml"))
			sort.Strings(files)
			for _, file := range files {
				raw, err := os.ReadFile(file)
				var doc testFile
				if err != nil || yaml.Unmarshal(raw, &doc) != nil {
					continue
				}
				for _, test := range doc.Tests {
					if len(test.Stages) == 0 {
						continue
					}
					stage := test.Stages[0]
					expected := false
					for _, id := range stage.Output.Log.ExpectIDs {
						expected = expected || id == doc.RuleID
					}
					if !expected || stage.Input.Encoded != "" {
						continue
					}
					data := ""
					switch value := stage.Input.Data.(type) {
					case string:
						data = value
					case []any:
						parts := make([]string, len(value))
						for index, part := range value {
							parts[index] = fmt.Sprint(part)
						}
						data = strings.Join(parts, "\r\n")
					}
					headers := map[string]string{}
					for name, value := range stage.Input.Headers {
						switch strings.ToLower(name) {
						case "host", "content-length", "connection", "transfer-encoding":
						default:
							headers[name] = value
						}
					}
					method := stage.Input.Method
					if method == "" {
						method = "GET"
					}
					// go-ftw (the CRS regression runner) sends a body without a Content-Type as a form;
					// without it ModSecurity never parses the body into ARGS and the test cannot match.
					if data != "" && !hasHeader(headers, "content-type") {
						headers["Content-Type"] = "application/x-www-form-urlencoded"
					}
					// YAML multipart bodies use bare LF; on the wire (and in go-ftw) they are CRLF,
					// which ModSecurity's multipart parser requires.
					if strings.HasPrefix(strings.ToLower(headerValue(headers, "content-type")), "multipart/") {
						data = strings.ReplaceAll(strings.ReplaceAll(data, "\r\n", "\n"), "\n", "\r\n")
					}
					uri := stage.Input.URI
					if uri == "" {
						uri = "/"
					}
					key, _ := json.Marshal([]any{method, uri, headers, data})
					if seen[string(key)] {
						continue
					}
					seen[string(key)] = true
					out = append(out, sample{ID: fmt.Sprintf("crs-%d-%d", doc.RuleID, test.TestID), Rule: doc.RuleID,
						PL: levels[doc.RuleID], Method: method, URI: uri, Headers: headers, Data: data})
				}
			}
		}
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(out); err != nil {
		os.Exit(1)
	}
}

func headerValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func hasHeader(headers map[string]string, name string) bool {
	for key := range headers {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}
