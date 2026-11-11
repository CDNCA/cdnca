package contentrewrite

// MaxTestBody is the largest body the console's tester accepts.
const MaxTestBody = 256 << 10

// TestResult is what the tester shows: the body as the node would send it.
type TestResult struct {
	Body         string   `json:"body"`
	MatchedRules []string `json:"matched_rules"`
	Replacements int      `json:"replacements"`
	Truncated    bool     `json:"truncated"`
}

// Test runs normalized settings on one response, as the node would: the
// rules whose path and content type match, the same streaming engine.
func Test(settings Settings, siteHosts []string, path, contentType string, body []byte) (TestResult, error) {
	result := TestResult{Body: string(body), MatchedRules: []string{}}
	node, ids, err := compile(settings, siteHosts)
	if err != nil || node == nil {
		return result, err
	}
	typeKey := TypeKey(contentType)
	active := node.Active(path, typeKey)
	if typeKey == "" || len(active) == 0 {
		return result, nil
	}
	for _, index := range active {
		result.MatchedRules = append(result.MatchedRules, ids[index])
	}
	stream := NewStream(node, active, typeKey)
	result.Body = string(stream.Write(body, true))
	result.Replacements, result.Truncated = stream.Replacements, stream.Truncated
	return result, nil
}
