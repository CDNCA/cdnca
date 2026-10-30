package waf

import "testing"

func TestSecurityRequestFactsFailClosedBeforeRuleMatching(t *testing.T) {
	policy := compileForTest(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: 11, Rules: []Rule{}})
	tests := []struct {
		name   string
		mutate func(*Request)
	}{
		{name: "empty host", mutate: func(request *Request) { request.Host = "" }},
		{name: "host with port", mutate: func(request *Request) { request.Host = "example.test:443" }},
		{name: "host with control", mutate: func(request *Request) { request.Host = "example.test\n" }},
		{name: "non-ASCII host", mutate: func(request *Request) { request.Host = "example.测试" }},
		{name: "empty method", mutate: func(request *Request) { request.Method = "" }},
		{name: "method separator", mutate: func(request *Request) { request.Method = "GE T" }},
		{name: "empty path", mutate: func(request *Request) { request.Path = "" }},
		{name: "relative path", mutate: func(request *Request) { request.Path = "admin" }},
		{name: "path with control", mutate: func(request *Request) { request.Path = "/admin\x00" }},
		{name: "invalid UTF-8 path", mutate: func(request *Request) { request.Path = string([]byte{'/', 0xff}) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validRequestForTest()
			test.mutate(&request)
			decision := (&Evaluator{}).EvaluateAt(policy, request, fixedEvaluationTime())
			if decision.Action != ActionBlock || decision.Reason != reasonInvalidRequest ||
				decision.RuleID != "" || decision.Version != policy.PolicyVersion {
				t.Fatalf("decision = %#v, want block/request_limit", decision)
			}
		})
	}
}

func TestSecurityRequestFactsKeepCanonicalEdgeInputsCompatible(t *testing.T) {
	policy := compileForTest(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: 12, Rules: []Rule{}})
	request := validRequestForTest()
	request.Host = "EXAMPLE.TEST."
	request.Method = "get"
	request.Path = "/objects/%2E"

	decision := (&Evaluator{}).EvaluateAt(policy, request, fixedEvaluationTime())
	if decision.Action != ActionAllow || decision.Reason != reasonNoMatch || decision.Version != policy.PolicyVersion {
		t.Fatalf("decision = %#v, want allow/no_match", decision)
	}
}
