package edgesite

import "testing"

// A19-b (L2_ROUTING): the L2 conditions' shape on the site object.
func TestValidateL2Conditions(t *testing.T) {
	pool := Pool{ID: "l2-topology", Kind: PoolL2, Endpoints: []Endpoint{{ID: "e1"}, {ID: "e2"}, {ID: "e3"}}}
	valid := func() []L2Condition {
		return []L2Condition{
			{ID: "c1", Rules: []L2Rule{{Field: "uri", Operator: "regex", Value: `^/img/.*\.png$`}}, EndpointIDs: []string{"e1", "e2"}},
			{ID: "c2", NodeIDs: []string{"018f47a2-5b9c-7d31-8a60-104c9c0b7a20"}, EndpointIDs: []string{"e3"}},
		}
	}
	if err := ValidateL2Conditions(valid(), pool); err != nil {
		t.Fatalf("valid refused: %v", err)
	}
	for name, mutate := range map[string]func([]L2Condition) []L2Condition{
		"unsorted":          func(c []L2Condition) []L2Condition { c[0].ID, c[1].ID = "c3", "c2"; return c },
		"endpoint twice":    func(c []L2Condition) []L2Condition { c[1].EndpointIDs = []string{"e2"}; return c },
		"unknown endpoint":  func(c []L2Condition) []L2Condition { c[1].EndpointIDs = []string{"e9"}; return c },
		"no endpoint":       func(c []L2Condition) []L2Condition { c[1].EndpointIDs = nil; return c },
		"node rule on node": func(c []L2Condition) []L2Condition { c[0].Rules[0].Field = "node_country"; return c },
		"operator":          func(c []L2Condition) []L2Condition { c[0].Rules[0].Operator = "glob"; return c },
		"empty value":       func(c []L2Condition) []L2Condition { c[0].Rules[0].Value = ""; return c },
		"lookahead":         func(c []L2Condition) []L2Condition { c[0].Rules[0].Value = "^/(?=a)"; return c },
		"backreference":     func(c []L2Condition) []L2Condition { c[0].Rules[0].Value = `(a)\1`; return c },
		"non-ascii regex":   func(c []L2Condition) []L2Condition { c[0].Rules[0].Value = "^/图片"; return c },
		"control byte": func(c []L2Condition) []L2Condition {
			c[0].Rules[0].Operator, c[0].Rules[0].Value = "eq", "a\nb"
			return c
		},
		"bad node id": func(c []L2Condition) []L2Condition { c[1].NodeIDs = []string{"7"}; return c },
	} {
		if ValidateL2Conditions(mutate(valid()), pool) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// a non-regex value may be any text (a Chinese host suffix, say)
	conditions := valid()
	conditions[0].Rules[0] = L2Rule{Field: "host", Operator: "suffix", Value: ".例子.测试"}
	if err := ValidateL2Conditions(conditions, pool); err != nil {
		t.Fatalf("text value refused: %v", err)
	}
	site := Site{Origin: Origin{L2: &L2{CacheOnly: true}}}
	if !site.UsesL2Routing() {
		t.Fatal("cache only needs L2_ROUTING")
	}
	site.Origin.L2.CacheOnly = false
	if site.UsesL2Routing() {
		t.Fatal("plain L2 needs L2_ROUTING")
	}
}
