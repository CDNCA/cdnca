package edgeconfig

import ()

func legacyWAFHostPortSpec() Spec {
	spec := validSpec()
	spec.Sites[0].WAF = WAFPolicy{
		DefaultAction: WAFAllow,
		Rules: []WAFRule{{
			Match: WAFMatch{
				Host:       "waf-target.example.test",
				Port:       18082,
				Method:     "GET",
				Path:       &WAFPathMatch{Kind: WAFPathExact, Value: "/host-port"},
				Header:     &WAFHeaderMatch{Name: "X-WAF-Token", Kind: WAFHeaderExact, Value: "strict"},
				SourceCIDR: "192.0.2.0/24",
			},
			Action: WAFDeny, Control: WAFStop,
		}},
	}
	return spec
}
