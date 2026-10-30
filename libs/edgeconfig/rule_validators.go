package edgeconfig

// Exported single-rule checks for compilers outside this package (the rule
// pack compiler, libs/rulepack): a rule accepted here is accepted by the node
// renderer, because it is the same code the bundle validators run.

// NormalizeSecurityRule validates one bound security policy (WAF / ACL)
// rule and returns its canonical form, exactly as a security policy
// document normalizes it.
func NormalizeSecurityRule(rule WAFRule) (WAFRule, error) { return normalizeSecurityRule(rule) }

// ValidateSecurityPolicyWAFSettings checks a bound policy's mode and auto
// block as a security policy document does (WAF policies only; auto block
// in its normalized form).
func ValidateSecurityPolicyWAFSettings(kind SecurityKind, mode WAFMode, autoBlock *WAFAutoBlock) error {
	header, err := normalizeSecurityPolicyHeader(SecurityPolicy{Kind: kind, Mode: mode, AutoBlock: autoBlock})
	if err != nil {
		return err
	}
	if (header.AutoBlock == nil) != (autoBlock == nil) || header.AutoBlock != nil && *header.AutoBlock != *autoBlock {
		return ErrInvalidConfig
	}
	return nil
}

// WAFMatchCovers reports whether every request matching current also matches
// previous (both normalized by NormalizeSecurityRule). A content inspection
// condition on previous never covers.
func WAFMatchCovers(previous, current WAFMatch) bool { return wafMatchCovers(previous, current) }

// ValidateCCV2Rule validates one CC v2 rule as a policy rule set does.
func ValidateCCV2Rule(rule CCV2Rule) error {
	return validateCCV2Rules([]CCV2Rule{rule}, map[string]struct{}{})
}
