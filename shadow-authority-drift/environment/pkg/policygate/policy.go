package policygate

// ResolvePolicy applies scenario defaults and policy_overrides.
func ResolvePolicy(requireCheckpoint, blockPartner, resetDomain bool, overrides map[string]interface{}) (bool, bool, bool, []string) {
	prefixes := make([]string, 0)
	if overrides == nil {
		return requireCheckpoint, blockPartner, resetDomain, prefixes
	}
	if v, ok := overrides["require_checkpoint_on_internal"]; ok {
		if b, ok := toBool(v); ok {
			requireCheckpoint = b
		}
	}
	if v, ok := overrides["block_partner_to_privileged"]; ok {
		if b, ok := toBool(v); ok {
			blockPartner = b
		}
	}
	if v, ok := overrides["reset_trust_domain_on_revoke"]; ok {
		if b, ok := toBool(v); ok {
			resetDomain = b
		}
	}
	if v, ok := overrides["require_checkpoint_prefixes"]; ok {
		if arr, ok := v.([]interface{}); ok {
			for _, item := range arr {
				if s, ok := item.(string); ok && s != "" {
					prefixes = append(prefixes, s)
				}
			}
		}
	}
	return requireCheckpoint, blockPartner, resetDomain, prefixes
}

// ResolveBools applies scenario defaults and policy_overrides (legacy bool-only helper).
func ResolveBools(requireCheckpoint, blockPartner bool, overrides map[string]interface{}) (bool, bool) {
	requireCheckpoint, blockPartner, _, _ = ResolvePolicy(requireCheckpoint, blockPartner, false, overrides)
	return requireCheckpoint, blockPartner
}

func toBool(v interface{}) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	default:
		return false, false
	}
}

func ActionRequiresPrefixCheckpoint(action string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if len(prefix) > 0 && len(action) >= len(prefix) && action[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
