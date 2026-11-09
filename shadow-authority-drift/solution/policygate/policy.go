package policygate

type Policy struct {
	RequireCheckpoint               bool
	BlockPartner                    bool
	ResetDomain                     bool
	AttenuateOnAllow                bool
	OpenAuthorityLexFirst           bool
	SuppressLateral                 bool
	AuditPartnerPrivilegedAsymmetry bool
	Prefixes                        []string
}

func ResolvePolicy(requireCheckpoint, blockPartner, resetDomain bool, overrides map[string]interface{}) Policy {
	p := Policy{
		RequireCheckpoint: requireCheckpoint,
		BlockPartner:      blockPartner,
		ResetDomain:       resetDomain,
		Prefixes:          make([]string, 0),
	}
	if overrides == nil {
		return p
	}
	if v, ok := overrides["require_checkpoint_on_internal"]; ok {
		if b, ok := toBool(v); ok {
			p.RequireCheckpoint = b
		}
	}
	if v, ok := overrides["block_partner_to_privileged"]; ok {
		if b, ok := toBool(v); ok {
			p.BlockPartner = b
		}
	}
	if v, ok := overrides["reset_trust_domain_on_revoke"]; ok {
		if b, ok := toBool(v); ok {
			p.ResetDomain = b
		}
	}
	if v, ok := overrides["attenuate_on_allow"]; ok {
		if b, ok := toBool(v); ok {
			p.AttenuateOnAllow = b
		}
	}
	if v, ok := overrides["open_authority_lex_first"]; ok {
		if b, ok := toBool(v); ok {
			p.OpenAuthorityLexFirst = b
		}
	}
	if v, ok := overrides["suppress_lateral_movement"]; ok {
		if b, ok := toBool(v); ok {
			p.SuppressLateral = b
		}
	}
	if v, ok := overrides["audit_partner_privileged_asymmetry"]; ok {
		if b, ok := toBool(v); ok {
			p.AuditPartnerPrivilegedAsymmetry = b
		}
	}
	if v, ok := overrides["require_checkpoint_prefixes"]; ok {
		if arr, ok := v.([]interface{}); ok {
			for _, item := range arr {
				if s, ok := item.(string); ok && s != "" {
					p.Prefixes = append(p.Prefixes, s)
				}
			}
		}
	}
	return p
}

func ResolveBools(requireCheckpoint, blockPartner bool, overrides map[string]interface{}) (bool, bool) {
	p := ResolvePolicy(requireCheckpoint, blockPartner, false, overrides)
	return p.RequireCheckpoint, p.BlockPartner
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
