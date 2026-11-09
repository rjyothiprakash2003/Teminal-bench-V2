package trustmesh

import (
	"encoding/json"
	"os"
	"sort"

	"realmshadow/pkg/policygate"
)

type Event struct {
	Seq              int      `json:"seq"`
	EventID          string   `json:"event_id"`
	RealmID          string   `json:"realm_id"`
	Kind             string   `json:"kind"`
	Tier             string   `json:"tier"`
	TrustDomain      string   `json:"trust_domain"`
	FromRealm        string   `json:"from_realm"`
	ToRealm          string   `json:"to_realm"`
	Scope            string   `json:"scope"`
	ViaEdge          string   `json:"via_edge"`
	ActorID          string   `json:"actor_id"`
	TargetRealm      string   `json:"target_realm"`
	Action           string   `json:"action"`
	HasCheckpoint    bool     `json:"has_checkpoint"`
	PropagatedScopes []string `json:"propagated_scopes"`
	OriginalActor    string   `json:"original_actor"`
	ExpiresAtSeq     int      `json:"expires_at_seq"`
	ActiveAfterSeq   int      `json:"active_after_seq"`
	Pinned           bool     `json:"pinned"`
}

type Scenario struct {
	ScenarioID                  string                 `json:"scenario_id"`
	RequireCheckpointOnInternal *bool                  `json:"require_checkpoint_on_internal"`
	BlockPartnerToPrivileged    *bool                  `json:"block_partner_to_privileged"`
	PolicyOverrides             map[string]interface{} `json:"policy_overrides"`
	Events                      []Event                `json:"events"`
}

type EdgeOut struct {
	FromRealm string `json:"from_realm"`
	ToRealm   string `json:"to_realm"`
}

type RealmOut struct {
	RealmID       string   `json:"realm_id"`
	Tier          string   `json:"tier"`
	BoundScopes   []string `json:"bound_scopes"`
	AuthorityRisk string   `json:"authority_risk"`
}

type JournalOut struct {
	FormatVersion   int `json:"format_version"`
	RecordsTotal    int `json:"records_total"`
	RecordsValid    int `json:"records_valid"`
	RecordsRejected int `json:"records_rejected"`
	DupSeqRejects   int `json:"dup_seq_rejects"`
	TruncatedTail   int `json:"truncated_tail"`
	PayloadBytes    int `json:"payload_bytes"`
}

type Finding struct {
	FindingID string `json:"finding_id"`
	EntityID  string `json:"entity_id"`
	Kind      string `json:"kind"`
	EventSeq  int    `json:"event_seq"`
	Action    string `json:"action"`
	Detail    string `json:"detail"`
}

type ScenarioOut struct {
	ScenarioID             string     `json:"scenario_id"`
	Status                 string     `json:"status"`
	DuplicateEventsSkipped int        `json:"duplicate_events_skipped"`
	Journal                JournalOut `json:"journal"`
	FederationEdges        []EdgeOut  `json:"federation_edges"`
	Realms                 []RealmOut `json:"realms"`
	Findings               []Finding  `json:"findings"`
}

type Report struct {
	Scenarios []ScenarioOut `json:"scenarios"`
}

type realmState struct {
	tier             string
	registeredDomain string
	domain           string
	domainPinned     bool
	caps             map[string]struct{}
	suspended        bool
	quarantined      bool
	frozen           bool
	sealed           bool
	scopeVia         map[string]string
	scopeExpiry      map[string]int
	scopeActiveAfter map[string]int
	scopePinned      map[string]bool
}

func LoadScenario(path string) (Scenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Scenario{}, err
	}
	var sc Scenario
	if err := json.Unmarshal(data, &sc); err != nil {
		return Scenario{}, err
	}
	return sc, nil
}

func findingID(scenarioID, entityID string, seq int) string {
	return scenarioID + "::" + entityID + "::" + formatSeq(seq)
}

func formatSeq(seq int) string {
	if seq < 0 {
		seq = 0
	}
	s := []byte("0000")
	n := seq
	for i := 3; i >= 0; i-- {
		s[i] = byte('0' + n%10)
		n /= 10
	}
	return string(s)
}

func strSlice(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func authorityRisk(tier string) string {
	switch tier {
	case "partner":
		return "elevated"
	case "privileged":
		return "critical"
	default:
		return "none"
	}
}

func edgeKey(from, to string) string {
	return from + "\x00" + to
}

func hasEdge(edges map[string]struct{}, from, to string) bool {
	_, ok := edges[edgeKey(from, to)]
	return ok
}

func appendFinding(findings *[]Finding, scenarioID, entityID, kind, action, detail string, seq int) {
	*findings = append(*findings, Finding{
		FindingID: findingID(scenarioID, entityID, seq),
		EntityID:  entityID,
		Kind:      kind,
		EventSeq:  seq,
		Action:    action,
		Detail:    detail,
	})
}

func firstMissingProp(caps map[string]struct{}, propagated []string) string {
	missing := make([]string, 0)
	for _, p := range propagated {
		if _, ok := caps[p]; !ok {
			missing = append(missing, p)
		}
	}
	sort.Strings(missing)
	if len(missing) == 0 {
		return ""
	}
	return missing[0]
}

func eventSortRealmID(ev Event) string {
	switch ev.Kind {
	case "ALLOW_FEDERATION", "REVOKE_FEDERATION":
		if ev.ToRealm != "" {
			return ev.ToRealm
		}
	case "AUTHORITY_ACTION":
		if ev.TargetRealm != "" {
			return ev.TargetRealm
		}
	}
	return ev.RealmID
}

func dropScope(st *realmState, scope string) {
	delete(st.caps, scope)
	delete(st.scopeVia, scope)
	delete(st.scopeExpiry, scope)
	delete(st.scopeActiveAfter, scope)
	delete(st.scopePinned, scope)
}

func activeCaps(st *realmState, seq int) map[string]struct{} {
	out := make(map[string]struct{})
	for scope := range st.caps {
		if after, ok := st.scopeActiveAfter[scope]; ok && after > 0 && !(seq > after) {
			continue
		}
		out[scope] = struct{}{}
	}
	return out
}

func Analyze(sc Scenario, journal JournalOut) ScenarioOut {
	requireCheckpoint := true
	if sc.RequireCheckpointOnInternal != nil {
		requireCheckpoint = *sc.RequireCheckpointOnInternal
	}
	blockPartner := true
	if sc.BlockPartnerToPrivileged != nil {
		blockPartner = *sc.BlockPartnerToPrivileged
	}
	pol := policygate.ResolvePolicy(requireCheckpoint, blockPartner, false, sc.PolicyOverrides)

	realms := make(map[string]*realmState)
	tombstones := make(map[string]struct{})
	edges := make(map[string]struct{})
	findings := make([]Finding, 0)
	dupSkipped := 0
	seenEvent := make(map[string]struct{})
	privEscFlagged := make(map[string]struct{})
	maxSeq := 0

	cascadeGrantor := func(grantor string) {
		for _, st := range realms {
			for scope, g := range st.scopeVia {
				if g == grantor && !st.scopePinned[scope] {
					dropScope(st, scope)
				}
			}
		}
	}

	recomputeDomain := func(to string) {
		st, ok := realms[to]
		if !ok {
			return
		}
		st.domain = st.registeredDomain
		st.domainPinned = false
		parents := make([]string, 0)
		for key := range edges {
			parts := splitEdgeKey(key)
			if len(parts) == 2 && parts[1] == to {
				parents = append(parents, parts[0])
			}
		}
		sort.Strings(parents)
		for _, parent := range parents {
			if ps, ok := realms[parent]; ok {
				if ps.domain < st.domain {
					st.domain = ps.domain
				}
			}
		}
		if len(parents) > 0 {
			st.domainPinned = true
		}
	}

	sweepExpiry := func(seq int) {
		for _, st := range realms {
			for scope, exp := range st.scopeExpiry {
				if exp > 0 && exp <= seq && !st.scopePinned[scope] {
					dropScope(st, scope)
				}
			}
		}
	}

	events := append([]Event(nil), sc.Events...)
	sort.Slice(events, func(i, j int) bool {
		if events[i].Seq != events[j].Seq {
			return events[i].Seq < events[j].Seq
		}
		ri := eventSortRealmID(events[i])
		rj := eventSortRealmID(events[j])
		if ri != rj {
			return ri < rj
		}
		return events[i].EventID < events[j].EventID
	})

	for _, ev := range events {
		seq := ev.Seq
		if seq > maxSeq {
			maxSeq = seq
		}
		kind := ev.Kind
		if ev.EventID != "" {
			if _, dup := seenEvent[ev.EventID]; dup {
				dupSkipped++
				continue
			}
			seenEvent[ev.EventID] = struct{}{}
		}
		sweepExpiry(seq)

		switch kind {
		case "REGISTER_REALM":
			sid := ev.RealmID
			if _, purged := tombstones[sid]; purged {
				appendFinding(&findings, sc.ScenarioID, sid, "RESURRECTED_REALM", "", "", seq)
				continue
			}
			if _, exists := realms[sid]; exists {
				appendFinding(&findings, sc.ScenarioID, sid, "DUPLICATE_REALM", "", "", seq)
				continue
			}
			domain := ev.TrustDomain
			if domain == "" {
				domain = "mesh-core"
			}
			realms[sid] = &realmState{
				tier:             ev.Tier,
				registeredDomain: domain,
				domain:           domain,
				domainPinned:     false,
				caps:             make(map[string]struct{}),
				scopeVia:         make(map[string]string),
				scopeExpiry:      make(map[string]int),
				scopeActiveAfter: make(map[string]int),
				scopePinned:      make(map[string]bool),
			}
		case "PURGE_REALM":
			sid := ev.RealmID
			if _, ok := realms[sid]; !ok {
				appendFinding(&findings, sc.ScenarioID, sid, "UNKNOWN_ACTOR", "", kind, seq)
				continue
			}
			for key := range edges {
				parts := splitEdgeKey(key)
				if len(parts) == 2 && (parts[0] == sid || parts[1] == sid) {
					delete(edges, key)
				}
			}
			cascadeGrantor(sid)
			delete(realms, sid)
			tombstones[sid] = struct{}{}
		case "ALLOW_FEDERATION":
			from := ev.FromRealm
			to := ev.ToRealm
			if from == to {
				continue
			}
			if _, ok := realms[from]; !ok {
				appendFinding(&findings, sc.ScenarioID, from, "UNKNOWN_ACTOR", "", kind, seq)
				continue
			}
			if _, ok := realms[to]; !ok {
				appendFinding(&findings, sc.ScenarioID, to, "UNKNOWN_TARGET", "", kind, seq)
				continue
			}
			if realms[from].suspended {
				appendFinding(&findings, sc.ScenarioID, from, "SUSPENDED_REALM", "", "from", seq)
				continue
			}
			if realms[to].suspended {
				appendFinding(&findings, sc.ScenarioID, to, "SUSPENDED_REALM", "", "to", seq)
				continue
			}
			if realms[from].quarantined {
				appendFinding(&findings, sc.ScenarioID, from, "QUARANTINED_REALM", "", "from", seq)
				continue
			}
			if realms[to].quarantined {
				appendFinding(&findings, sc.ScenarioID, to, "QUARANTINED_REALM", "", "to", seq)
				continue
			}
			key := edgeKey(from, to)
			if _, exists := edges[key]; exists {
				appendFinding(&findings, sc.ScenarioID, to, "DUPLICATE_FEDERATION", "", from, seq)
				continue
			}
			edges[key] = struct{}{}
			pinned := realms[from].domain
			if realms[to].registeredDomain < pinned {
				pinned = realms[to].registeredDomain
			}
			realms[to].domain = pinned
			realms[to].domainPinned = true
			if pol.AttenuateOnAllow {
				child := realms[to]
				parent := realms[from]
				for scope := range child.caps {
					if child.scopePinned[scope] {
						continue
					}
					if _, ok := parent.caps[scope]; !ok {
						dropScope(child, scope)
					}
				}
			}
		case "REVOKE_FEDERATION":
			from := ev.FromRealm
			to := ev.ToRealm
			if _, ok := realms[from]; !ok {
				appendFinding(&findings, sc.ScenarioID, from, "UNKNOWN_ACTOR", "", kind, seq)
				continue
			}
			if _, ok := realms[to]; !ok {
				appendFinding(&findings, sc.ScenarioID, to, "UNKNOWN_TARGET", "", kind, seq)
				continue
			}
			key := edgeKey(from, to)
			if _, exists := edges[key]; !exists {
				continue
			}
			delete(edges, key)
			if st, ok := realms[to]; ok {
				for scope, grantor := range st.scopeVia {
					if grantor == from && !st.scopePinned[scope] {
						dropScope(st, scope)
					}
				}
			}
			if pol.ResetDomain {
				recomputeDomain(to)
			}
		case "BIND_SCOPE":
			sid := ev.RealmID
			if _, ok := realms[sid]; !ok {
				appendFinding(&findings, sc.ScenarioID, sid, "UNKNOWN_ACTOR", "", kind, seq)
				continue
			}
			if realms[sid].suspended {
				appendFinding(&findings, sc.ScenarioID, sid, "SUSPENDED_REALM", "", "bind", seq)
				continue
			}
			if realms[sid].quarantined {
				appendFinding(&findings, sc.ScenarioID, sid, "QUARANTINED_REALM", "", "bind", seq)
				continue
			}
			if realms[sid].frozen {
				appendFinding(&findings, sc.ScenarioID, sid, "FROZEN_REALM", "", "bind", seq)
				continue
			}
			if ev.ViaEdge != "" {
				if !hasEdge(edges, ev.ViaEdge, sid) {
					appendFinding(&findings, sc.ScenarioID, sid, "UNAUTHORIZED_SCOPE_BIND", "", ev.ViaEdge, seq)
					continue
				}
				if gs, ok := realms[ev.ViaEdge]; ok && (gs.suspended || gs.quarantined || gs.frozen) {
					appendFinding(&findings, sc.ScenarioID, sid, "UNAUTHORIZED_SCOPE_BIND", "", ev.ViaEdge, seq)
					continue
				}
				realms[sid].caps[ev.Scope] = struct{}{}
				realms[sid].scopeVia[ev.Scope] = ev.ViaEdge
			} else {
				realms[sid].caps[ev.Scope] = struct{}{}
				realms[sid].scopeVia[ev.Scope] = ""
			}
			realms[sid].scopePinned[ev.Scope] = ev.Pinned
			if ev.ExpiresAtSeq > 0 {
				realms[sid].scopeExpiry[ev.Scope] = ev.ExpiresAtSeq
			} else {
				delete(realms[sid].scopeExpiry, ev.Scope)
			}
			if ev.ActiveAfterSeq > 0 {
				realms[sid].scopeActiveAfter[ev.Scope] = ev.ActiveAfterSeq
			} else {
				delete(realms[sid].scopeActiveAfter, ev.Scope)
			}
		case "SUSPEND_REALM":
			sid := ev.RealmID
			if _, ok := realms[sid]; !ok {
				appendFinding(&findings, sc.ScenarioID, sid, "UNKNOWN_ACTOR", "", kind, seq)
				continue
			}
			realms[sid].suspended = true
		case "QUARANTINE_REALM":
			sid := ev.RealmID
			if _, ok := realms[sid]; !ok {
				appendFinding(&findings, sc.ScenarioID, sid, "UNKNOWN_ACTOR", "", kind, seq)
				continue
			}
			realms[sid].quarantined = true
		case "FREEZE_REALM":
			sid := ev.RealmID
			if _, ok := realms[sid]; !ok {
				appendFinding(&findings, sc.ScenarioID, sid, "UNKNOWN_ACTOR", "", kind, seq)
				continue
			}
			realms[sid].frozen = true
		case "SEAL_REALM":
			sid := ev.RealmID
			if _, ok := realms[sid]; !ok {
				appendFinding(&findings, sc.ScenarioID, sid, "UNKNOWN_ACTOR", "", kind, seq)
				continue
			}
			realms[sid].sealed = true
		case "UNSEAL_REALM":
			sid := ev.RealmID
			if _, ok := realms[sid]; !ok {
				appendFinding(&findings, sc.ScenarioID, sid, "UNKNOWN_ACTOR", "", kind, seq)
				continue
			}
			realms[sid].sealed = false
		case "ROTATE_TRUST_DOMAIN":
			sid := ev.RealmID
			if _, ok := realms[sid]; !ok {
				appendFinding(&findings, sc.ScenarioID, sid, "UNKNOWN_ACTOR", "", kind, seq)
				continue
			}
			domain := ev.TrustDomain
			if domain == "" {
				domain = "mesh-core"
			}
			realms[sid].registeredDomain = domain
			realms[sid].domain = domain
		case "AUTHORITY_ACTION":
			actor := ev.ActorID
			target := ev.TargetRealm
			action := ev.Action
			targetSt, ok := realms[target]
			if !ok {
				appendFinding(&findings, sc.ScenarioID, target, "UNKNOWN_TARGET", action, kind, seq)
				continue
			}
			actorSt, ok := realms[actor]
			if !ok {
				appendFinding(&findings, sc.ScenarioID, actor, "UNKNOWN_ACTOR", action, kind, seq)
				continue
			}
			if actorSt.suspended {
				appendFinding(&findings, sc.ScenarioID, actor, "SUSPENDED_REALM", action, "actor", seq)
				continue
			}
			if targetSt.suspended {
				appendFinding(&findings, sc.ScenarioID, target, "SUSPENDED_REALM", action, "target", seq)
				continue
			}
			if actorSt.frozen {
				appendFinding(&findings, sc.ScenarioID, actor, "FROZEN_REALM", action, "actor", seq)
				continue
			}
			if targetSt.frozen {
				appendFinding(&findings, sc.ScenarioID, target, "FROZEN_REALM", action, "target", seq)
				continue
			}
			if actorSt.sealed {
				appendFinding(&findings, sc.ScenarioID, actor, "SEALED_REALM", action, "actor", seq)
				continue
			}
			if targetSt.sealed {
				appendFinding(&findings, sc.ScenarioID, target, "SEALED_REALM", action, "target", seq)
				continue
			}
			if !hasEdge(edges, actor, target) {
				appendFinding(&findings, sc.ScenarioID, target, "UNTRUSTED_REALM", action, actor, seq)
				continue
			}
			if actorSt.domain != targetSt.domain {
				appendFinding(&findings, sc.ScenarioID, target, "DOMAIN_CONTAMINATION", action, actor, seq)
				continue
			}
			if pol.BlockPartner && actorSt.tier == "partner" && targetSt.tier == "privileged" && len(ev.PropagatedScopes) == 0 {
				appendFinding(&findings, sc.ScenarioID, target, "RESTRICTED_ESCALATION", action, actor, seq)
				continue
			}
			if pol.RequireCheckpoint && targetSt.tier == "internal" && !ev.HasCheckpoint {
				appendFinding(&findings, sc.ScenarioID, target, "UNVERIFIED_ACTOR", action, "", seq)
				continue
			}
			if policygate.ActionRequiresPrefixCheckpoint(action, pol.Prefixes) && !ev.HasCheckpoint {
				appendFinding(&findings, sc.ScenarioID, actor, "UNVERIFIED_ACTOR", action, "", seq)
				continue
			}
			liveCaps := activeCaps(actorSt, seq)
			if miss := firstMissingProp(liveCaps, ev.PropagatedScopes); miss != "" {
				pkey := actor + "::" + miss
				if _, done := privEscFlagged[pkey]; !done {
					privEscFlagged[pkey] = struct{}{}
					appendFinding(&findings, sc.ScenarioID, actor, "PRIVILEGE_ESCALATION", action, miss, seq)
				}
			}
			if !pol.SuppressLateral {
				orig := ev.OriginalActor
				if orig != "" && orig != actor {
					if ost, ok := realms[orig]; ok && !ost.suspended {
						missArray := ""
						for _, p := range ev.PropagatedScopes {
							if _, ok := liveCaps[p]; !ok {
								missArray = p
								break
							}
						}
						if missArray != "" {
							appendFinding(&findings, sc.ScenarioID, orig, "LATERAL_MOVEMENT", action, missArray, seq)
						}
					}
				}
			}
		}
	}

	auditSeq := maxSeq + 1
	federationFlagged := make(map[string]struct{})
	openFlagged := make(map[string]struct{})

	for key := range edges {
		parts := splitEdgeKey(key)
		if len(parts) != 2 {
			continue
		}
		from, to := parts[0], parts[1]
		fromSt, ok1 := realms[from]
		toSt, ok2 := realms[to]
		if !ok1 || !ok2 {
			continue
		}
		if fromSt.tier == "partner" && (toSt.tier == "internal" || (pol.AuditPartnerPrivilegedAsymmetry && toSt.tier == "privileged")) {
			mkey := from + "::" + to
			if _, done := federationFlagged[mkey]; done {
				continue
			}
			if !hasEdge(edges, to, from) {
				federationFlagged[mkey] = struct{}{}
				appendFinding(&findings, sc.ScenarioID, from, "FEDERATION_ASYMMETRY", "", to, auditSeq)
			}
		}
	}

	for sid, st := range realms {
		if st.tier != "privileged" {
			continue
		}
		if _, ok := st.caps["fed:audit"]; ok {
			continue
		}
		partners := make([]string, 0)
		for key := range edges {
			parts := splitEdgeKey(key)
			if len(parts) != 2 {
				continue
			}
			from, to := parts[0], parts[1]
			if to != sid {
				continue
			}
			if fs, ok := realms[from]; ok && fs.tier == "partner" {
				partners = append(partners, from)
			}
		}
		if len(partners) == 0 {
			continue
		}
		sort.Strings(partners)
		detail := partners[len(partners)-1]
		if pol.OpenAuthorityLexFirst {
			detail = partners[0]
		}
		if _, done := openFlagged[sid]; !done {
			openFlagged[sid] = struct{}{}
			appendFinding(&findings, sc.ScenarioID, sid, "OPEN_AUTHORITY_PATH", "", detail, auditSeq)
		}
	}

	for sid, st := range realms {
		if st.tier != "privileged" {
			continue
		}
		if _, ok := st.caps["fed:admin"]; ok {
			continue
		}
		if _, open := openFlagged[sid]; open {
			continue
		}
		appendFinding(&findings, sc.ScenarioID, sid, "ADMIN_UNBOUND", "", "", auditSeq)
	}

	edgeOut := make([]EdgeOut, 0, len(edges))
	for key := range edges {
		parts := splitEdgeKey(key)
		if len(parts) == 2 {
			edgeOut = append(edgeOut, EdgeOut{FromRealm: parts[0], ToRealm: parts[1]})
		}
	}
	sort.Slice(edgeOut, func(i, j int) bool {
		if edgeOut[i].FromRealm != edgeOut[j].FromRealm {
			return edgeOut[i].FromRealm < edgeOut[j].FromRealm
		}
		return edgeOut[i].ToRealm < edgeOut[j].ToRealm
	})

	outRealms := make([]RealmOut, 0, len(realms))
	sids := make([]string, 0, len(realms))
	for id := range realms {
		sids = append(sids, id)
	}
	sort.Strings(sids)
	for _, id := range sids {
		st := realms[id]
		outRealms = append(outRealms, RealmOut{
			RealmID:       id,
			Tier:          st.tier,
			BoundScopes:   strSlice(st.caps),
			AuthorityRisk: authorityRisk(st.tier),
		})
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].FindingID != findings[j].FindingID {
			return findings[i].FindingID < findings[j].FindingID
		}
		return findings[i].Kind < findings[j].Kind
	})

	status := "VALID"
	if len(findings) > 0 {
		status = "INVALID"
	}

	return ScenarioOut{
		ScenarioID:             sc.ScenarioID,
		Status:                 status,
		DuplicateEventsSkipped: dupSkipped,
		Journal:                journal,
		FederationEdges:        edgeOut,
		Realms:                 outRealms,
		Findings:               findings,
	}
}

func splitEdgeKey(key string) []string {
	for i := 0; i < len(key); i++ {
		if key[i] == 0 {
			return []string{key[:i], key[i+1:]}
		}
	}
	return nil
}
