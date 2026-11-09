package trustmesh

// Authority replay engine (module realmshadow; see /app/fedproto/WORKSPACE_LAYOUT.md and TRUST_MESH_REPLAY.md).

import (
	"encoding/json"
	"os"
	"sort"

	"realmshadow/pkg/policygate"
)

type Event struct {
	Seq               int      `json:"seq"`
	EventID           string   `json:"event_id"`
	RealmID           string   `json:"realm_id"`
	Kind              string   `json:"kind"`
	Tier              string   `json:"tier"`
	TrustDomain       string   `json:"trust_domain"`
	FromRealm         string   `json:"from_realm"`
	ToRealm           string   `json:"to_realm"`
	Scope             string   `json:"scope"`
	ViaEdge           string   `json:"via_edge"`
	ActorID           string   `json:"actor_id"`
	TargetRealm       string   `json:"target_realm"`
	Action            string   `json:"action"`
	HasCheckpoint     bool     `json:"has_checkpoint"`
	PropagatedScopes  []string `json:"propagated_scopes"`
	OriginalActor     string   `json:"original_actor"`
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
	tier  string
	scopes map[string]struct{}
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

func actorHasAny(scopes map[string]struct{}, propagated []string) bool {
	for _, p := range propagated {
		if _, ok := scopes[p]; ok {
			return true
		}
	}
	return len(propagated) == 0
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

func Analyze(sc Scenario, journal JournalOut) ScenarioOut {
	_ = journal
	requireCheckpoint := true
	if sc.RequireCheckpointOnInternal != nil {
		requireCheckpoint = *sc.RequireCheckpointOnInternal
	}
	blockPartner := true
	if sc.BlockPartnerToPrivileged != nil {
		blockPartner = *sc.BlockPartnerToPrivileged
	}
	requireCheckpoint, blockPartner = policygate.ResolveBools(
		requireCheckpoint,
		blockPartner,
		sc.PolicyOverrides,
	)
	_ = requireCheckpoint
	_ = blockPartner

	realms := make(map[string]*realmState)
	edges := make(map[string]struct{})
	findings := make([]Finding, 0)
	dupSkipped := 0
	seenEvent := make(map[string]struct{})
	maxSeq := 0

	events := append([]Event(nil), sc.Events...)
	sort.Slice(events, func(i, j int) bool {
		return events[i].Seq < events[j].Seq
	})

	for _, ev := range events {
		seq := ev.Seq
		if seq > maxSeq {
			maxSeq = seq
		}
		kind := ev.Kind
		_ = seenEvent

		switch kind {
		case "REGISTER_REALM":
			rid := ev.RealmID
			if _, exists := realms[rid]; exists {
				appendFinding(&findings, sc.ScenarioID, rid, "DUPLICATE_REALM", "", "", seq)
				continue
			}
			realms[rid] = &realmState{tier: ev.Tier, scopes: make(map[string]struct{})}
		case "ALLOW_FEDERATION":
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
			key := from + "->" + to
			edges[key] = struct{}{}
		case "BIND_SCOPE":
			rid := ev.RealmID
			if _, ok := realms[rid]; !ok {
				appendFinding(&findings, sc.ScenarioID, rid, "UNKNOWN_ACTOR", "", kind, seq)
				continue
			}
			realms[rid].scopes[ev.Scope] = struct{}{}
		case "AUTHORITY_ACTION":
			actor := ev.ActorID
			target := ev.TargetRealm
			if _, ok := realms[target]; !ok {
				appendFinding(&findings, sc.ScenarioID, target, "UNKNOWN_TARGET", ev.Action, kind, seq)
				continue
			}
			if _, ok := realms[actor]; !ok {
				appendFinding(&findings, sc.ScenarioID, actor, "UNKNOWN_ACTOR", ev.Action, kind, seq)
				continue
			}
			actorScopes := realms[actor].scopes
			if !actorHasAny(actorScopes, ev.PropagatedScopes) && len(ev.PropagatedScopes) > 0 {
				appendFinding(&findings, sc.ScenarioID, actor, "PRIVILEGE_ESCALATION", ev.Action, ev.PropagatedScopes[0], seq)
			}
		}
	}

	edgeOut := make([]EdgeOut, 0)
	for key := range edges {
		parts := splitEdge(key)
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
	rids := make([]string, 0, len(realms))
	for id := range realms {
		rids = append(rids, id)
	}
	sort.Strings(rids)
	for _, id := range rids {
		st := realms[id]
		outRealms = append(outRealms, RealmOut{
			RealmID:       id,
			Tier:          st.tier,
			BoundScopes:   strSlice(st.scopes),
			AuthorityRisk: authorityRisk(st.tier),
		})
	}

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].FindingID < findings[j].FindingID
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

func splitEdge(key string) []string {
	for i := 0; i < len(key); i++ {
		if i+1 < len(key) && key[i] == '-' && key[i+1] == '>' {
			return []string{key[:i], key[i+2:]}
		}
	}
	return nil
}
