package score

import (
	"encoding/json"
	"os"
	"sort"

	"pairclass/fanout/reach"
	"pairclass/featmesh/replay"
	"pairclass/limitmath/resolve"
)

type Event = replay.Event

type Case struct {
	CaseID               string                 `json:"case_id"`
	MaxFanoutDepth       *int                   `json:"max_fanout_depth"`
	MaxChainDepth        *int                   `json:"max_chain_depth"`
	RequireObservedMatch *bool                  `json:"require_observed_match"`
	EmitStaleCouplings   *bool                  `json:"emit_stale_couplings"`
	ScoreMutualCouplings *bool                  `json:"score_mutual_couplings"`
	MinConfidence        *int                   `json:"min_confidence"`
	SoftDampenPct        *int                   `json:"soft_dampen_pct"`
	OutlierThreshold     *int                   `json:"outlier_threshold"`
	PolicyOverrides      map[string]interface{} `json:"policy_overrides"`
	Events               []Event                `json:"events"`
}

type SiteOut struct {
	SiteID   string `json:"site_id"`
	Tier     string `json:"tier"`
	Critical bool   `json:"critical"`
	Failed   bool   `json:"failed"`
}

type DeclaredCouplingOut struct {
	SinkID   string `json:"sink_id"`
	SourceID string `json:"source_id"`
	Channel  string `json:"channel"`
	Required bool   `json:"required"`
}

type ObservedCouplingOut struct {
	SinkID   string `json:"sink_id"`
	SourceID string `json:"source_id"`
	Channel  string `json:"channel"`
	Weight     int    `json:"weight"`
}

type Finding struct {
	FindingID string `json:"finding_id"`
	EntityID  string `json:"entity_id"`
	Kind      string `json:"kind"`
	EventSeq  int    `json:"event_seq"`
	Detail    string `json:"detail"`
}

type Correction struct {
	CorrectionID string `json:"correction_id"`
	Action       string `json:"action"`
	TargetID     string `json:"target_id"`
	Detail       string `json:"detail"`
}

type CaseOut struct {
	CaseID                 string                `json:"case_id"`
	Status                 string                `json:"status"`
	Confidence             int                   `json:"confidence"`
	DuplicateEventsSkipped int                   `json:"duplicate_events_skipped"`
	Sites                  []SiteOut             `json:"sites"`
	DeclaredCouplings      []DeclaredCouplingOut `json:"declared_couplings"`
	ObservedCouplings      []ObservedCouplingOut `json:"observed_couplings"`
	Findings               []Finding             `json:"findings"`
	Corrections            []Correction          `json:"corrections"`
}

type Report struct {
	Cases []CaseOut `json:"cases"`
}

type siteState struct {
	tier     string
	critical bool
	failed   bool
}

type declCoupling struct {
	channel  string
	required bool
	seq      int
}

type obsCoupling struct {
	channel string
	weight    int
	seq     int
}

func LoadCase(path string) (Case, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Case{}, err
	}
	var sc Case
	if err := json.Unmarshal(data, &sc); err != nil {
		return Case{}, err
	}
	return sc, nil
}

var findingOrdinal = 0

func findingID(caseID, entityID, kind string, seq int) string {
	_ = kind
	_ = seq
	findingOrdinal++
	return caseID + "::" + entityID + "::" + formatSeq(findingOrdinal)
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

func appendFinding(findings *[]Finding, caseID, entityID, kind, detail string, seq int) {
	*findings = append(*findings, Finding{
		FindingID: findingID(caseID, entityID, kind, seq),
		EntityID:  entityID,
		Kind:      kind,
		EventSeq:  seq,
		Detail:    detail,
	})
}

func couplingKey(a, b string) string {
	return a + "\x00" + b
}

func splitKey(key string) [2]string {
	for i := 0; i < len(key); i++ {
		if key[i] == 0 {
			return [2]string{key[:i], key[i+1:]}
		}
	}
	return [2]string{key, ""}
}

func Analyze(sc Case) CaseOut {
	maxFanout := 2
	if sc.MaxFanoutDepth != nil {
		maxFanout = *sc.MaxFanoutDepth
	}
	maxDepth := 3
	if sc.MaxChainDepth != nil {
		maxDepth = *sc.MaxChainDepth
	}
	requireObs := true
	if sc.RequireObservedMatch != nil {
		requireObs = *sc.RequireObservedMatch
	}
	emitStale := true
	if sc.EmitStaleCouplings != nil {
		emitStale = *sc.EmitStaleCouplings
	}
	scoreMutual := true
	if sc.ScoreMutualCouplings != nil {
		scoreMutual = *sc.ScoreMutualCouplings
	}
	maxFanout, maxDepth, requireObs, emitStale, scoreMutual = resolve.ResolveCase(
		maxFanout, maxDepth, requireObs, emitStale, scoreMutual, sc.PolicyOverrides,
	)
	minConf := 20
	if sc.MinConfidence != nil {
		minConf = *sc.MinConfidence
	}
	softDamp := 40
	if sc.SoftDampenPct != nil {
		softDamp = *sc.SoftDampenPct
	}
	outlier := 40
	if sc.OutlierThreshold != nil {
		outlier = *sc.OutlierThreshold
	}
	minConf, softDamp, outlier = resolve.ResolveConfidence(minConf, softDamp, outlier, sc.PolicyOverrides)

	findingOrdinal = 0
	sites := map[string]*siteState{}
	declared := map[string]declCoupling{}
	observed := map[string]obsCoupling{}
	seed := ""
	findings := make([]Finding, 0)
	maxSeq := 0

	sorted := replay.SortEvents(sc.Events)
	events, dupSkipped := replay.FilterDuplicateEvents(sorted)

	for _, ev := range events {
		seq := ev.Seq
		if seq > maxSeq {
			maxSeq = seq
		}
		switch ev.Kind {
		case "REGISTER_SITE":
			if _, exists := sites[ev.SiteID]; exists {
				appendFinding(&findings, sc.CaseID, ev.SiteID, "DUPLICATE_SITE", "", seq)
				continue
			}
			sites[ev.SiteID] = &siteState{tier: ev.Tier, critical: ev.Critical}
		case "DECLARE_COUPLING":
			if _, ok := sites[ev.SinkID]; !ok {
				appendFinding(&findings, sc.CaseID, ev.SinkID, "MISSING_SITE", ev.Kind, seq)
				continue
			}
			if _, ok := sites[ev.SourceID]; !ok {
				appendFinding(&findings, sc.CaseID, ev.SourceID, "MISSING_SITE", ev.Kind, seq)
				continue
			}
			declared[couplingKey(ev.SinkID, ev.SourceID)] = declCoupling{
				channel:  ev.Channel,
				required: ev.Required,
				seq:      seq,
			}
		case "OBSERVE_COUPLING":
			if _, ok := sites[ev.SinkID]; !ok {
				appendFinding(&findings, sc.CaseID, ev.SinkID, "UNKNOWN_SINK", ev.SourceID, seq)
				continue
			}
			if _, ok := sites[ev.SourceID]; !ok {
				appendFinding(&findings, sc.CaseID, ev.SourceID, "MISSING_SITE", ev.Kind, seq)
				continue
			}
			observed[couplingKey(ev.SinkID, ev.SourceID)] = obsCoupling{
				channel: ev.Channel,
				weight:    ev.Weight,
				seq:     seq,
			}
		case "SET_SEED":
			if _, ok := sites[ev.SiteID]; ok {
				seed = ev.SiteID
			}
		case "FLAG_CRITICAL":
			if s, ok := sites[ev.SiteID]; ok {
				s.critical = true
			}
		case "INJECT_FAILURE":
			if s, ok := sites[ev.SiteID]; ok {
				s.failed = true
			}
		}
	}

	auditSeq := maxSeq + 1

	for key, obs := range observed {
		parts := splitKey(key)
		sink, source := parts[0], parts[1]
		d, ok := declared[key]
		if !ok {
			if requireObs {
				appendFinding(&findings, sc.CaseID, sink, "UNDECLARED_COUPLING", source, obs.seq)
			}
			continue
		}
		if d.channel != obs.channel {
			appendFinding(&findings, sc.CaseID, sink, "CHANNEL_DRIFT", obs.channel+">"+d.channel, obs.seq)
		}
		if d.required && obs.weight < 0 {
			appendFinding(&findings, sc.CaseID, sink, "WEIGHT_STARVE", source, obs.seq)
		}
	}
	if emitStale {
		for key, d := range declared {
			if _, ok := observed[key]; ok {
				continue
			}
			parts := splitKey(key)
			appendFinding(&findings, sc.CaseID, parts[0], "STALE_COUPLING", parts[1], d.seq)
		}
	}


	obsEdges := make([]reach.Edge, 0, len(observed))
	liveEdges := make([]reach.Edge, 0, len(observed))
	for key, o := range observed {
		parts := splitKey(key)
		e := reach.Edge{From: parts[0], To: parts[1]}
		obsEdges = append(obsEdges, e)
		if o.weight > 0 {
			liveEdges = append(liveEdges, e)
		}
	}

	declEdges := make([]reach.Edge, 0, len(declared))
	reqSources := map[string]bool{}
	for key, d := range declared {
		parts := splitKey(key)
		declEdges = append(declEdges, reach.Edge{From: parts[0], To: parts[1]})
		if d.required {
			reqSources[parts[1]] = true
		}
	}

	cycles := reach.FindCycles(liveEdges)
	for _, loop := range cycles {
		appendFinding(&findings, sc.CaseID, loop[0], "CYCLE_DETECTED", loop[1], auditSeq)
	}

	if scoreMutual {
		for _, pair := range reach.MutualPairs(obsEdges) {
			appendFinding(&findings, sc.CaseID, pair[0], "MUTUAL_COUPLING", pair[1], auditSeq)
		}
	}

	referenced := map[string]struct{}{}
	for key := range declared {
		parts := splitKey(key)
		referenced[parts[0]] = struct{}{}
		referenced[parts[1]] = struct{}{}
	}
	for key := range observed {
		parts := splitKey(key)
		referenced[parts[0]] = struct{}{}
		referenced[parts[1]] = struct{}{}
	}
	orphanIDs := make([]string, 0)
	for id := range sites {
		if _, ok := referenced[id]; !ok {
			orphanIDs = append(orphanIDs, id)
		}
	}
	sort.Strings(orphanIDs)
	for _, id := range orphanIDs {
		appendFinding(&findings, sc.CaseID, id, "ORPHAN_SITE", "", auditSeq)
	}

	declAdj := reach.DeclaredAdj(declEdges)
	if seed != "" {
		reachSet := reach.Reachable(declAdj, seed)
		critIDs := make([]string, 0)
		for id, s := range sites {
			if s.critical {
				critIDs = append(critIDs, id)
			}
		}
		sort.Strings(critIDs)
		for _, id := range critIDs {
			if _, ok := reachSet[id]; !ok {
				appendFinding(&findings, sc.CaseID, id, "SEED_UNREACHABLE", seed, auditSeq)
			}
		}

		deepest, depth := reach.LongestDeclaredDepth(declAdj, seed)
		if depth >= maxDepth {
			appendFinding(&findings, sc.CaseID, deepest, "DEPTH_EXCEEDED", reach.FormatInt(depth), auditSeq)
		}
	}

	rev := reach.ReverseAdj(obsEdges)
	failedIDs := make([]string, 0)
	for id, s := range sites {
		if s.failed {
			failedIDs = append(failedIDs, id)
		}
	}
	sort.Strings(failedIDs)
	for _, fid := range failedIDs {
		maxHop, _ := reach.CascadeHops(rev, fid)
		if maxHop >= maxFanout {
			appendFinding(&findings, sc.CaseID, fid, "FANOUT_DEPTH", reach.FormatInt(maxHop), auditSeq)
		}
	}

	if seed != "" && len(failedIDs) > 0 {
		aliveAdj := map[string][]string{}
		for _, e := range declEdges {
			if sites[e.From] != nil && sites[e.From].failed {
				continue
			}
			if sites[e.To] != nil && sites[e.To].failed {
				continue
			}
			aliveAdj[e.From] = append(aliveAdj[e.From], e.To)
		}
		for k := range aliveAdj {
			sort.Strings(aliveAdj[k])
		}
		seedState := sites[seed]
		if seedState == nil || !seedState.failed {
			reachSet := reach.Reachable(aliveAdj, seed)
			srcIDs := make([]string, 0)
			for p := range reqSources {
				srcIDs = append(srcIDs, p)
			}
			sort.Strings(srcIDs)
			for _, p := range srcIDs {
				if sites[p] != nil && sites[p].failed {
					appendFinding(&findings, sc.CaseID, p, "REQUIRED_UNREACHABLE", seed, auditSeq)
					continue
				}
				if _, ok := reachSet[p]; !ok {
					appendFinding(&findings, sc.CaseID, p, "REQUIRED_UNREACHABLE", seed, auditSeq)
				}
			}
		}
	}

	corrections := make([]Correction, 0)
	corrSeen := map[string]struct{}{}
	for _, f := range findings {
		action, target, detail, ok := resolve.CorrectionFor(f.Kind, f.EntityID, f.Detail, seed)
		if !ok {
			continue
		}
		cid := sc.CaseID + "::" + action + "::" + target
		if _, exists := corrSeen[cid]; exists {
			continue
		}
		corrSeen[cid] = struct{}{}
		corrections = append(corrections, Correction{
			CorrectionID: cid,
			Action:       action,
			TargetID:     target,
			Detail:       detail,
		})
	}

	outSites := make([]SiteOut, 0, len(sites))
	sids := make([]string, 0, len(sites))
	for id := range sites {
		sids = append(sids, id)
	}
	sort.Strings(sids)
	for _, id := range sids {
		s := sites[id]
		outSites = append(outSites, SiteOut{SiteID: id, Tier: s.tier, Critical: s.critical, Failed: s.failed})
	}

	outDecl := make([]DeclaredCouplingOut, 0, len(declared))
	dkeys := make([]string, 0, len(declared))
	for k := range declared {
		dkeys = append(dkeys, k)
	}
	sort.Strings(dkeys)
	for _, k := range dkeys {
		parts := splitKey(k)
		d := declared[k]
		outDecl = append(outDecl, DeclaredCouplingOut{SinkID: parts[0], SourceID: parts[1], Channel: d.channel, Required: d.required})
	}

	outObs := make([]ObservedCouplingOut, 0, len(observed))
	okeys := make([]string, 0, len(observed))
	for k := range observed {
		okeys = append(okeys, k)
	}
	sort.Strings(okeys)
	for _, k := range okeys {
		parts := splitKey(k)
		o := observed[k]
		outObs = append(outObs, ObservedCouplingOut{SinkID: parts[0], SourceID: parts[1], Channel: o.channel, Weight: o.weight})
	}

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].FindingID < findings[j].FindingID
	})
	sort.Slice(corrections, func(i, j int) bool {
		return corrections[i].CorrectionID < corrections[j].CorrectionID
	})

	kinds := make([]string, 0, len(findings))
	for _, f := range findings {
		kinds = append(kinds, f.Kind)
	}
	confidence, _, _, hasHard := resolve.ScoreConfidence(kinds, softDamp)
	status, confidence := resolve.Verdict(confidence, minConf, outlier, hasHard, len(findings))

	return CaseOut{
		CaseID: sc.CaseID, Status: status, Confidence: confidence, DuplicateEventsSkipped: dupSkipped,
		Sites: outSites, DeclaredCouplings: outDecl, ObservedCouplings: outObs,
		Findings: findings, Corrections: corrections,
	}
}
