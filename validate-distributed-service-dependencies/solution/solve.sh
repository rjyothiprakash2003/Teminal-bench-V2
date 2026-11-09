#!/bin/bash
set -euo pipefail
cd /app

cat > /app/featmesh/replay/replay.go <<'EOF'
package replay

import "sort"

type Event struct {
	Seq      int    `json:"seq"`
	EventID  string `json:"event_id"`
	Kind     string `json:"kind"`
	SiteID   string `json:"site_id"`
	SinkID   string `json:"sink_id"`
	SourceID string `json:"source_id"`
	Channel  string `json:"channel"`
	Required bool   `json:"required"`
	Critical bool   `json:"critical"`
	Tier     string `json:"tier"`
	Weight     int    `json:"weight"`
}

func EventTieKey(ev Event) string {
	switch ev.Kind {
	case "REGISTER_SITE", "SET_SEED", "FLAG_CRITICAL", "INJECT_FAILURE":
		return ev.SiteID
	case "DECLARE_COUPLING", "OBSERVE_COUPLING":
		return ev.SinkID
	default:
		return ""
	}
}

func SortEvents(events []Event) []Event {
	out := append([]Event(nil), events...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Seq != out[j].Seq {
			return out[i].Seq < out[j].Seq
		}
		ci := EventTieKey(out[i])
		cj := EventTieKey(out[j])
		if ci != cj {
			return ci < cj
		}
		return out[i].EventID < out[j].EventID
	})
	return out
}

func FilterDuplicateEvents(events []Event) ([]Event, int) {
	seen := map[string]struct{}{}
	out := make([]Event, 0, len(events))
	skipped := 0
	for _, ev := range events {
		if _, ok := seen[ev.EventID]; ok {
			skipped++
			continue
		}
		seen[ev.EventID] = struct{}{}
		out = append(out, ev)
	}
	return out, skipped
}
EOF

cat > /app/featmesh/score/analyze.go <<'EOF'
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

func findingID(caseID, entityID string, seq int) string {
	return caseID + "::" + entityID + "::" + formatSeq(seq)
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
		FindingID: findingID(caseID, entityID, seq),
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
			appendFinding(&findings, sc.CaseID, sink, "CHANNEL_DRIFT", d.channel+">"+obs.channel, obs.seq)
		}
		if d.required && obs.weight == 0 {
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
	reqDeclEdges := make([]reach.Edge, 0, len(declared))
	reqSources := map[string]bool{}
	for key, d := range declared {
		parts := splitKey(key)
		e := reach.Edge{From: parts[0], To: parts[1]}
		declEdges = append(declEdges, e)
		if d.required {
			reqDeclEdges = append(reqDeclEdges, e)
			reqSources[parts[1]] = true
		}
	}

	cycles := reach.FindCycles(obsEdges)
	for _, loop := range cycles {
		appendFinding(&findings, sc.CaseID, loop[0], "CYCLE_DETECTED", loop[1], auditSeq)
	}

	if scoreMutual {
		for _, pair := range reach.MutualPairs(liveEdges) {
			covered := false
			for _, loop := range cycles {
				if reach.CycleCoversPair(loop[1], pair[0], pair[1]) {
					covered = true
					break
				}
			}
			if covered {
				continue
			}
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

		deepest, depth := reach.LongestDeclaredDepth(reach.DeclaredAdj(reqDeclEdges), seed)
		if depth > maxDepth {
			appendFinding(&findings, sc.CaseID, deepest, "DEPTH_EXCEEDED", reach.FormatInt(depth), auditSeq)
		}
	}

	rev := reach.ReverseAdj(liveEdges)
	failedIDs := make([]string, 0)
	for id, s := range sites {
		if s.failed {
			failedIDs = append(failedIDs, id)
		}
	}
	sort.Strings(failedIDs)
	for _, fid := range failedIDs {
		maxHop, _ := reach.CascadeHops(rev, fid)
		if maxHop > maxFanout {
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
EOF

cat > /app/fanout/reach/reach.go <<'EOF'
package reach

import (
	"sort"
	"strconv"
	"strings"
)

type Edge struct {
	From string
	To   string
}

func ObservedAdj(edges []Edge) map[string][]string {
	adj := make(map[string][]string)
	for _, e := range edges {
		adj[e.From] = append(adj[e.From], e.To)
	}
	for k := range adj {
		sort.Strings(adj[k])
	}
	return adj
}

func ReverseAdj(edges []Edge) map[string][]string {
	adj := make(map[string][]string)
	for _, e := range edges {
		adj[e.To] = append(adj[e.To], e.From)
	}
	for k := range adj {
		sort.Strings(adj[k])
	}
	return adj
}

func DeclaredAdj(edges []Edge) map[string][]string {
	return ObservedAdj(edges)
}

func SmallestCycleRotation(cycle []string) string {
	if len(cycle) < 2 {
		return strings.Join(cycle, ">")
	}
	body := cycle[:len(cycle)-1]
	if len(body) == 0 {
		return strings.Join(cycle, ">")
	}
	best := ""
	n := len(body)
	for i := 0; i < n; i++ {
		rot := append(append([]string{}, body[i:]...), body[:i]...)
		rot = append(rot, rot[0])
		s := strings.Join(rot, ">")
		if best == "" || s < best {
			best = s
		}
	}
	return best
}

func FindCycles(edges []Edge) [][2]string {
	adj := ObservedAdj(edges)
	nodes := make(map[string]struct{})
	for _, e := range edges {
		nodes[e.From] = struct{}{}
		nodes[e.To] = struct{}{}
	}
	ids := make([]string, 0, len(nodes))
	for id := range nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	index := 0
	indices := map[string]int{}
	lowlink := map[string]int{}
	onstack := map[string]bool{}
	stack := []string{}
	var sccs [][]string

	var strongconnect func(v string)
	strongconnect = func(v string) {
		indices[v] = index
		lowlink[v] = index
		index++
		stack = append(stack, v)
		onstack[v] = true
		for _, w := range adj[v] {
			if _, ok := indices[w]; !ok {
				strongconnect(w)
				if lowlink[w] < lowlink[v] {
					lowlink[v] = lowlink[w]
				}
			} else if onstack[w] {
				if indices[w] < lowlink[v] {
					lowlink[v] = indices[w]
				}
			}
		}
		if lowlink[v] == indices[v] {
			comp := []string{}
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onstack[w] = false
				comp = append(comp, w)
				if w == v {
					break
				}
			}
			if len(comp) > 1 {
				sort.Strings(comp)
				sccs = append(sccs, comp)
			} else if len(comp) == 1 {
				for _, to := range adj[comp[0]] {
					if to == comp[0] {
						sccs = append(sccs, comp)
						break
					}
				}
			}
		}
	}
	for _, v := range ids {
		if _, ok := indices[v]; !ok {
			strongconnect(v)
		}
	}

	out := make([][2]string, 0)
	seen := map[string]struct{}{}
	for _, comp := range sccs {
		cycle := extractCycle(comp, adj)
		if cycle == nil {
			continue
		}
		detail := SmallestCycleRotation(cycle)
		entity := strings.Split(detail, ">")[0]
		if _, ok := seen[detail]; ok {
			continue
		}
		seen[detail] = struct{}{}
		out = append(out, [2]string{entity, detail})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i][1] != out[j][1] {
			return out[i][1] < out[j][1]
		}
		return out[i][0] < out[j][0]
	})
	return out
}

func extractCycle(comp []string, adj map[string][]string) []string {
	inComp := map[string]struct{}{}
	for _, n := range comp {
		inComp[n] = struct{}{}
	}
	start := comp[0]
	type frame struct {
		node string
		path []string
	}
	queue := []frame{{node: start, path: []string{start}}}
	visited := map[string]struct{}{start: {}}
	for len(queue) > 0 {
		f := queue[0]
		queue = queue[1:]
		for _, nxt := range adj[f.node] {
			if _, ok := inComp[nxt]; !ok {
				continue
			}
			if nxt == start && len(f.path) >= 1 {
				cyc := append(append([]string{}, f.path...), start)
				// >=3 distinct sites => path length before close is >=3 => cyc len >= 4
				if len(cyc) >= 4 {
					return cyc
				}
			}
			if _, seen := visited[nxt]; seen {
				continue
			}
			visited[nxt] = struct{}{}
			np := append(append([]string{}, f.path...), nxt)
			queue = append(queue, frame{node: nxt, path: np})
		}
	}
	return nil
}

func Reachable(adj map[string][]string, from string) map[string]struct{} {
	seen := map[string]struct{}{}
	if from == "" {
		return seen
	}
	stack := []string{from}
	seen[from] = struct{}{}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, nxt := range adj[cur] {
			if _, ok := seen[nxt]; ok {
				continue
			}
			seen[nxt] = struct{}{}
			stack = append(stack, nxt)
		}
	}
	return seen
}

func CascadeHops(rev map[string][]string, failed string) (maxHop int, reached map[string]int) {
	reached = map[string]int{}
	if failed == "" {
		return 0, reached
	}
	type item struct {
		id  string
		hop int
	}
	q := []item{{id: failed, hop: 0}}
	reached[failed] = 0
	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		for _, nxt := range rev[cur.id] {
			if _, ok := reached[nxt]; ok {
				continue
			}
			h := cur.hop + 1
			reached[nxt] = h
			if h > maxHop {
				maxHop = h
			}
			q = append(q, item{id: nxt, hop: h})
		}
	}
	return maxHop, reached
}

func LongestDeclaredDepth(adj map[string][]string, seed string) (deepest string, depth int) {
	if seed == "" {
		return "", 0
	}
	bestDepth := 0
	bestID := seed
	path := map[string]struct{}{seed: {}}
	var dfs func(id string, dep int)
	dfs = func(id string, dep int) {
		if dep > bestDepth || (dep == bestDepth && id < bestID) {
			bestDepth = dep
			bestID = id
		}
		for _, nxt := range adj[id] {
			if _, in := path[nxt]; in {
				continue
			}
			path[nxt] = struct{}{}
			dfs(nxt, dep+1)
			delete(path, nxt)
		}
	}
	dfs(seed, 0)
	return bestID, bestDepth
}

func MutualPairs(edges []Edge) [][2]string {
	forward := map[string]map[string]struct{}{}
	for _, e := range edges {
		if forward[e.From] == nil {
			forward[e.From] = map[string]struct{}{}
		}
		forward[e.From][e.To] = struct{}{}
	}
	seen := map[string]struct{}{}
	out := [][2]string{}
	for a, tos := range forward {
		for b := range tos {
			if _, ok := forward[b][a]; !ok {
				continue
			}
			key := a + ">" + b
			if _, ok := seen[key]; ok {
				continue
			}
			rev := b + ">" + a
			if _, ok := seen[rev]; ok {
				continue
			}
			seen[key] = struct{}{}
			lo, hi := a, b
			if b < a {
				lo, hi = b, a
			}
			out = append(out, [2]string{lo, hi})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i][0] != out[j][0] {
			return out[i][0] < out[j][0]
		}
		return out[i][1] < out[j][1]
	})
	return out
}

func CycleCoversPair(detail, a, b string) bool {
	nodes := strings.Split(detail, ">")
	hasA, hasB := false, false
	for _, n := range nodes[:len(nodes)-1] {
		if n == a {
			hasA = true
		}
		if n == b {
			hasB = true
		}
	}
	return hasA && hasB
}

func FormatInt(n int) string {
	return strconv.Itoa(n)
}
EOF

cat > /app/limitmath/resolve/policy.go <<'EOF'
package resolve

func ResolveCase(
	maxFanout int,
	maxDepth int,
	requireObserved bool,
	emitStale bool,
	scoreMutual bool,
	overrides map[string]interface{},
) (int, int, bool, bool, bool) {
	if overrides != nil {
		if v, ok := overrides["max_chain_depth"]; ok {
			if n, ok := toInt(v); ok && n >= 0 {
				maxDepth = n
			}
		}
		if v, ok := overrides["max_fanout_depth"]; ok {
			if n, ok := toInt(v); ok && n >= 0 {
				maxFanout = n
			}
		}
		if v, ok := overrides["require_observed_match"]; ok {
			if b, ok := toBool(v); ok {
				requireObserved = b
			}
		}
		if v, ok := overrides["emit_stale_couplings"]; ok {
			if b, ok := toBool(v); ok {
				emitStale = b
			}
		}
		if v, ok := overrides["score_mutual_couplings"]; ok {
			if b, ok := toBool(v); ok {
				scoreMutual = b
			}
		}
	}
	return maxFanout, maxDepth, requireObserved, emitStale, scoreMutual
}

func ResolveConfidence(
	minConf int,
	softDamp int,
	outlier int,
	overrides map[string]interface{},
) (int, int, int) {
	if overrides != nil {
		if v, ok := overrides["min_confidence"]; ok {
			if n, ok := toInt(v); ok && n >= 0 {
				minConf = n
			}
		}
		if v, ok := overrides["soft_dampen_pct"]; ok {
			if n, ok := toInt(v); ok && n >= 0 {
				softDamp = n
			}
		}
		if v, ok := overrides["outlier_threshold"]; ok {
			if n, ok := toInt(v); ok && n >= 0 {
				outlier = n
			}
		}
	}
	return minConf, softDamp, outlier
}

func toBool(v interface{}) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	default:
		return false, false
	}
}

func toInt(v interface{}) (int, bool) {
	switch x := v.(type) {
	case float64:
		return int(x), true
	case int:
		return x, true
	default:
		return 0, false
	}
}

func FeatureWeight(kind string) (int, bool) {
	w, ok := featureWeights[kind]
	return w, ok
}

func IsHardKind(kind string) bool {
	_, ok := hardKinds[kind]
	return ok
}

func IsSoftKind(kind string) bool {
	_, ok := softKinds[kind]
	return ok
}

var hardKinds = map[string]struct{}{
	"CYCLE_DETECTED": {}, "FANOUT_DEPTH": {}, "DEPTH_EXCEEDED": {},
	"REQUIRED_UNREACHABLE": {}, "SEED_UNREACHABLE": {}, "WEIGHT_STARVE": {},
	"CHANNEL_DRIFT": {},
}

var softKinds = map[string]struct{}{
	"MUTUAL_COUPLING": {}, "STALE_COUPLING": {}, "UNDECLARED_COUPLING": {},
	"ORPHAN_SITE": {}, "DUPLICATE_SITE": {}, "UNKNOWN_SINK": {}, "MISSING_SITE": {},
}

var featureWeights = map[string]int{
	"CYCLE_DETECTED": 40, "FANOUT_DEPTH": 34, "DEPTH_EXCEEDED": 34,
	"REQUIRED_UNREACHABLE": 34, "SEED_UNREACHABLE": 34, "WEIGHT_STARVE": 28,
	"CHANNEL_DRIFT": 28, "MUTUAL_COUPLING": 12, "STALE_COUPLING": 12,
	"UNDECLARED_COUPLING": 12, "ORPHAN_SITE": 55, "DUPLICATE_SITE": 12,
	"UNKNOWN_SINK": 12, "MISSING_SITE": 12,
}

func ScoreConfidence(kinds []string, softDamp int) (confidence int, hardCount int, softCount int, hasHard bool) {
	hardSum := 0
	softSum := 0
	hasDrift := false
	hasStarve := false
	distinctHard := map[string]struct{}{}
	for _, kind := range kinds {
		w, ok := featureWeights[kind]
		if !ok {
			continue
		}
		if IsHardKind(kind) {
			hardSum += w
			hardCount++
			hasHard = true
			distinctHard[kind] = struct{}{}
			if kind == "CHANNEL_DRIFT" {
				hasDrift = true
			}
			if kind == "WEIGHT_STARVE" {
				hasStarve = true
			}
		} else if IsSoftKind(kind) {
			softSum += w
			softCount++
		}
	}
	confidence = hardSum + softSum*softDamp/100
	if hasDrift && hasStarve {
		confidence += 10
	}
	if len(distinctHard) >= 3 {
		confidence += 12
	}
	if hardCount > 0 && softCount > 0 {
		confidence -= 6
	}
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 100 {
		confidence = 100
	}
	return confidence, hardCount, softCount, hasHard
}

func Verdict(confidence, minConf, outlier int, hasHard bool, findingCount int) (string, int) {
	if findingCount == 0 {
		return "STABLE", 0
	}
	if confidence < minConf {
		return "STABLE", 0
	}
	if confidence >= outlier && hasHard {
		return "OUTLIER", confidence
	}
	return "REVIEW", confidence
}

func CorrectionFor(kind, entity, detail, seed string) (action, target, rdetail string, ok bool) {
	switch kind {
	case "UNDECLARED_COUPLING":
		return "ADD_COUPLING", entity, detail, true
	case "STALE_COUPLING":
		return "DROP_COUPLING", entity, detail, true
	case "CYCLE_DETECTED":
		return "BREAK_CYCLE", entity, detail, true
	case "FANOUT_DEPTH":
		return "SHIELD_SITE", entity, detail, true
	case "SEED_UNREACHABLE", "REQUIRED_UNREACHABLE":
		return "REROUTE_PATH", entity, seed, true
	case "WEIGHT_STARVE":
		return "BOOST_FLUX", entity, detail, true
	default:
		return "", "", "", false
	}
}
EOF

rm -f /app/build/scorectl /app/build/pairing_class_report.json
make build
test -x /app/build/scorectl
make run
test -f /app/build/pairing_class_report.json
