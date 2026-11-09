#!/usr/bin/env bash
set -euo pipefail
cd /app
cat > /app/sigscore/zscore/zscore.go <<'EOF'
package zscore

import "math"

type FeatureSpec struct {
	Feature   string
	Weight    float64
	Direction string
}

type Sample struct {
	Mean float64 `json:"mean"`
	Obs  float64 `json:"obs"`
	Std  float64 `json:"std"`
}

type Factor struct {
	Feature      string  `json:"feature"`
	Z            float64 `json:"z"`
	Weight       float64 `json:"weight"`
	Contribution float64 `json:"contribution"`
}

func DefaultCatalog() []FeatureSpec {
	return []FeatureSpec{
		{Feature: "flow_bytes", Weight: 1.0, Direction: "HIGH"},
		{Feature: "auth_fail_rate", Weight: 1.5, Direction: "HIGH"},
		{Feature: "dns_nx", Weight: 1.2, Direction: "HIGH"},
		{Feature: "beacon_interval", Weight: 1.8, Direction: "LOW"},
		{Feature: "unique_peers", Weight: 1.1, Direction: "HIGH"},
	}
}

func CatalogIndex(feature string) int {
	for i, spec := range DefaultCatalog() {
		if spec.Feature == feature {
			return i
		}
	}
	return 999
}

func ZScore(mean, obs, std, sentinel float64, direction string) float64 {
	if std <= 0 {
		if obs == mean {
			return 0
		}
		return sentinel
	}
	if direction == "LOW" {
		return (mean - obs) / std
	}
	return (obs - mean) / std
}

func Round4(v float64) float64 {
	return math.Round(v*10000) / 10000
}

func Suppress(factors []Factor) []Factor {
	hasBeacon, hasPeers := false, false
	for _, f := range factors {
		if f.Feature == "beacon_interval" {
			hasBeacon = true
		}
		if f.Feature == "unique_peers" {
			hasPeers = true
		}
	}
	if !(hasBeacon && hasPeers) {
		return factors
	}
	out := make([]Factor, 0, len(factors))
	for _, f := range factors {
		if f.Feature == "unique_peers" {
			continue
		}
		out = append(out, f)
	}
	return out
}

func CollectDeviations(features map[string]Sample, threshold, sentinel float64) []Factor {
	raw := make([]Factor, 0)
	for _, spec := range DefaultCatalog() {
		sample, ok := features[spec.Feature]
		if !ok {
			continue
		}
		z := Round4(ZScore(sample.Mean, sample.Obs, sample.Std, sentinel, spec.Direction))
		if z > threshold {
			excess := z - threshold
			if excess < 0 {
				excess = 0
			}
			raw = append(raw, Factor{
				Feature:      spec.Feature,
				Z:            z,
				Weight:       spec.Weight,
				Contribution: Round4(spec.Weight * math.Log1p(excess)),
			})
		}
	}
	return Suppress(raw)
}

func Confidence(sumContrib, scale float64) float64 {
	if scale <= 0 {
		scale = 2.5
	}
	return Round4(1 - math.Exp(-sumContrib/scale))
}
EOF

cat > /app/peerhunt/mesh/mesh.go <<'EOF'
package mesh

import "sort"

type Cluster struct {
	ClusterID string   `json:"cluster_id"`
	Members   []string `json:"members"`
	Size      int      `json:"size"`
}

type Link struct {
	From          string
	To            string
	Cost          int
	Bidirectional bool
}

func joinPlus(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for i := 1; i < len(parts); i++ {
		out += "+" + parts[i]
	}
	return out
}

func addEdge(g map[string]map[string]int, a, b string, cost int) {
	if cost <= 0 || a == "" || b == "" || a == b {
		return
	}
	if g[a] == nil {
		g[a] = map[string]int{}
	}
	prev, ok := g[a][b]
	if !ok || cost < prev {
		g[a][b] = cost
	}
}

func BuildDirected(hostIDs []string, hostPeers map[string][]string, links []Link) map[string]map[string]int {
	known := map[string]struct{}{}
	for _, h := range hostIDs {
		known[h] = struct{}{}
	}
	g := map[string]map[string]int{}
	for _, h := range hostIDs {
		g[h] = map[string]int{}
	}
	for h, peers := range hostPeers {
		if _, ok := known[h]; !ok {
			continue
		}
		for _, p := range peers {
			if _, ok := known[p]; !ok {
				continue
			}
			addEdge(g, h, p, 1)
			addEdge(g, p, h, 1)
		}
	}
	for _, lk := range links {
		if lk.Cost <= 0 {
			continue
		}
		if _, ok := known[lk.From]; !ok {
			continue
		}
		if _, ok := known[lk.To]; !ok {
			continue
		}
		addEdge(g, lk.From, lk.To, lk.Cost)
		if lk.Bidirectional {
			addEdge(g, lk.To, lk.From, lk.Cost)
		}
	}
	return g
}

func BuildPeerCluster(hostIDs []string, hostPeers map[string][]string) map[string]map[string]int {
	known := map[string]struct{}{}
	for _, h := range hostIDs {
		known[h] = struct{}{}
	}
	g := map[string]map[string]int{}
	for _, h := range hostIDs {
		g[h] = map[string]int{}
	}
	for h, peers := range hostPeers {
		if _, ok := known[h]; !ok {
			continue
		}
		for _, p := range peers {
			if _, ok := known[p]; !ok {
				continue
			}
			addEdge(g, h, p, 1)
			addEdge(g, p, h, 1)
		}
	}
	return g
}

func DirectEdgeCost(g map[string]map[string]int, src, dst string) (int, bool) {
	if g[src] == nil {
		return 0, false
	}
	c, ok := g[src][dst]
	return c, ok
}

func BuildClusters(alertHosts []string, undirected map[string]map[string]int, minSize int) ([]Cluster, map[string]string) {
	membership := map[string]string{}
	if len(alertHosts) == 0 {
		return []Cluster{}, membership
	}
	alertSet := map[string]struct{}{}
	for _, h := range alertHosts {
		alertSet[h] = struct{}{}
	}
	visited := map[string]struct{}{}
	components := make([][]string, 0)
	ordered := append([]string(nil), alertHosts...)
	sort.Strings(ordered)
	for _, h := range ordered {
		if _, ok := visited[h]; ok {
			continue
		}
		stack := []string{h}
		visited[h] = struct{}{}
		comp := make([]string, 0)
		for len(stack) > 0 {
			cur := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			comp = append(comp, cur)
			neighbors := make([]string, 0)
			for n := range undirected[cur] {
				if _, ok := alertSet[n]; ok {
					neighbors = append(neighbors, n)
				}
			}
			sort.Strings(neighbors)
			for _, n := range neighbors {
				if _, seen := visited[n]; seen {
					continue
				}
				visited[n] = struct{}{}
				stack = append(stack, n)
			}
		}
		sort.Strings(comp)
		components = append(components, comp)
	}
	sort.Slice(components, func(i, j int) bool {
		return joinPlus(components[i]) < joinPlus(components[j])
	})
	clusters := make([]Cluster, 0)
	for _, comp := range components {
		if len(comp) < minSize {
			continue
		}
		id := "CL-" + joinPlus(comp)
		clusters = append(clusters, Cluster{ClusterID: id, Members: append([]string(nil), comp...), Size: len(comp)})
		for _, m := range comp {
			membership[m] = id
		}
	}
	sort.Slice(clusters, func(i, j int) bool { return clusters[i].ClusterID < clusters[j].ClusterID })
	return clusters, membership
}

func ClusterBoost(size int, inCluster bool) float64 {
	if !inCluster {
		return 1.0
	}
	return 1.0 + 0.15*float64(size)
}
EOF

cat > /app/triageprio/rank/rank.go <<'EOF'
package rank

import (
	"encoding/json"
	"math"
	"os"
	"sort"

	"huntsig/peerhunt/mesh"
	"huntsig/sigscore/zscore"
)

type FeatureSample = zscore.Sample

type HostIn struct {
	HostID   string                   `json:"host_id"`
	Role     string                   `json:"role"`
	Features map[string]FeatureSample `json:"features"`
	Peers    []string                 `json:"peers"`
}

type PeerLink struct {
	From          string `json:"from"`
	To            string `json:"to"`
	Cost          int    `json:"cost"`
	Bidirectional bool   `json:"bidirectional"`
}

type Window struct {
	WindowID            string                 `json:"window_id"`
	ZThreshold          *float64               `json:"z_threshold"`
	EscalateZ           *float64               `json:"escalate_z"`
	MinClusterSize      *int                   `json:"min_cluster_size"`
	ConfidenceFloor     *float64               `json:"confidence_floor"`
	ContribScale        *float64               `json:"contrib_scale"`
	MinEmitContribution *float64               `json:"min_emit_contribution"`
	ContagionMaxCost    *int                   `json:"contagion_max_cost"`
	ContagionDamp       *float64               `json:"contagion_damp"`
	QuarantineDamp      *float64               `json:"quarantine_damp"`
	QuarantineMin       *int                   `json:"quarantine_min"`
	QuarantineCost      *int                   `json:"quarantine_cost"`
	ContagionSeedZ      *float64               `json:"contagion_seed_z"`
	PolicyOverrides     map[string]interface{} `json:"policy_overrides"`
	PeerLinks           []PeerLink             `json:"peer_links"`
	Hosts               []HostIn               `json:"hosts"`
}

type HostOut struct {
	HostID         string  `json:"host_id"`
	Role           string  `json:"role"`
	Verdict        string  `json:"verdict"`
	Confidence     float64 `json:"confidence"`
	DeviationCount int     `json:"deviation_count"`
}

type FactorOut = zscore.Factor

type Investigation struct {
	InvestigationID string      `json:"investigation_id"`
	HostID          string      `json:"host_id"`
	ClusterID       string      `json:"cluster_id"`
	Confidence      float64     `json:"confidence"`
	Priority        float64     `json:"priority"`
	Risk            string      `json:"risk"`
	Factors         []FactorOut `json:"factors"`
}

type WindowOut struct {
	WindowID       string          `json:"window_id"`
	Status         string          `json:"status"`
	Hosts          []HostOut       `json:"hosts"`
	Clusters       []mesh.Cluster  `json:"clusters"`
	Investigations []Investigation `json:"investigations"`
}

type Report struct {
	Windows []WindowOut `json:"windows"`
}

func LoadWindow(path string) (Window, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Window{}, err
	}
	var w Window
	if err := json.Unmarshal(data, &w); err != nil {
		return Window{}, err
	}
	return w, nil
}

type policy struct {
	zThreshold, escalateZ, confFloor, contribScale, minEmit float64
	minCluster, contagionMax, quarantineMin, quarantineCost int
	contagionDamp, quarantineDamp, contagionSeedZ           float64
}

func ResolveWindow(p policy, overrides map[string]interface{}) policy {
	if overrides == nil {
		return p
	}
	setF := func(key string, dst *float64, requirePos bool) {
		if v, ok := overrides[key]; ok {
			if f, ok := toFloat(v); ok {
				if !requirePos || f > 0 {
					*dst = f
				}
			}
		}
	}
	setI := func(key string, dst *int, min int) {
		if v, ok := overrides[key]; ok {
			if n, ok := toInt(v); ok && n >= min {
				*dst = n
			}
		}
	}
	setF("z_threshold", &p.zThreshold, true)
	setF("escalate_z", &p.escalateZ, true)
	setI("min_cluster_size", &p.minCluster, 1)
	setF("confidence_floor", &p.confFloor, false)
	setF("contrib_scale", &p.contribScale, true)
	setF("min_emit_contribution", &p.minEmit, false)
	setI("contagion_max_cost", &p.contagionMax, 0)
	setF("contagion_damp", &p.contagionDamp, true)
	setF("quarantine_damp", &p.quarantineDamp, true)
	setI("quarantine_min", &p.quarantineMin, 1)
	setI("quarantine_cost", &p.quarantineCost, 0)
	setF("contagion_seed_z", &p.contagionSeedZ, true)
	return p
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

func toFloat(v interface{}) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	default:
		return 0, false
	}
}

func RoleMult(role string) float64 {
	switch role {
	case "server":
		return 1.25
	case "dns":
		return 1.35
	case "dc":
		return 1.5
	default:
		return 1.0
	}
}

func riskRank(risk string) int {
	switch risk {
	case "HIGH":
		return 0
	case "MEDIUM":
		return 1
	default:
		return 2
	}
}

func privileged(role string) bool {
	return role == "server" || role == "dns" || role == "dc"
}

func stagedPriority(conf, role, severity, boost, damp float64) float64 {
	stage1 := zscore.Round4(conf * role)
	stage2 := zscore.Round4(stage1 * severity)
	stage3 := zscore.Round4(stage2 * boost)
	return zscore.Round4(stage3 * damp)
}

func AnalyzeWindow(w Window) WindowOut {
	p := policy{
		zThreshold: 2.5, escalateZ: 8.0, minCluster: 2, confFloor: 0.4,
		contribScale: 2.5, minEmit: 1.0, contagionMax: 2, contagionDamp: 0.9,
		quarantineDamp: 0.85, quarantineMin: 2, quarantineCost: 1, contagionSeedZ: 10.0,
	}
	if w.ZThreshold != nil {
		p.zThreshold = *w.ZThreshold
	}
	if w.EscalateZ != nil {
		p.escalateZ = *w.EscalateZ
	}
	if w.MinClusterSize != nil {
		p.minCluster = *w.MinClusterSize
	}
	if w.ConfidenceFloor != nil {
		p.confFloor = *w.ConfidenceFloor
	}
	if w.ContribScale != nil {
		p.contribScale = *w.ContribScale
	}
	if w.MinEmitContribution != nil {
		p.minEmit = *w.MinEmitContribution
	}
	if w.ContagionMaxCost != nil {
		p.contagionMax = *w.ContagionMaxCost
	}
	if w.ContagionDamp != nil {
		p.contagionDamp = *w.ContagionDamp
	}
	if w.QuarantineDamp != nil {
		p.quarantineDamp = *w.QuarantineDamp
	}
	if w.QuarantineMin != nil {
		p.quarantineMin = *w.QuarantineMin
	}
	if w.QuarantineCost != nil {
		p.quarantineCost = *w.QuarantineCost
	}
	if w.ContagionSeedZ != nil {
		p.contagionSeedZ = *w.ContagionSeedZ
	}
	p = ResolveWindow(p, w.PolicyOverrides)

	hostIDs := make([]string, 0, len(w.Hosts))
	hostPeers := map[string][]string{}
	for _, h := range w.Hosts {
		hostIDs = append(hostIDs, h.HostID)
		hostPeers[h.HostID] = append([]string(nil), h.Peers...)
	}
	links := make([]mesh.Link, 0, len(w.PeerLinks))
	for _, pl := range w.PeerLinks {
		links = append(links, mesh.Link{From: pl.From, To: pl.To, Cost: pl.Cost, Bidirectional: pl.Bidirectional})
	}
	directed := mesh.BuildDirected(hostIDs, hostPeers, links)
	peerCluster := mesh.BuildPeerCluster(hostIDs, hostPeers)

	type scored struct {
		host        HostIn
		factors     []FactorOut
		conf        float64
		verdict     string
		maxZ        float64
		promoteKind string
		hops        int
	}
	scoredHosts := make([]scored, 0, len(w.Hosts))
	for _, h := range w.Hosts {
		factors := zscore.CollectDeviations(h.Features, p.zThreshold, 1000)
		sum := 0.0
		maxZ := 0.0
		for _, f := range factors {
			sum += f.Contribution
			if f.Z > maxZ {
				maxZ = f.Z
			}
		}
		conf := 0.0
		verdict := "CLEAN"
		if len(factors) > 0 {
			conf = zscore.Confidence(sum, p.contribScale)
			if conf < p.confFloor {
				verdict = "WATCH"
			} else if len(factors) >= 2 || privileged(h.Role) || maxZ >= p.escalateZ {
				verdict = "ALERT"
			} else {
				verdict = "WATCH"
			}
		}
		scoredHosts = append(scoredHosts, scored{host: h, factors: factors, conf: conf, verdict: verdict, maxZ: maxZ})
	}

	// Quarantine FIRST against provisional ALERTs only.
	for i := range scoredHosts {
		if scoredHosts[i].verdict != "WATCH" {
			continue
		}
		hid := scoredHosts[i].host.HostID
		cnt := 0
		for _, s := range scoredHosts {
			if s.verdict != "ALERT" || s.promoteKind != "" {
				continue
			}
			if cost, ok := mesh.DirectEdgeCost(directed, s.host.HostID, hid); ok && cost <= p.quarantineCost {
				cnt++
			}
		}
		if cnt >= p.quarantineMin {
			scoredHosts[i].verdict = "ALERT"
			scoredHosts[i].promoteKind = "quarantine"
			scoredHosts[i].hops = 1
		}
	}

	// Iterative half-open contagion: cost < contagionMax
	changed := true
	for changed {
		changed = false
		spreaders := make([]int, 0)
		for i, s := range scoredHosts {
			if s.verdict != "ALERT" {
				continue
			}
			if s.promoteKind == "quarantine" {
				continue
			}
			if s.promoteKind == "contagion" || s.maxZ >= p.contagionSeedZ {
				spreaders = append(spreaders, i)
			}
		}
		for i := range scoredHosts {
			if scoredHosts[i].verdict != "WATCH" {
				continue
			}
			hid := scoredHosts[i].host.HostID
			can := false
			for _, si := range spreaders {
				sp := scoredHosts[si]
				if cost, ok := mesh.DirectEdgeCost(directed, sp.host.HostID, hid); ok && cost < p.contagionMax {
					can = true
					break
				}
			}
			if can {
				scoredHosts[i].verdict = "ALERT"
				scoredHosts[i].promoteKind = "contagion"
				scoredHosts[i].hops = 1
				changed = true
			}
		}
	}

	// Recompute contagion hops as MAXIMUM over qualifying spreaders.
	for i := range scoredHosts {
		if scoredHosts[i].promoteKind != "contagion" {
			if scoredHosts[i].verdict == "ALERT" && scoredHosts[i].promoteKind == "" {
				scoredHosts[i].hops = 0
			}
			continue
		}
		scoredHosts[i].hops = 0
	}
	for pass := 0; pass < len(scoredHosts); pass++ {
		changedHops := false
		for i := range scoredHosts {
			if scoredHosts[i].promoteKind != "contagion" {
				continue
			}
			hid := scoredHosts[i].host.HostID
			best := -1
			for _, s := range scoredHosts {
				if s.verdict != "ALERT" || s.promoteKind == "quarantine" {
					continue
				}
				if !(s.promoteKind == "contagion" || s.maxZ >= p.contagionSeedZ) {
					continue
				}
				if cost, ok := mesh.DirectEdgeCost(directed, s.host.HostID, hid); ok && cost < p.contagionMax {
					cand := s.hops + 1
					if best < 0 || cand > best {
						best = cand
					}
				}
			}
			if best >= 0 && best != scoredHosts[i].hops {
				scoredHosts[i].hops = best
				changedHops = true
			}
		}
		if !changedHops {
			break
		}
	}

	alertIDs := make([]string, 0)
	for _, s := range scoredHosts {
		if s.verdict == "ALERT" {
			alertIDs = append(alertIDs, s.host.HostID)
		}
	}
	sort.Strings(alertIDs)
	clusters, membership := mesh.BuildClusters(alertIDs, peerCluster, p.minCluster)

	hostsOut := make([]HostOut, 0, len(scoredHosts))
	investigations := make([]Investigation, 0)
	for _, s := range scoredHosts {
		hostsOut = append(hostsOut, HostOut{
			HostID: s.host.HostID, Role: s.host.Role, Verdict: s.verdict,
			Confidence: s.conf, DeviationCount: len(s.factors),
		})
		if s.verdict == "CLEAN" {
			continue
		}
		cid := membership[s.host.HostID]
		inCluster := cid != ""
		organic := 0
		if inCluster {
			for _, other := range scoredHosts {
				if membership[other.host.HostID] == cid && other.promoteKind == "" {
					organic++
				}
			}
		}
		boost := 1.0
		if s.promoteKind == "" && inCluster {
			boost = 1.0 + 0.15*float64(organic)
		}
		emit := make([]FactorOut, 0)
		severe := 0
		for _, f := range s.factors {
			if f.Z >= 5.0 {
				severe++
			}
			if f.Contribution >= p.minEmit {
				emit = append(emit, f)
			}
		}
		sort.Slice(emit, func(i, j int) bool {
			ii, jj := zscore.CatalogIndex(emit[i].Feature), zscore.CatalogIndex(emit[j].Feature)
			if ii != jj {
				return ii < jj
			}
			return emit[i].Contribution > emit[j].Contribution
		})
		severity := 1.0 + 0.05*float64(severe)
		damp := 1.0
		if s.promoteKind == "contagion" {
			damp = math.Pow(p.contagionDamp, float64(s.hops))
		} else if s.promoteKind == "quarantine" {
			damp = p.quarantineDamp
		}
		priority := stagedPriority(s.conf, RoleMult(s.host.Role), severity, boost, damp)
		risk := "LOW"
		if s.verdict == "ALERT" && s.conf >= 0.8 && s.maxZ >= 5.0 {
			risk = "HIGH"
		} else if s.conf >= p.confFloor {
			risk = "MEDIUM"
		}
		investigations = append(investigations, Investigation{
			InvestigationID: w.WindowID + "::" + s.host.HostID,
			HostID:          s.host.HostID,
			ClusterID:       cid,
			Confidence:      s.conf,
			Priority:        priority,
			Risk:            risk,
			Factors:         emit,
		})
	}
	sort.Slice(hostsOut, func(i, j int) bool { return hostsOut[i].HostID < hostsOut[j].HostID })
	sort.Slice(investigations, func(i, j int) bool {
		if investigations[i].Priority != investigations[j].Priority {
			return investigations[i].Priority > investigations[j].Priority
		}
		ri, rj := riskRank(investigations[i].Risk), riskRank(investigations[j].Risk)
		if ri != rj {
			return ri < rj
		}
		return investigations[i].HostID < investigations[j].HostID
	})
	status := "CLEAN"
	for _, h := range hostsOut {
		if h.Verdict == "ALERT" {
			status = "ALERT"
			break
		}
		if h.Verdict == "WATCH" && status == "CLEAN" {
			status = "WATCH"
		}
	}
	return WindowOut{WindowID: w.WindowID, Status: status, Hosts: hostsOut, Clusters: clusters, Investigations: investigations}
}

EOF

make clean || true
make build
make run
