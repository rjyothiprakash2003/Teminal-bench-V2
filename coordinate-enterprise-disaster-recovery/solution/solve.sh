#!/usr/bin/env bash
set -euo pipefail
cd /app
cat > /app/wavesync/drill/analyze.go <<'EOF'
package drill

import (
	"encoding/json"
	"os"
	"sort"

	"drcoord/depgraph/order"
	"drcoord/slaedge/policy"
)

type Event struct {
	Seq            int    `json:"seq"`
	EventID        string `json:"event_id"`
	Kind           string `json:"kind"`
	DatacenterID   string `json:"datacenter_id"`
	RegionClass    string `json:"region_class"`
	CapacityUnits  int    `json:"capacity_units"`
	SnapshotID     string `json:"snapshot_id"`
	ServiceID      string `json:"service_id"`
	Checksum       string `json:"checksum"`
	CapturedAt     string `json:"captured_at"`
	LagSec         int    `json:"lag_sec"`
	FromService    string `json:"from_service"`
	ToService      string `json:"to_service"`
	WaveID         string `json:"wave_id"`
	WaveIndex      int    `json:"wave_index"`
	MaxConcurrent  int    `json:"max_concurrent"`
	StartedAt      string `json:"started_at"`
	FinishedAt     string `json:"finished_at"`
	ReplicaCount   int    `json:"replica_count"`
	ProbeID        string `json:"probe_id"`
	Healthy        bool   `json:"healthy"`
	Critical       bool   `json:"critical"`
	Reason         string `json:"reason"`
	ClosedAt       string `json:"closed_at"`
	FailoverTarget string `json:"failover_target"`
}

type Drill struct {
	DrillID          string                 `json:"drill_id"`
	RpoLimitSec      *int                   `json:"rpo_limit_sec"`
	RtoLimitSec      *int                   `json:"rto_limit_sec"`
	MaxSnapshotAge   *int                   `json:"max_snapshot_age_sec"`
	HealthQuorumPct  *int                   `json:"health_quorum_pct"`
	MaxWaveCapacity  *int                   `json:"max_wave_capacity"`
	RequireDepOrder  *bool                  `json:"require_dependency_order"`
	RiskCeiling      *int                   `json:"risk_ceiling"`
	MinReplicas      *int                   `json:"min_replicas"`
	AllowedFailovers []string               `json:"allowed_failovers"`
	PolicyOverrides  map[string]interface{} `json:"policy_overrides"`
	Events           []Event                `json:"events"`
}

type DCOut struct {
	DatacenterID  string `json:"datacenter_id"`
	RegionClass   string `json:"region_class"`
	CapacityUnits int    `json:"capacity_units"`
}

type SvcOut struct {
	ServiceID  string `json:"service_id"`
	State      string `json:"state"`
	SnapshotID string `json:"snapshot_id"`
	WaveID     string `json:"wave_id"`
}

type Finding struct {
	FindingID string `json:"finding_id"`
	EntityID  string `json:"entity_id"`
	Kind      string `json:"kind"`
	EventSeq  int    `json:"event_seq"`
	Detail    string `json:"detail"`
}

type MetricsOut struct {
	RtoSec          int `json:"rto_sec"`
	RpoSec          int `json:"rpo_sec"`
	AvailabilityPct int `json:"availability_pct"`
	RiskScore       int `json:"risk_score"`
	TimelineSec     int `json:"timeline_sec"`
}

type DrillOut struct {
	DrillID                string     `json:"drill_id"`
	Status                 string     `json:"status"`
	DuplicateEventsSkipped int        `json:"duplicate_events_skipped"`
	Datacenters            []DCOut    `json:"datacenters"`
	Services               []SvcOut   `json:"services"`
	Findings               []Finding  `json:"findings"`
	Metrics                MetricsOut `json:"metrics"`
}

type Report struct {
	Drills []DrillOut `json:"drills"`
}

type dcState struct {
	regionClass   string
	capacityUnits int
}

type snapState struct {
	serviceID  string
	checksum   string
	capturedAt string
	lagSec     int
}

type svcState struct {
	state      string
	snapshotID string
	waveID     string
}

type waveState struct {
	index         int
	maxConcurrent int
	restored      int
}

type probeState struct {
	healthy  bool
	critical bool
}

func LoadDrill(path string) (Drill, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Drill{}, err
	}
	var sc Drill
	if err := json.Unmarshal(data, &sc); err != nil {
		return Drill{}, err
	}
	return sc, nil
}

func findingID(drillID, entityID string, seq int) string {
	return drillID + "::" + entityID + "::" + formatSeq(seq)
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

func formatInt(n int) string {
	if n < 0 {
		n = 0
	}
	s := []byte("0000")
	for i := 3; i >= 0; i-- {
		s[i] = byte('0' + n%10)
		n /= 10
	}
	return string(s)
}

func appendFinding(findings *[]Finding, drillID, entityID, kind, detail string, seq int) {
	*findings = append(*findings, Finding{
		FindingID: findingID(drillID, entityID, seq),
		EntityID:  entityID,
		Kind:      kind,
		EventSeq:  seq,
		Detail:    detail,
	})
}

func Analyze(sc Drill) DrillOut {
	rpoLimit := 300
	if sc.RpoLimitSec != nil {
		rpoLimit = *sc.RpoLimitSec
	}
	rtoLimit := 900
	if sc.RtoLimitSec != nil {
		rtoLimit = *sc.RtoLimitSec
	}
	maxAge := 86400
	if sc.MaxSnapshotAge != nil {
		maxAge = *sc.MaxSnapshotAge
	}
	quorumPct := 67
	if sc.HealthQuorumPct != nil {
		quorumPct = *sc.HealthQuorumPct
	}
	maxWave := 2
	if sc.MaxWaveCapacity != nil {
		maxWave = *sc.MaxWaveCapacity
	}
	requireDep := true
	if sc.RequireDepOrder != nil {
		requireDep = *sc.RequireDepOrder
	}
	riskCeiling := 50
	if sc.RiskCeiling != nil {
		riskCeiling = *sc.RiskCeiling
	}
	minReplicas := 1
	if sc.MinReplicas != nil {
		minReplicas = *sc.MinReplicas
	}
	rpoLimit, rtoLimit, maxAge, quorumPct, maxWave, requireDep, riskCeiling, minReplicas = policy.ResolveDrill(
		rpoLimit, rtoLimit, maxAge, quorumPct, maxWave, requireDep, riskCeiling, minReplicas, sc.PolicyOverrides,
	)

	allowed := map[string]struct{}{}
	for _, a := range sc.AllowedFailovers {
		allowed[a] = struct{}{}
	}
	if len(allowed) == 0 {
		allowed["primary>dr"] = struct{}{}
		allowed["dr>primary"] = struct{}{}
	}

	dcs := make(map[string]*dcState)
	snaps := make(map[string]*snapState)
	svcs := make(map[string]*svcState)
	waves := make(map[string]*waveState)
	probes := make(map[string]*probeState)
	deps := order.NewGraph()
	findings := make([]Finding, 0)
	maxSeq := 0
	rollbackDone := false
	var firstStart, lastFinish string
	maxRto := 0
	maxRpoUsed := 0
	known := map[string]struct{}{}

	sorted := SortEvents(sc.Events)
	events, dupSkipped := FilterDuplicateEvents(sorted)

	for _, ev := range events {
		seq := ev.Seq
		if seq > maxSeq {
			maxSeq = seq
		}
		switch ev.Kind {
		case "REGISTER_DATACENTER":
			if _, exists := dcs[ev.DatacenterID]; exists {
				appendFinding(&findings, sc.DrillID, ev.DatacenterID, "DUPLICATE_DATACENTER", "", seq)
				continue
			}
			dcs[ev.DatacenterID] = &dcState{regionClass: ev.RegionClass, capacityUnits: ev.CapacityUnits}
		case "DECLARE_SNAPSHOT":
			snaps[ev.SnapshotID] = &snapState{
				serviceID: ev.ServiceID, checksum: ev.Checksum, capturedAt: ev.CapturedAt, lagSec: ev.LagSec,
			}
			known[ev.ServiceID] = struct{}{}
			if _, ok := svcs[ev.ServiceID]; !ok {
				svcs[ev.ServiceID] = &svcState{state: "declared"}
			}
		case "LINK_DEPENDENCY":
			_, fromOK := known[ev.FromService]
			_, toOK := known[ev.ToService]
			if !fromOK {
				appendFinding(&findings, sc.DrillID, ev.FromService, "ORPHAN_EDGE", ev.ToService, seq)
				continue
			}
			if !toOK {
				appendFinding(&findings, sc.DrillID, ev.ToService, "ORPHAN_EDGE", ev.FromService, seq)
				continue
			}
			if _, ok := svcs[ev.FromService]; !ok {
				svcs[ev.FromService] = &svcState{state: "declared"}
			}
			if _, ok := svcs[ev.ToService]; !ok {
				svcs[ev.ToService] = &svcState{state: "declared"}
			}
			deps.AddEdge(ev.FromService, ev.ToService)
		case "START_WAVE":
			waves[ev.WaveID] = &waveState{index: ev.WaveIndex, maxConcurrent: ev.MaxConcurrent}
		case "RESTORE_SERVICE":
			if _, ok := known[ev.ServiceID]; !ok {
				appendFinding(&findings, sc.DrillID, ev.ServiceID, "UNKNOWN_SERVICE", ev.SnapshotID, seq)
				continue
			}
			snap, sok := snaps[ev.SnapshotID]
			if !sok {
				appendFinding(&findings, sc.DrillID, ev.SnapshotID, "SNAPSHOT_MISSING", ev.ServiceID, seq)
				continue
			}
			if !policy.ChecksumExact(snap.checksum, ev.Checksum) {
				appendFinding(&findings, sc.DrillID, ev.SnapshotID, "SNAPSHOT_CORRUPT", ev.Checksum, seq)
				continue
			}
			if policy.RPOExceeded(snap.lagSec, rpoLimit) {
				appendFinding(&findings, sc.DrillID, ev.SnapshotID, "RPO_BREACH", formatInt(snap.lagSec), seq)
				continue
			}
			if snap.lagSec > maxRpoUsed {
				maxRpoUsed = snap.lagSec
			}
			if policy.SnapshotStale(snap.capturedAt, ev.StartedAt, maxAge) {
				appendFinding(&findings, sc.DrillID, ev.SnapshotID, "STALE_SNAPSHOT", snap.capturedAt, seq)
				continue
			}
			if ev.FailoverTarget != "" {
				srcClass := ""
				for _, d := range dcs {
					if d.regionClass == "primary" {
						srcClass = "primary"
						break
					}
				}
				if srcClass == "" {
					ids := make([]string, 0, len(dcs))
					for id := range dcs {
						ids = append(ids, id)
					}
					sort.Strings(ids)
					if len(ids) > 0 {
						srcClass = dcs[ids[0]].regionClass
					}
				}
				dstClass := ""
				if d, ok := dcs[ev.FailoverTarget]; ok {
					dstClass = d.regionClass
				} else {
					appendFinding(&findings, sc.DrillID, ev.FailoverTarget, "FAILOVER_DENIED", "missing_dc", seq)
					continue
				}
				pair := srcClass + ">" + dstClass
				if _, ok := allowed[pair]; !ok {
					appendFinding(&findings, sc.DrillID, ev.FailoverTarget, "REGION_PAIR_DENIED", pair, seq)
					continue
				}
			}
			st := svcs[ev.ServiceID]
			if st == nil {
				st = &svcState{state: "declared"}
				svcs[ev.ServiceID] = st
			}
			if st.state == "restoring" || st.state == "restored" {
				appendFinding(&findings, sc.DrillID, ev.ServiceID, "PARALLEL_CONFLICT", st.state, seq)
				continue
			}
			if requireDep {
				restored := map[string]bool{}
				for id, s := range svcs {
					restored[id] = s.state == "restored"
				}
				if blocked := order.UnmetProviders(deps, ev.ServiceID, restored); blocked != "" {
					appendFinding(&findings, sc.DrillID, ev.ServiceID, "DEPENDENCY_BLOCKED", blocked, seq)
					continue
				}
			}
			w, wok := waves[ev.WaveID]
			if wok {
				prior := ""
				for wid, ow := range waves {
					if ow.index < w.index && ow.restored == 0 {
						if prior == "" || wid < prior {
							prior = wid
						}
					}
				}
				if prior != "" {
					appendFinding(&findings, sc.DrillID, ev.WaveID, "WAVE_ORDER_VIOLATION", prior, seq)
					continue
				}
				cap := policy.EffectiveWaveCap(maxWave, w.maxConcurrent)
				if w.restored >= cap {
					appendFinding(&findings, sc.DrillID, ev.WaveID, "WAVE_CAPACITY_EXCEEDED", formatInt(cap), seq)
					continue
				}
			}
			dur := policy.DurationSec(ev.StartedAt, ev.FinishedAt)
			if policy.RTOExceeded(dur, rtoLimit) {
				appendFinding(&findings, sc.DrillID, ev.ServiceID, "RTO_BREACH", formatInt(dur), seq)
				continue
			}
			if dur > maxRto {
				maxRto = dur
			}
			if ev.ReplicaCount < minReplicas {
				appendFinding(&findings, sc.DrillID, ev.ServiceID, "INSUFFICIENT_REPLICAS", formatInt(ev.ReplicaCount), seq)
				continue
			}
			st.state = "restored"
			st.snapshotID = ev.SnapshotID
			st.waveID = ev.WaveID
			if wok {
				w.restored++
			}
			if firstStart == "" || ev.StartedAt < firstStart {
				firstStart = ev.StartedAt
			}
			if ev.FinishedAt > lastFinish {
				lastFinish = ev.FinishedAt
			}
		case "PROBE_HEALTH":
			probes[ev.ProbeID] = &probeState{healthy: ev.Healthy, critical: ev.Critical}
			if ev.Critical && !ev.Healthy {
				appendFinding(&findings, sc.DrillID, ev.ProbeID, "CRITICAL_PROBE_FAIL", ev.ServiceID, seq)
			}
		case "EXECUTE_ROLLBACK":
			targets := order.DirectDependents(deps, ev.ServiceID)
			for _, t := range targets {
				if s, ok := svcs[t]; ok {
					s.state = "rolled_back"
				}
			}
			if s, ok := svcs[ev.ServiceID]; ok {
				s.state = "rolled_back"
			} else {
				appendFinding(&findings, sc.DrillID, ev.ServiceID, "ROLLBACK_INCOMPLETE", ev.Reason, seq)
			}
			rollbackDone = true
		case "CLOSE_DRILL":
			total := len(probes)
			healthyN := 0
			for _, p := range probes {
				if p.healthy {
					healthyN++
				}
			}
			if total > 0 {
				need := policy.QuorumRequired(total, quorumPct)
				if healthyN < need {
					appendFinding(&findings, sc.DrillID, sc.DrillID, "HEALTH_QUORUM_MISS", formatInt(healthyN), seq)
				}
			}
			risk := policy.RiskScore(findingKinds(findings))
			if risk > riskCeiling {
				appendFinding(&findings, sc.DrillID, sc.DrillID, "RISK_CEILING_HIT", formatInt(risk), seq)
			}
		}
	}

	auditSeq := maxSeq + 1
	if cyc := order.DetectCycle(deps); cyc != "" {
		appendFinding(&findings, sc.DrillID, cycleEntity(cyc), "DEPENDENCY_CYCLE", cyc, auditSeq)
	}

	outDC := make([]DCOut, 0, len(dcs))
	ids := make([]string, 0, len(dcs))
	for id := range dcs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		d := dcs[id]
		outDC = append(outDC, DCOut{DatacenterID: id, RegionClass: d.regionClass, CapacityUnits: d.capacityUnits})
	}

	outSvc := make([]SvcOut, 0, len(svcs))
	sids := make([]string, 0, len(svcs))
	for id := range svcs {
		sids = append(sids, id)
	}
	sort.Strings(sids)
	for _, id := range sids {
		s := svcs[id]
		outSvc = append(outSvc, SvcOut{ServiceID: id, State: s.state, SnapshotID: s.snapshotID, WaveID: s.waveID})
	}

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].FindingID < findings[j].FindingID
	})

	total := len(probes)
	healthyN := 0
	for _, p := range probes {
		if p.healthy {
			healthyN++
		}
	}
	avail := 0
	if total > 0 {
		avail = (healthyN * 100) / total
	}
	timeline := 0
	if firstStart != "" && lastFinish != "" {
		timeline = policy.DurationSec(firstStart, lastFinish)
	}
	risk := policy.RiskScore(findingKinds(findings))

	status := "RECOVERED"
	if rollbackDone {
		status = "ROLLED_BACK"
	} else if len(findings) > 0 {
		status = "FAILED"
	}

	return DrillOut{
		DrillID:                sc.DrillID,
		Status:                 status,
		DuplicateEventsSkipped: dupSkipped,
		Datacenters:            outDC,
		Services:               outSvc,
		Findings:               findings,
		Metrics: MetricsOut{
			RtoSec: maxRto, RpoSec: maxRpoUsed, AvailabilityPct: avail, RiskScore: risk, TimelineSec: timeline,
		},
	}
}

func findingKinds(findings []Finding) []string {
	out := make([]string, len(findings))
	for i, f := range findings {
		out[i] = f.Kind
	}
	return out
}

func cycleEntity(detail string) string {
	if detail == "" {
		return ""
	}
	for i := 0; i < len(detail); i++ {
		if detail[i] == '>' {
			return detail[:i]
		}
	}
	return detail
}
EOF
cat > /app/wavesync/drill/schedule.go <<'EOF'
package drill

import "sort"

func EventTieKey(ev Event) string {
	switch ev.Kind {
	case "REGISTER_DATACENTER":
		return ev.DatacenterID
	case "DECLARE_SNAPSHOT":
		return ev.SnapshotID
	case "LINK_DEPENDENCY":
		return ev.FromService
	case "START_WAVE":
		return ev.WaveID
	case "RESTORE_SERVICE":
		return ev.ServiceID
	case "PROBE_HEALTH":
		return ev.ProbeID
	case "EXECUTE_ROLLBACK":
		return ev.ServiceID
	case "CLOSE_DRILL":
		return ev.ClosedAt
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
	seen := make(map[string]struct{})
	out := make([]Event, 0, len(events))
	skipped := 0
	for _, ev := range events {
		if ev.EventID == "" {
			out = append(out, ev)
			continue
		}
		if _, dup := seen[ev.EventID]; dup {
			skipped++
			continue
		}
		seen[ev.EventID] = struct{}{}
		out = append(out, ev)
	}
	return out, skipped
}
EOF
cat > /app/slaedge/policy/policy.go <<'EOF'
package policy

import (
	"math"
	"time"
)

func ResolveDrill(
	rpoLimit, rtoLimit, maxAge, quorumPct, maxWave int,
	requireDep bool,
	riskCeiling, minReplicas int,
	overrides map[string]interface{},
) (int, int, int, int, int, bool, int, int) {
	if overrides != nil {
		if v, ok := overrides["rpo_limit_sec"]; ok {
			if n, ok := toInt(v); ok && n > 0 {
				rpoLimit = n
			}
		}
		if v, ok := overrides["rto_limit_sec"]; ok {
			if n, ok := toInt(v); ok && n > 0 {
				rtoLimit = n
			}
		}
		if v, ok := overrides["max_snapshot_age_sec"]; ok {
			if n, ok := toInt(v); ok && n > 0 {
				maxAge = n
			}
		}
		if v, ok := overrides["health_quorum_pct"]; ok {
			if n, ok := toInt(v); ok && n > 0 {
				quorumPct = n
			}
		}
		if v, ok := overrides["max_wave_capacity"]; ok {
			if n, ok := toInt(v); ok && n > 0 {
				maxWave = n
			}
		}
		if v, ok := overrides["require_dependency_order"]; ok {
			if b, ok := toBool(v); ok {
				requireDep = b
			}
		}
		if v, ok := overrides["risk_ceiling"]; ok {
			if n, ok := toInt(v); ok && n >= 0 {
				riskCeiling = n
			}
		}
		if v, ok := overrides["min_replicas"]; ok {
			if n, ok := toInt(v); ok && n >= 0 {
				minReplicas = n
			}
		}
	}
	return rpoLimit, rtoLimit, maxAge, quorumPct, maxWave, requireDep, riskCeiling, minReplicas
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

func ParseRFC3339(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func DurationSec(start, end string) int {
	a, okA := ParseRFC3339(start)
	b, okB := ParseRFC3339(end)
	if !okA || !okB {
		return 0
	}
	d := int(b.Sub(a).Seconds())
	if d < 0 {
		return 0
	}
	return d
}

func RPOExceeded(lagSec, limit int) bool {
	return lagSec > limit
}

func RTOExceeded(durSec, limit int) bool {
	return durSec > limit
}

func SnapshotStale(capturedAt, startedAt string, maxAgeSec int) bool {
	age := DurationSec(capturedAt, startedAt)
	return age > maxAgeSec
}

func ChecksumExact(declared, provided string) bool {
	return declared == provided
}

func QuorumRequired(total, pct int) int {
	if total <= 0 {
		return 0
	}
	return int(math.Ceil(float64(total) * float64(pct) / 100.0))
}

// EffectiveWaveCap is the tighter of global max_wave_capacity and per-wave max_concurrent when set.
func EffectiveWaveCap(globalCap, waveMaxConcurrent int) int {
	cap := globalCap
	if waveMaxConcurrent > 0 && (cap <= 0 || waveMaxConcurrent < cap) {
		cap = waveMaxConcurrent
	}
	if cap < 0 {
		cap = 0
	}
	return cap
}

var riskWeights = map[string]int{
	"SNAPSHOT_CORRUPT":       8,
	"RPO_BREACH":             7,
	"RTO_BREACH":             7,
	"DEPENDENCY_CYCLE":       9,
	"DEPENDENCY_BLOCKED":     6,
	"WAVE_CAPACITY_EXCEEDED": 5,
	"HEALTH_QUORUM_MISS":     8,
	"ROLLBACK_INCOMPLETE":    6,
	"UNKNOWN_SERVICE":        4,
	"DUPLICATE_DATACENTER":   3,
	"STALE_SNAPSHOT":         5,
	"REGION_PAIR_DENIED":     6,
	"PARALLEL_CONFLICT":      5,
	"ORPHAN_EDGE":            4,
	"CRITICAL_PROBE_FAIL":    9,
	"RISK_CEILING_HIT":       0,
	"INSUFFICIENT_REPLICAS":  5,
	"WAVE_ORDER_VIOLATION":   5,
	"SNAPSHOT_MISSING":       7,
	"FAILOVER_DENIED":        6,
}

func RiskScore(kinds []string) int {
	sum := 0
	for _, k := range kinds {
		if w, ok := riskWeights[k]; ok {
			sum += w
		}
	}
	return sum
}
EOF
cat > /app/depgraph/order/topo.go <<'EOF'
package order

import "sort"

type Graph map[string]map[string]struct{}

func NewGraph() Graph {
	return Graph{}
}

func (g Graph) AddEdge(from, to string) {
	if g[from] == nil {
		g[from] = make(map[string]struct{})
	}
	g[from][to] = struct{}{}
}

func UnmetProviders(g Graph, service string, restored map[string]bool) string {
	providers := make([]string, 0)
	for p := range g[service] {
		providers = append(providers, p)
	}
	sort.Strings(providers)
	for _, p := range providers {
		if !restored[p] {
			return p
		}
	}
	return ""
}

func DirectDependents(g Graph, target string) []string {
	out := make([]string, 0)
	for dep, providers := range g {
		if _, ok := providers[target]; ok {
			out = append(out, dep)
		}
	}
	sort.Strings(out)
	return out
}

func DetectCycle(g Graph) string {
	nodes := make([]string, 0, len(g))
	seen := map[string]struct{}{}
	for n, providers := range g {
		if _, ok := seen[n]; !ok {
			seen[n] = struct{}{}
			nodes = append(nodes, n)
		}
		for p := range providers {
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				nodes = append(nodes, p)
			}
		}
	}
	sort.Strings(nodes)

	visited := map[string]struct{}{}
	stack := map[string]struct{}{}
	var path []string
	var found []string

	var dfs func(cur string) bool
	dfs = func(cur string) bool {
		if _, on := stack[cur]; on {
			idx := 0
			for i, n := range path {
				if n == cur {
					idx = i
					break
				}
			}
			cyc := append([]string{}, path[idx:]...)
			cyc = append(cyc, cur)
			detail := rotateCycle(cyc)
			if found == nil || detail < joinCycle(found) {
				found = cyc
			}
			return true
		}
		if _, done := visited[cur]; done {
			return false
		}
		visited[cur] = struct{}{}
		stack[cur] = struct{}{}
		path = append(path, cur)
		providers := make([]string, 0, len(g[cur]))
		for p := range g[cur] {
			providers = append(providers, p)
		}
		sort.Strings(providers)
		hit := false
		for _, p := range providers {
			if dfs(p) {
				hit = true
			}
		}
		path = path[:len(path)-1]
		delete(stack, cur)
		return hit
	}

	for _, n := range nodes {
		dfs(n)
	}
	if found == nil {
		return ""
	}
	return joinCycle(found)
}

func rotateCycle(cyc []string) string {
	if len(cyc) < 2 {
		return joinCycle(cyc)
	}
	body := cyc[:len(cyc)-1]
	best := body
	bestStr := joinCycle(append(append([]string{}, body...), body[0]))
	for i := 1; i < len(body); i++ {
		rot := append(append([]string{}, body[i:]...), body[:i]...)
		s := joinCycle(append(append([]string{}, rot...), rot[0]))
		if s < bestStr {
			best = rot
			bestStr = s
		}
	}
	return joinCycle(append(append([]string{}, best...), best[0]))
}

func joinCycle(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for i := 1; i < len(parts); i++ {
		out += ">" + parts[i]
	}
	return out
}
EOF
make clean || true
make build
make run
