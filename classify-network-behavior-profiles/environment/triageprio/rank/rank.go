package rank

import (
	"encoding/json"
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

func AnalyzeWindow(w Window) WindowOut {
	zThreshold := 2.5
	confFloor := 0.4
	contribScale := 2.5
	minCluster := 2
	if w.ZThreshold != nil {
		zThreshold = *w.ZThreshold
	}
	if w.ConfidenceFloor != nil {
		confFloor = *w.ConfidenceFloor
	}
	if w.ContribScale != nil {
		contribScale = *w.ContribScale
	}
	if w.MinClusterSize != nil {
		minCluster = *w.MinClusterSize
	}
	if w.PolicyOverrides != nil {
		if v, ok := w.PolicyOverrides["min_cluster_size"]; ok {
			if n, ok := toInt(v); ok && n >= 1 {
				minCluster = n
			}
		}
		if v, ok := w.PolicyOverrides["confidence_floor"]; ok {
			if f, ok := toFloat(v); ok {
				confFloor = f
			}
		}
	}

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
	_ = links
	peerCluster := mesh.BuildPeerCluster(hostIDs, hostPeers)

	type scored struct {
		host    HostIn
		factors []FactorOut
		conf    float64
		verdict string
		maxZ    float64
	}
	scoredHosts := make([]scored, 0, len(w.Hosts))
	alertIDs := make([]string, 0)
	for _, h := range w.Hosts {
		factors := zscore.CollectDeviations(h.Features, zThreshold, 1000)
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
			conf = zscore.Confidence(sum, contribScale)
			if conf < confFloor {
				verdict = "WATCH"
			} else {
				verdict = "ALERT"
			}
		}
		scoredHosts = append(scoredHosts, scored{host: h, factors: factors, conf: conf, verdict: verdict, maxZ: maxZ})
		if verdict == "ALERT" {
			alertIDs = append(alertIDs, h.HostID)
		}
	}
	sort.Strings(alertIDs)
	clusters, membership := mesh.BuildClusters(alertIDs, peerCluster, minCluster)

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
		size := 1
		if inCluster {
			for _, c := range clusters {
				if c.ClusterID == cid {
					size = c.Size
					break
				}
			}
		}
		boost := mesh.ClusterBoost(size, inCluster)
		priority := zscore.Round4(s.conf * boost * RoleMult(s.host.Role))
		factors := append([]FactorOut(nil), s.factors...)
		sort.Slice(factors, func(i, j int) bool {
			if factors[i].Contribution != factors[j].Contribution {
				return factors[i].Contribution > factors[j].Contribution
			}
			return factors[i].Feature < factors[j].Feature
		})
		risk := "LOW"
		if s.conf >= 0.8 {
			risk = "HIGH"
		} else if s.conf >= confFloor {
			risk = "MEDIUM"
		}
		investigations = append(investigations, Investigation{
			InvestigationID: w.WindowID + "::" + s.host.HostID,
			HostID:          s.host.HostID,
			ClusterID:       cid,
			Confidence:      s.conf,
			Priority:        priority,
			Risk:            risk,
			Factors:         factors,
		})
	}
	sort.Slice(hostsOut, func(i, j int) bool { return hostsOut[i].HostID < hostsOut[j].HostID })
	sort.Slice(investigations, func(i, j int) bool {
		if investigations[i].Priority != investigations[j].Priority {
			return investigations[i].Priority > investigations[j].Priority
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
