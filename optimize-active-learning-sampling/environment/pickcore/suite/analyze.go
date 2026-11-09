package suite

import (
	"encoding/json"
	"os"
	"sort"
	"strconv"

	"alsbench/effimath/conf"
	"alsbench/stratops/blend"
)

type Event struct {
	Seq         int      `json:"seq"`
	EventID     string   `json:"event_id"`
	Kind        string   `json:"kind"`
	SampleID    string   `json:"sample_id"`
	Uncertainty int      `json:"uncertainty"`
	Diversity   int      `json:"diversity"`
	Strategy    string   `json:"strategy"`
	RoundID     string   `json:"round_id"`
	Round       int      `json:"round"`
	BatchSize   int      `json:"batch_size"`
	AccuracyBPS int      `json:"accuracy_bps"`
	SuiteID     string   `json:"suite_id"`
	Picks       []string `json:"picks"`
}

type Suite struct {
	SuiteID             string                 `json:"suite_id"`
	BatchSize           *int                   `json:"batch_size"`
	LabelBudget         *int                   `json:"label_budget"`
	MaxScoreAgeRounds   *int                   `json:"max_score_age_rounds"`
	UncertaintyWeight   *int                   `json:"uncertainty_weight"`
	DiversityWeight     *int                   `json:"diversity_weight"`
	TargetAccuracyBPS   *int                   `json:"target_accuracy_bps"`
	StallDeltaBPS       *int                   `json:"stall_delta_bps"`
	StallRounds         *int                   `json:"stall_rounds"`
	MinConfidenceN      *int                   `json:"min_confidence_n"`
	CostPerLabelMilli   *int                   `json:"cost_per_label_milli"`
	CostPerScoreMilli   *int                   `json:"cost_per_score_milli"`
	ConfidenceZ2        *int                   `json:"confidence_z2"`
	MaxComputeCostMilli   *int                   `json:"max_compute_cost_milli"`
	MaxChannelSkewRounds  *int                   `json:"max_channel_skew_rounds"`
	SeedAccuracyBPS       int                    `json:"seed_accuracy_bps"`
	PolicyOverrides       map[string]interface{} `json:"policy_overrides"`
	Events                []Event                `json:"events"`
}

type SampleOut struct {
	SampleID    string `json:"sample_id"`
	Labeled     bool   `json:"labeled"`
	Uncertainty int    `json:"uncertainty"`
	Diversity   int    `json:"diversity"`
	ScoreRound  int    `json:"score_round"`
}

type Finding struct {
	FindingID string `json:"finding_id"`
	EntityID  string `json:"entity_id"`
	Kind      string `json:"kind"`
	EventSeq  int    `json:"event_seq"`
	Detail    string `json:"detail"`
}

type SuiteOut struct {
	SuiteID                 string      `json:"suite_id"`
	Status                  string      `json:"status"`
	DuplicateEventsSkipped  int         `json:"duplicate_events_skipped"`
	Strategy                string      `json:"strategy"`
	LabelsUsed              int         `json:"labels_used"`
	AnnotationEfficiencyBPS int         `json:"annotation_efficiency_bps"`
	ConvergenceRound        int         `json:"convergence_round"`
	FinalAccuracyBPS        int         `json:"final_accuracy_bps"`
	ComputeCostMilli        int         `json:"compute_cost_milli"`
	ConfidenceLoBPS         int         `json:"confidence_lo_bps"`
	Samples                 []SampleOut `json:"samples"`
	Findings                []Finding   `json:"findings"`
}

type Report struct {
	Suites []SuiteOut `json:"suites"`
}

type sampleState struct {
	labeled          bool
	uncertainty      int
	diversity        int
	uncertaintyRound int
	diversityRound   int
	hasUnc           bool
	hasDiv           bool
}

func LoadSuite(path string) (Suite, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Suite{}, err
	}
	var sc Suite
	if err := json.Unmarshal(data, &sc); err != nil {
		return Suite{}, err
	}
	return sc, nil
}

func findingID(suiteID, entityID string, seq int) string {
	return suiteID + "::" + entityID + "::" + formatSeq(seq)
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

func appendFinding(findings *[]Finding, suiteID, entityID, kind, detail string, seq int) {
	*findings = append(*findings, Finding{
		FindingID: findingID(suiteID, entityID, seq),
		EntityID:  entityID,
		Kind:      kind,
		EventSeq:  seq,
		Detail:    detail,
	})
}

func ptrOr(p *int, def int) int {
	if p != nil {
		return *p
	}
	return def
}

func Analyze(sc Suite) SuiteOut {
	batchSize := ptrOr(sc.BatchSize, 2)
	labelBudget := ptrOr(sc.LabelBudget, 10)
	maxScoreAge := ptrOr(sc.MaxScoreAgeRounds, 1)
	uncW := ptrOr(sc.UncertaintyWeight, 60)
	divW := ptrOr(sc.DiversityWeight, 40)
	targetAcc := ptrOr(sc.TargetAccuracyBPS, 8000)
	stallDelta := ptrOr(sc.StallDeltaBPS, 50)
	stallRounds := ptrOr(sc.StallRounds, 2)
	minConfN := ptrOr(sc.MinConfidenceN, 3)
	costLabel := ptrOr(sc.CostPerLabelMilli, 100)
	costScore := ptrOr(sc.CostPerScoreMilli, 5)
	confZ2 := ptrOr(sc.ConfidenceZ2, 4)
	maxCost := ptrOr(sc.MaxComputeCostMilli, 100000)
	maxSkew := ptrOr(sc.MaxChannelSkewRounds, 2)

	if sc.PolicyOverrides != nil {
		batchSize, labelBudget, maxScoreAge, uncW, divW, targetAcc, stallDelta, stallRounds, minConfN, costLabel, costScore, confZ2, maxCost = conf.ResolveSuite(
			2, 10, 1, 60, 40, 8000, 50, 2, 3, 100, 5, 4, 100000, sc.PolicyOverrides,
		)
	}
	_ = maxSkew

	samples := make(map[string]*sampleState)
	findings := make([]Finding, 0)
	dupSkipped := 0
	maxSeq := 0
	strategy := ""
	labelsUsed := 0
	scoreCalls := 0
	seedAcc := sc.SeedAccuracyBPS
	finalAcc := seedAcc
	convergenceRound := 0
	currentRound := 0
	previousPickRound := 0
	havePickRound := false
	probeAccs := make([]int, 0)
	probeRoundIDs := make([]string, 0)
	orphanKinds := make(map[string]string)

	events := SortEvents(sc.Events)
	_ = FilterDuplicateEvents
	_ = previousPickRound
	_ = havePickRound
	_ = probeRoundIDs

	for _, ev := range events {
		seq := ev.Seq
		if seq > maxSeq {
			maxSeq = seq
		}
		switch ev.Kind {
		case "REGISTER_SAMPLE":
			if _, exists := samples[ev.SampleID]; exists {
				appendFinding(&findings, sc.SuiteID, ev.SampleID, "DUPLICATE_SAMPLE", "", seq)
				continue
			}
			samples[ev.SampleID] = &sampleState{}
		case "SEED_LABEL":
			if st, ok := samples[ev.SampleID]; ok {
				if !st.labeled {
					st.labeled = true
					labelsUsed++
				}
			}
		case "SCORE_UNCERTAINTY":
			scoreCalls++
			st, ok := samples[ev.SampleID]
			if !ok {
				orphanKinds[ev.SampleID] = "SCORE_UNCERTAINTY"
				continue
			}
			if !st.hasUnc {
				st.uncertainty = ev.Uncertainty
				st.hasUnc = true
				st.uncertaintyRound = ev.Round
			}
		case "SCORE_DIVERSITY":
			scoreCalls++
			st, ok := samples[ev.SampleID]
			if !ok {
				orphanKinds[ev.SampleID] = "SCORE_DIVERSITY"
				continue
			}
			if !st.hasDiv {
				st.diversity = ev.Diversity
				st.hasDiv = true
				st.diversityRound = ev.Round
			}
		case "SET_STRATEGY":
			if !blend.ValidStrategy(ev.Strategy) {
				appendFinding(&findings, sc.SuiteID, ev.Strategy, "UNKNOWN_STRATEGY", "", seq)
				continue
			}
			if strategy != "" && strategy != ev.Strategy {
				appendFinding(&findings, sc.SuiteID, ev.Strategy, "STRATEGY_SWITCH", strategy, seq)
			}
			strategy = ev.Strategy
		case "PICK_BATCH":
			currentRound = ev.Round
			previousPickRound = currentRound
			havePickRound = true
			req := batchSize
			if ev.BatchSize > 0 {
				req = ev.BatchSize
			}
			remaining := labelBudget - labelsUsed
			if strategy == "" || !blend.ValidStrategy(strategy) {
				entity := strategy
				if entity == "" {
					entity = "unset"
				}
				appendFinding(&findings, sc.SuiteID, entity, "UNKNOWN_STRATEGY", "", seq)
				continue
			}
			if strategy == "hybrid" && !blend.HybridWeightsOK(uncW, divW) {
				appendFinding(&findings, sc.SuiteID, "hybrid", "HYBRID_WEIGHT_INVALID", strconv.Itoa(uncW)+":"+strconv.Itoa(divW), seq)
				continue
			}
			if req > remaining {
				appendFinding(&findings, sc.SuiteID, ev.RoundID, "BUDGET_OVERRUN", strconv.Itoa(remaining), seq)
				continue
			}
			if len(ev.Picks) > 0 {
				seenPick := make(map[string]struct{})
				failed := false
				for _, id := range ev.Picks {
					if _, dup := seenPick[id]; dup {
						appendFinding(&findings, sc.SuiteID, id, "DUPLICATE_PICK", "", seq)
						failed = true
						break
					}
					seenPick[id] = struct{}{}
					st, ok := samples[id]
					if !ok || !st.hasUnc || !st.hasDiv {
						appendFinding(&findings, sc.SuiteID, id, "SCORE_MISSING", "", seq)
						failed = true
						break
					}
					if conf.ScoreIsStale(currentRound, st.uncertaintyRound, maxScoreAge) {
						appendFinding(&findings, sc.SuiteID, id, "STALE_SCORE", "uncertainty:"+strconv.Itoa(st.uncertaintyRound), seq)
						failed = true
						break
					}
					if conf.ScoreIsStale(currentRound, st.diversityRound, maxScoreAge) {
						appendFinding(&findings, sc.SuiteID, id, "STALE_SCORE", "diversity:"+strconv.Itoa(st.diversityRound), seq)
						failed = true
						break
					}
					if st.labeled {
						appendFinding(&findings, sc.SuiteID, id, "LABEL_LEAK", "", seq)
						failed = true
						break
					}
				}
				if failed {
					continue
				}
				if len(ev.Picks) < req {
					appendFinding(&findings, sc.SuiteID, ev.RoundID, "BATCH_UNDERFILL", strconv.Itoa(len(ev.Picks)), seq)
					continue
				}
				for _, id := range ev.Picks {
					samples[id].labeled = true
					labelsUsed++
				}
				continue
			}
			cands := make([]blend.Candidate, 0)
			for id, st := range samples {
				if st.labeled {
					continue
				}
				cands = append(cands, blend.Candidate{
					SampleID:         id,
					Uncertainty:      st.uncertainty,
					Diversity:        st.diversity,
					UncertaintyRound: st.uncertaintyRound,
					DiversityRound:   st.diversityRound,
					HasUnc:           st.hasUnc,
					HasDiv:           st.hasDiv,
				})
			}
			if len(cands) == 0 {
				appendFinding(&findings, sc.SuiteID, ev.RoundID, "POOL_EXHAUSTED", "", seq)
				continue
			}
			sort.Slice(cands, func(i, j int) bool {
				return cands[i].SampleID < cands[j].SampleID
			})
			missing := false
			for _, c := range cands {
				if !c.HasUnc || !c.HasDiv {
					appendFinding(&findings, sc.SuiteID, c.SampleID, "SCORE_MISSING", "", seq)
					missing = true
					break
				}
			}
			if missing {
				continue
			}
			ranked := blend.RankCandidates(strategy, cands, uncW, divW)
			selected := make([]string, 0, req)
			for _, c := range ranked {
				if len(selected) >= req {
					break
				}
				if conf.ScoreIsStale(currentRound, c.UncertaintyRound, maxScoreAge) {
					appendFinding(&findings, sc.SuiteID, c.SampleID, "STALE_SCORE", "uncertainty:"+strconv.Itoa(c.UncertaintyRound), seq)
					selected = nil
					break
				}
				if conf.ScoreIsStale(currentRound, c.DiversityRound, maxScoreAge) {
					appendFinding(&findings, sc.SuiteID, c.SampleID, "STALE_SCORE", "diversity:"+strconv.Itoa(c.DiversityRound), seq)
					selected = nil
					break
				}
				selected = append(selected, c.SampleID)
			}
			if selected == nil {
				continue
			}
			if len(selected) < req {
				appendFinding(&findings, sc.SuiteID, ev.RoundID, "BATCH_UNDERFILL", strconv.Itoa(len(selected)), seq)
				continue
			}
			for _, id := range selected {
				samples[id].labeled = true
				labelsUsed++
			}
		case "APPLY_LABEL":
			if st, ok := samples[ev.SampleID]; ok {
				if st.labeled {
					appendFinding(&findings, sc.SuiteID, ev.SampleID, "LABEL_LEAK", "", seq)
					continue
				}
				st.labeled = true
				labelsUsed++
			}
		case "RECORD_PROBE":
			finalAcc = ev.AccuracyBPS
			probeAccs = append(probeAccs, ev.AccuracyBPS)
			probeRoundIDs = append(probeRoundIDs, ev.RoundID)
			if convergenceRound == 0 && ev.AccuracyBPS > targetAcc {
				if n, err := strconv.Atoi(ev.RoundID); err == nil {
					convergenceRound = n
				} else {
					convergenceRound = ev.Round
				}
			}
		case "CLOSE_SUITE":
		}
	}

	auditSeq := maxSeq + 1
	_ = orphanKinds

	cost := conf.ComputeCostMilli(labelsUsed, scoreCalls, costLabel, costScore)
	eff := conf.AnnotationEfficiencyBPS(finalAcc, seedAcc, labelsUsed)
	confLo := conf.ConfidenceLoBPS(finalAcc, labelsUsed, confZ2)

	if cost >= maxCost {
		appendFinding(&findings, sc.SuiteID, sc.SuiteID, "COST_OVERFLOW", strconv.Itoa(cost), auditSeq)
	}
	if labelsUsed < minConfN {
		appendFinding(&findings, sc.SuiteID, sc.SuiteID, "CONFIDENCE_UNDERFLOW", strconv.Itoa(labelsUsed), auditSeq)
	}
	if len(probeAccs) >= stallRounds+1 {
		stalled := true
		lastDelta := 0
		for i := len(probeAccs) - stallRounds; i < len(probeAccs); i++ {
			delta := probeAccs[i] - probeAccs[i-1]
			lastDelta = delta
			if delta >= stallDelta {
				stalled = false
				break
			}
		}
		if stalled {
			appendFinding(&findings, sc.SuiteID, strconv.Itoa(len(probeAccs)), "CONVERGENCE_STALL", strconv.Itoa(lastDelta), auditSeq)
		}
	}

	outSamples := make([]SampleOut, 0, len(samples))
	ids := make([]string, 0, len(samples))
	for id := range samples {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		st := samples[id]
		scoreRound := 0
		if st.hasUnc && st.hasDiv {
			scoreRound = st.uncertaintyRound
			if st.diversityRound > scoreRound {
				scoreRound = st.diversityRound
			}
		}
		outSamples = append(outSamples, SampleOut{
			SampleID:    id,
			Labeled:     st.labeled,
			Uncertainty: st.uncertainty,
			Diversity:   st.diversity,
			ScoreRound:  scoreRound,
		})
	}

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].FindingID < findings[j].FindingID
	})

	status := "ACCEPTED"
	if len(findings) > 0 {
		status = "REJECTED"
	}

	return SuiteOut{
		SuiteID:                 sc.SuiteID,
		Status:                  status,
		DuplicateEventsSkipped:  dupSkipped,
		Strategy:                strategy,
		LabelsUsed:              labelsUsed,
		AnnotationEfficiencyBPS: eff,
		ConvergenceRound:        convergenceRound,
		FinalAccuracyBPS:        finalAcc,
		ComputeCostMilli:        cost,
		ConfidenceLoBPS:         confLo,
		Samples:                 outSamples,
		Findings:                findings,
	}
}
