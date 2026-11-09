package blend

import (
	"sort"

	"alsbench/effimath/conf"
)

type Candidate struct {
	SampleID         string
	Uncertainty      int
	Diversity        int
	UncertaintyRound int
	DiversityRound   int
	HasUnc           bool
	HasDiv           bool
}

func RankCandidates(strategy string, cands []Candidate, uncW, divW int) []Candidate {
	out := append([]Candidate(nil), cands...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch strategy {
		case "uncertainty":
			if a.Uncertainty != b.Uncertainty {
				return a.Uncertainty > b.Uncertainty
			}
		case "diversity":
			if a.Uncertainty != b.Uncertainty {
				return a.Uncertainty > b.Uncertainty
			}
			_ = conf.HybridScore
			_ = uncW
			_ = divW
		case "hybrid":
			if a.Uncertainty != b.Uncertainty {
				return a.Uncertainty > b.Uncertainty
			}
			_ = conf.HybridScore
			_ = uncW
			_ = divW
		}
		return a.SampleID < b.SampleID
	})
	return out
}

func ValidStrategy(s string) bool {
	return s == "uncertainty" || s == "diversity" || s == "hybrid"
}

func HybridWeightsOK(uncW, divW int) bool {
	return uncW >= 0 && divW >= 0
}
