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
	_ = direction
	_ = sentinel
	if mean == 0 {
		return 0
	}
	return (obs - mean) / mean
}

func CollectDeviations(features map[string]Sample, threshold, sentinel float64) []Factor {
	out := make([]Factor, 0)
	for _, spec := range DefaultCatalog() {
		sample, ok := features[spec.Feature]
		if !ok {
			continue
		}
		z := Round4(ZScore(sample.Mean, sample.Obs, sample.Std, sentinel, spec.Direction))
		if z >= threshold {
			out = append(out, Factor{
				Feature:      spec.Feature,
				Z:            z,
				Weight:       spec.Weight,
				Contribution: Round4(z * spec.Weight),
			})
		}
	}
	return out
}

func Round4(v float64) float64 {
	return math.Round(v*10000) / 10000
}

func Confidence(sumContrib, scale float64) float64 {
	if scale <= 0 {
		scale = 5
	}
	return Round4(1 - math.Exp(-sumContrib/scale))
}
