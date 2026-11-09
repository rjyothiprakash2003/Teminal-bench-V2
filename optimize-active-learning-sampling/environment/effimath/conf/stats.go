package conf

func ResolveSuite(
	batchSize int,
	labelBudget int,
	maxScoreAge int,
	uncWeight int,
	divWeight int,
	targetAcc int,
	stallDelta int,
	stallRounds int,
	minConfN int,
	costLabel int,
	costScore int,
	confZ2 int,
	maxCost int,
	overrides map[string]interface{},
) (int, int, int, int, int, int, int, int, int, int, int, int, int) {
	if overrides == nil {
		return batchSize, labelBudget, maxScoreAge, uncWeight, divWeight, targetAcc, stallDelta, stallRounds, minConfN, costLabel, costScore, confZ2, maxCost
	}
	if v, ok := overrides["batch_size"]; ok {
		if n, ok := toInt(v); ok && n > 0 {
			batchSize = n
		}
	}
	if v, ok := overrides["label_budget"]; ok {
		if n, ok := toInt(v); ok && n >= 0 {
			labelBudget = n
		}
	}
	if v, ok := overrides["target_accuracy_bps"]; ok {
		if n, ok := toInt(v); ok && n >= 0 {
			targetAcc = n
		}
	}
	if v, ok := overrides["stall_delta_bps"]; ok {
		if n, ok := toInt(v); ok && n >= 0 {
			stallDelta = n
		}
	}
	if v, ok := overrides["stall_rounds"]; ok {
		if n, ok := toInt(v); ok && n > 0 {
			stallRounds = n
		}
	}
	if v, ok := overrides["min_confidence_n"]; ok {
		if n, ok := toInt(v); ok && n >= 0 {
			minConfN = n
		}
	}
	if v, ok := overrides["cost_per_label_milli"]; ok {
		if n, ok := toInt(v); ok && n >= 0 {
			costLabel = n
		}
	}
	if v, ok := overrides["cost_per_score_milli"]; ok {
		if n, ok := toInt(v); ok && n >= 0 {
			costScore = n
		}
	}
	if v, ok := overrides["confidence_z2"]; ok {
		if n, ok := toInt(v); ok && n >= 0 {
			confZ2 = n
		}
	}
	if v, ok := overrides["max_compute_cost_milli"]; ok {
		if n, ok := toInt(v); ok && n >= 0 {
			maxCost = n
		}
	}
	return batchSize, labelBudget, maxScoreAge, uncWeight, divWeight, targetAcc, stallDelta, stallRounds, minConfN, costLabel, costScore, confZ2, maxCost
}

func ToInt(v interface{}) (int, bool) {
	return toInt(v)
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

func AnnotationEfficiencyBPS(finalAcc, seedAcc, labelsUsed int) int {
	if labelsUsed <= 0 {
		return 0
	}
	return (finalAcc - seedAcc) / labelsUsed
}

func ConfidenceLoBPS(finalAcc, labelsUsed, z2 int) int {
	if labelsUsed <= 0 {
		return 0
	}
	return finalAcc
}

func ComputeCostMilli(labelsUsed, scoreCalls, costLabel, costScore int) int {
	return labelsUsed*costLabel + scoreCalls*costScore
}

func ScoreIsStale(currentRound, scoreRound, maxAge int) bool {
	return currentRound-scoreRound >= maxAge
}

func HybridScore(unc, div, uncW, divW int) int {
	return (uncW*unc + divW*div) / 100
}
