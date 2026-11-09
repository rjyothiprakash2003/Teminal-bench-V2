package resolve

import "fmt"

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
			if n, ok := toInt(v); ok && n > 0 {
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
	case string:
		var n int
		if _, err := fmt.Sscanf(x, "%d", &n); err == nil {
			return n, true
		}
		return 0, false
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
	for _, kind := range kinds {
		w, ok := featureWeights[kind]
		if !ok {
			continue
		}
		if IsHardKind(kind) {
			hardSum += w * softDamp / 100
			hardCount++
			hasHard = true
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
	confidence = hardSum + softSum
	if hasDrift && hasStarve {
		confidence += 10
	}
	if hardCount >= 3 {
		confidence += 12
	}
	if hardCount > 0 && softCount > 0 && softDamp > 0 {
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
	if confidence >= outlier {
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
