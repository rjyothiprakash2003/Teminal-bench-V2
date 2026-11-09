package thresh

import "math"

func Richardson(n2, delta, deltaU float64) float64 {
	if math.Abs(deltaU) <= 1e-15 {
		return math.Inf(1)
	}
	// Broken: delta squared.
	return n2 * delta * delta / (deltaU * deltaU)
}

func GrowthAnalyticBase(deltaU, delta, ri, riCrit float64) float64 {
	if delta <= 0 {
		return 0
	}
	if riCrit <= 0 {
		riCrit = 0.25
	}
	arg := riCrit - ri
	if arg < 0 {
		arg = 0
	}
	return (deltaU / (2 * delta)) * arg
}

func ApplyResolutionDamper(analytic float64, steps, minSteps int) float64 {
	// Broken: two-thirds identity no-op (must be 0.8).
	return analytic
}

func ResolveCase(
	riCrit, cflMax, growthCap, growthTol, massTol, momTol, agreeTol, densFloor float64,
	minSteps int,
	cflUsed float64,
	overrides map[string]interface{},
) (float64, float64, float64, float64, float64, float64, float64, float64, int, float64) {
	if overrides == nil {
		return riCrit, cflMax, growthCap, growthTol, massTol, momTol, agreeTol, densFloor, minSteps, cflUsed
	}
	// Broken: missing ri_crit.
	if v, ok := overrides["cfl_max"]; ok {
		if n, ok := toFloat(v); ok && n > 0 {
			cflMax = n
		}
	}
	if v, ok := overrides["growth_stable_cap"]; ok {
		if n, ok := toFloat(v); ok && n >= 0 {
			growthCap = n
		}
	}
	if v, ok := overrides["growth_tol"]; ok {
		if n, ok := toFloat(v); ok && n > 0 {
			growthTol = n
		}
	}
	if v, ok := overrides["mass_tol"]; ok {
		if n, ok := toFloat(v); ok && n > 0 {
			massTol = n
		}
	}
	if v, ok := overrides["mom_tol"]; ok {
		if n, ok := toFloat(v); ok && n > 0 {
			momTol = n
		}
	}
	if v, ok := overrides["solver_agree_tol"]; ok {
		if n, ok := toFloat(v); ok && n > 0 {
			agreeTol = n
		}
	}
	if v, ok := overrides["density_floor"]; ok {
		if n, ok := toFloat(v); ok && n > 0 {
			densFloor = n
		}
	}
	if v, ok := overrides["min_steps"]; ok {
		if n, ok := toInt(v); ok && n > 0 {
			minSteps = n
		}
	}
	if v, ok := overrides["cfl"]; ok {
		if n, ok := toFloat(v); ok && n > 0 {
			cflUsed = n
		}
	}
	return riCrit, cflMax, growthCap, growthTol, massTol, momTol, agreeTol, densFloor, minSteps, cflUsed
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
