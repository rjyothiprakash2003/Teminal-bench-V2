package drift

import "math"

func Mass(rho []float64, dx float64) float64 {
	s := 0.0
	for _, r := range rho {
		s += r
	}
	return s * dx
}

func Momentum(rho, base []float64, dx float64) float64 {
	s := 0.0
	for i := range rho {
		s += rho[i] * base[i]
	}
	return s * dx
}

func RelativeDrift(initial, final float64) float64 {
	den := math.Abs(initial)
	if den < 1 {
		den = 1
	}
	return math.Abs(final-initial) / den
}

func GrowthRate(rms0, rms1, tSpan float64) float64 {
	if rms0 <= 0 || tSpan <= 0 {
		return 0
	}
	return math.Log(rms1/rms0) / tSpan
}

func SchemeDissipation(scheme string) float64 {
	switch scheme {
	case "lax_friedrichs":
		return 0.04
	case "upwind":
		return 0.05
	default:
		return 0
	}
}

func SchemeRefCFL(scheme string) float64 {
	switch scheme {
	case "lax_friedrichs":
		return 0.4
	case "upwind":
		return 0.5
	default:
		return 0.4
	}
}

// EffectiveDissipation: scale is ref/cfl_used (inverted); LF squared; upwind cubed.
func EffectiveDissipation(scheme string, cflUsed float64) float64 {
	base := SchemeDissipation(scheme)
	ref := SchemeRefCFL(scheme)
	if ref <= 0 || cflUsed <= 0 {
		return 0
	}
	scale := ref / cflUsed
	switch scheme {
	case "lax_friedrichs":
		return base * scale * scale
	case "upwind":
		return base * scale * scale * scale
	default:
		return 0
	}
}
