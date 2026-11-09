package flux

import "math"

func ValidScheme(name string) bool {
	return name == "lax_friedrichs" || name == "upwind"
}

func Advect(q, vel []float64, dx, dt float64, scheme string) []float64 {
	n := len(q)
	out := make([]float64, n)
	if n == 0 {
		return out
	}
	fluxes := make([]float64, n)
	for i := 0; i < n; i++ {
		j := (i + 1) % n
		switch scheme {
		case "upwind":
			uFace := 0.5 * (vel[i] + vel[j])
			if uFace >= 0 {
				fluxes[i] = uFace * q[i]
			} else {
				fluxes[i] = uFace * q[j]
			}
		default:
			uL, uR := vel[i], vel[j]
			fL, fR := uL*q[i], uR*q[j]
			alpha := math.Abs(uL)
			if a := math.Abs(uR); a > alpha {
				alpha = a
			}
			fluxes[i] = 0.5*(fL+fR) - 0.5*alpha*(q[j]-q[i])
		}
	}
	for i := 0; i < n; i++ {
		im := (i - 1 + n) % n
		out[i] = q[i] - dt/dx*(fluxes[i]-fluxes[im])
	}
	return out
}
