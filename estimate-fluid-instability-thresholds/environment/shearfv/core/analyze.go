package core

import (
	"encoding/json"
	"math"
	"os"
	"sort"
	"strconv"

	"flowinstab/growscan/thresh"
	"flowinstab/massguard/drift"
	"flowinstab/shearfv/flux"
)

type Case struct {
	CaseID          string                 `json:"case_id"`
	Nx              int                    `json:"nx"`
	Lx              float64                `json:"lx"`
	DeltaU          float64                `json:"delta_u"`
	N2              float64                `json:"n2"`
	Delta           float64                `json:"delta"`
	Amplitude       float64                `json:"amplitude"`
	TEnd            float64                `json:"t_end"`
	CFL             float64                `json:"cfl"`
	SchemePrimary   string                 `json:"scheme_primary"`
	SchemeSecondary string                 `json:"scheme_secondary"`
	RiCrit          float64                `json:"ri_crit"`
	CFLMax          float64                `json:"cfl_max"`
	GrowthStableCap float64                `json:"growth_stable_cap"`
	GrowthTol       float64                `json:"growth_tol"`
	MassTol         float64                `json:"mass_tol"`
	MomTol          float64                `json:"mom_tol"`
	SolverAgreeTol  float64                `json:"solver_agree_tol"`
	DensityFloor    float64                `json:"density_floor"`
	MinSteps        int                    `json:"min_steps"`
	PolicyOverrides map[string]interface{} `json:"policy_overrides"`
}

type Finding struct {
	FindingID string `json:"finding_id"`
	EntityID  string `json:"entity_id"`
	Kind      string `json:"kind"`
	Detail    string `json:"detail"`
}

type CaseOut struct {
	CaseID          string    `json:"case_id"`
	Status          string    `json:"status"`
	Richardson      float64   `json:"richardson"`
	RiCrit          float64   `json:"ri_crit"`
	GrowthPrimary   float64   `json:"growth_primary"`
	GrowthSecondary float64   `json:"growth_secondary"`
	GrowthAnalytic  float64   `json:"growth_analytic"`
	GrowthL2Err     float64   `json:"growth_l2_err"`
	MassDrift       float64   `json:"mass_drift"`
	MomDrift        float64   `json:"mom_drift"`
	StepsTaken      int       `json:"steps_taken"`
	CFLUsed         float64   `json:"cfl_used"`
	PreferredScheme string    `json:"preferred_scheme"`
	Findings        []Finding `json:"findings"`
}

type Report struct {
	Cases []CaseOut `json:"cases"`
}

type rawFinding struct {
	EntityID string
	Kind     string
	Detail   string
}

func LoadCase(path string) (Case, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Case{}, err
	}
	var sc Case
	if err := json.Unmarshal(data, &sc); err != nil {
		return Case{}, err
	}
	return sc, nil
}

func Analyze(sc Case) CaseOut {
	riCrit := sc.RiCrit
	if riCrit == 0 {
		riCrit = 0.25
	}
	cflMax := sc.CFLMax
	if cflMax == 0 {
		cflMax = 0.9
	}
	growthCap := sc.GrowthStableCap
	if growthCap == 0 {
		growthCap = 0.001
	}
	growthTol := sc.GrowthTol
	if growthTol == 0 {
		growthTol = 0.2
	}
	massTol := sc.MassTol
	if massTol == 0 {
		massTol = 1e-9
	}
	momTol := sc.MomTol
	if momTol == 0 {
		momTol = 1.0
	}
	agreeTol := sc.SolverAgreeTol
	if agreeTol == 0 {
		agreeTol = 0.05
	}
	densFloor := sc.DensityFloor
	if densFloor == 0 {
		densFloor = 1e-12
	}
	minSteps := sc.MinSteps
	if minSteps == 0 {
		minSteps = 8
	}
	cflUsed := sc.CFL
	if cflUsed == 0 {
		cflUsed = 0.4
	}

	riCrit, cflMax, growthCap, growthTol, massTol, momTol, agreeTol, densFloor, minSteps, cflUsed =
		thresh.ResolveCase(riCrit, cflMax, growthCap, growthTol, massTol, momTol, agreeTol, densFloor, minSteps, cflUsed, sc.PolicyOverrides)

	raw := make([]rawFinding, 0)
	ri := thresh.Richardson(sc.N2, sc.Delta, sc.DeltaU)

	nx := sc.Nx
	if nx < 2 {
		nx = 2
	}
	lx := sc.Lx
	if lx <= 0 {
		lx = 1
	}
	dx := lx / float64(nx)
	speed := geometricBaseSpeed(sc, nx, dx) // Broken: must be arithmetic.
	dt := cflUsed * dx / speed
	steps := int(math.Floor(sc.TEnd/dt + 1e-12)) // Broken: must be round.
	if steps < 1 {
		steps = 1
	}

	analytic := thresh.GrowthAnalyticBase(sc.DeltaU, sc.Delta, ri, riCrit) // Broken: no 0.8 damper

	appendRaw := func(entity, kind, detail string) {
		raw = append(raw, rawFinding{EntityID: entity, Kind: kind, Detail: detail})
	}

	rejected := false
	if cflUsed >= cflMax { // Broken: inclusive; must be strict >.
		appendRaw(sc.CaseID, "CFL_BREACH", formatFloat(cflUsed))
		rejected = true
	}
	if !flux.ValidScheme(sc.SchemePrimary) {
		appendRaw(sc.SchemePrimary, "SCHEME_UNKNOWN", "primary")
		rejected = true
	}
	if !flux.ValidScheme(sc.SchemeSecondary) {
		appendRaw(sc.SchemeSecondary, "SCHEME_UNKNOWN", "secondary")
		rejected = true
	}

	var growthP, growthS, massDrift, momDrift float64
	preferred := ""
	growthPref := 0.0

	if !rejected {
		gp, md, momd, floorHit := march(sc, nx, dx, dt, steps, analytic, densFloor, cflUsed, sc.SchemePrimary)
		growthP = gp
		massDrift = md
		momDrift = momd
		if floorHit {
			appendRaw(sc.CaseID, "DENSITY_FLOOR", formatFloat(densFloor))
			rejected = true
			preferred = ""
		} else {
			gs, _, _, floor2 := march(sc, nx, dx, dt, steps, analytic, densFloor, cflUsed, sc.SchemeSecondary)
			growthS = gs
			if floor2 {
				appendRaw(sc.CaseID, "DENSITY_FLOOR", formatFloat(densFloor))
				rejected = true
				preferred = ""
			} else {
				errP := math.Abs(growthP - analytic)
				errS := math.Abs(growthS - analytic)
				// Broken: prefer lower error; ties pick lex larger.
				if errP < errS-1e-12 || (math.Abs(errP-errS) <= 1e-12 && sc.SchemePrimary > sc.SchemeSecondary) {
					preferred = sc.SchemePrimary
					growthPref = growthP
				} else {
					preferred = sc.SchemeSecondary
					growthPref = growthS
				}
			}
		}
	}

	// Broken: L-inf instead of RMS.
	growthErr := math.Abs(growthP - analytic)
	if a := math.Abs(growthS - analytic); a > growthErr {
		growthErr = a
	}
	prefAbs := math.Abs(growthPref - analytic)
	if rejected {
		growthP = 0
		growthS = 0
		preferred = ""
		growthPref = 0
		analytic = 0
		growthErr = 0
		prefAbs = 0
	}

	if !rejected {
		if steps < minSteps {
			appendRaw(sc.CaseID, "UNDER_RESOLVED", formatInt(steps))
		}
		missTol := growthTol * math.Max(1.0, math.Abs(analytic))
		if prefAbs >= missTol {
			appendRaw(sc.CaseID, "GROWTH_MISS", formatFloat(prefAbs))
		}
		if massDrift > massTol {
			appendRaw(sc.CaseID, "MASS_DRIFT", formatFloat(massDrift))
		}
		if momDrift > momTol {
			appendRaw(sc.CaseID, "MOM_DRIFT", formatFloat(momDrift))
		}
		splitTol := agreeTol * math.Max(1, math.Max(math.Abs(growthP), math.Abs(growthS)))
		if math.Abs(growthP-growthS) >= splitTol {
			appendRaw(preferred, "SOLVER_SPLIT", formatFloat(math.Abs(growthP-growthS)))
		}
	}

	findings := finalizeFindings(sc.CaseID, raw)

	status := "TRANSITIONAL"
	if rejected {
		status = "REJECTED"
	} else if ri > riCrit && growthP <= growthCap && growthS <= growthCap && len(findings) == 0 && preferred == sc.SchemePrimary {
		status = "STABLE"
	} else if ri < riCrit && growthP > growthCap && growthS > growthCap {
		status = "UNSTABLE"
	} else {
		status = "TRANSITIONAL"
	}

	if !rejected {
		if (status == "STABLE" && ri < riCrit) || (status == "UNSTABLE" && ri > riCrit) {
			raw = append(raw, rawFinding{EntityID: sc.CaseID, Kind: "RI_MISCLASS", Detail: status})
			findings = finalizeFindings(sc.CaseID, raw)
			if status == "STABLE" {
				status = "TRANSITIONAL"
			}
		}
	}

	return CaseOut{
		CaseID:          sc.CaseID,
		Status:          status,
		Richardson:      ri,
		RiCrit:          riCrit,
		GrowthPrimary:   growthP,
		GrowthSecondary: growthS,
		GrowthAnalytic:  analytic,
		GrowthL2Err:     growthErr,
		MassDrift:       massDrift,
		MomDrift:        momDrift,
		StepsTaken:      steps,
		CFLUsed:         cflUsed,
		PreferredScheme: preferred,
		Findings:        findings,
	}
}

func geometricBaseSpeed(sc Case, nx int, dx float64) float64 {
	maxAbs := 0.0
	sumSq := 0.0
	for i := 0; i < nx; i++ {
		x := (float64(i) + 0.5) * dx
		xi := 0.0
		if sc.Delta != 0 {
			xi = (x - sc.Lx/2) / sc.Delta
		}
		b := 0.5 * sc.DeltaU * math.Tanh(xi)
		a := math.Abs(b)
		if a > maxAbs {
			maxAbs = a
		}
		sumSq += b * b
	}
	rms := math.Sqrt(sumSq/float64(nx)) + 1e-12
	maxAbs = maxAbs + 1e-12
	return math.Sqrt(maxAbs*rms) + 1e-12
}

func finalizeFindings(caseID string, raw []rawFinding) []Finding {
	sort.Slice(raw, func(i, j int) bool {
		if raw[i].Kind != raw[j].Kind {
			return raw[i].Kind < raw[j].Kind
		}
		if raw[i].EntityID != raw[j].EntityID {
			return raw[i].EntityID < raw[j].EntityID
		}
		return raw[i].Detail < raw[j].Detail
	})
	out := make([]Finding, 0, len(raw))
	for i, rf := range raw {
		out = append(out, Finding{
			FindingID: caseID + "::" + rf.EntityID + "::" + pad4(i+1),
			EntityID:  rf.EntityID,
			Kind:      rf.Kind,
			Detail:    rf.Detail,
		})
	}
	return out
}

func march(sc Case, nx int, dx, dt float64, steps int, analytic, densFloor, cflUsed float64, scheme string) (growth, massDrift, momDrift float64, floorHit bool) {
	rho := make([]float64, nx)
	seed := make([]float64, nx)
	base := make([]float64, nx)
	for i := 0; i < nx; i++ {
		x := (float64(i) + 0.5) * dx
		xi := 0.0
		if sc.Delta != 0 {
			xi = (x - sc.Lx/2) / sc.Delta
		}
		base[i] = 0.5 * sc.DeltaU * math.Tanh(xi)
		seed[i] = sc.Amplitude * math.Sin(2*math.Pi*x/sc.Lx)
		rho[i] = 1.0 + 0.1*math.Tanh(xi)
	}
	mass0 := drift.Mass(rho, dx)
	mom0 := drift.Momentum(rho, base, dx)
	rms0 := rms(seed)
	dissip := drift.EffectiveDissipation(scheme, cflUsed)

	for step := 0; step < steps; step++ {
		vel := make([]float64, nx)
		copy(vel, base)
		rho = flux.Advect(rho, vel, dx, dt, scheme)
		for i := 0; i < nx; i++ {
			if rho[i] < densFloor {
				return 0, 0, 0, true
			}
		}
		factor := math.Exp((analytic - dissip) * dt)
		for i := 0; i < nx; i++ {
			seed[i] *= factor
		}
	}
	rms1 := rms(seed)
	growth = drift.GrowthRate(rms0, rms1, sc.TEnd) // Broken: must use steps*dt.
	mass1 := drift.Mass(rho, dx)
	mom1 := drift.Momentum(rho, base, dx)
	massDrift = drift.RelativeDrift(mass0, mass1)
	momDrift = drift.RelativeDrift(mom0, mom1)
	return growth, massDrift, momDrift, false
}

func rms(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := 0.0
	for _, x := range v {
		s += x * x
	}
	return math.Sqrt(s / float64(len(v)))
}

func pad4(n int) string {
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

func formatFloat(v float64) string {
	return strconv.FormatFloat(math.Round(v*1e12)/1e12, 'g', -1, 64)
}

func formatInt(v int) string {
	return strconv.Itoa(v)
}
