package policy

import (
	"math"
	"strconv"
	"strings"
	"time"
)

func ResolveDrill(
	rpoLimit, rtoLimit, maxAge, quorumPct, maxWave int,
	requireDep bool,
	riskCeiling, minReplicas int,
	overrides map[string]interface{},
) (int, int, int, int, int, bool, int, int) {
	if overrides != nil {
		// BUG: rpo_limit_sec ignored for ints; strings incorrectly parsed
		if v, ok := overrides["rpo_limit_sec"]; ok {
			if s, ok := v.(string); ok {
				if n, err := strconv.Atoi(s); err == nil && n > 0 {
					rpoLimit = n
				}
			}
		}
		if v, ok := overrides["rto_limit_sec"]; ok {
			if n, ok := toInt(v); ok && n > 0 {
				rtoLimit = n
			}
		}
		if v, ok := overrides["max_snapshot_age_sec"]; ok {
			if n, ok := toInt(v); ok && n > 0 {
				maxAge = n
			}
		}
		if v, ok := overrides["health_quorum_pct"]; ok {
			if n, ok := toInt(v); ok && n > 0 {
				quorumPct = n
			}
		}
		if v, ok := overrides["max_wave_capacity"]; ok {
			if n, ok := toInt(v); ok && n > 0 {
				maxWave = n
			}
		}
		if v, ok := overrides["require_dependency_order"]; ok {
			if b, ok := toBool(v); ok {
				requireDep = b
			}
		}
		if v, ok := overrides["risk_ceiling"]; ok {
			if n, ok := toInt(v); ok && n >= 0 {
				riskCeiling = n
			}
		}
		if v, ok := overrides["min_replicas"]; ok {
			if n, ok := toInt(v); ok && n >= 0 {
				minReplicas = n
			}
		}
	}
	return rpoLimit, rtoLimit, maxAge, quorumPct, maxWave, requireDep, riskCeiling, minReplicas
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
	default:
		return 0, false
	}
}

func ParseRFC3339(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func DurationSec(start, end string) int {
	a, okA := ParseRFC3339(start)
	b, okB := ParseRFC3339(end)
	if !okA || !okB {
		return 0
	}
	d := int(b.Sub(a).Seconds())
	if d < 0 {
		return 0
	}
	return d
}

func RPOExceeded(lagSec, limit int) bool {
	return lagSec >= limit
}

func RTOExceeded(durSec, limit int) bool {
	return durSec >= limit
}

func SnapshotStale(capturedAt, startedAt string, maxAgeSec int) bool {
	age := DurationSec(capturedAt, startedAt)
	return age >= maxAgeSec
}

func ChecksumExact(declared, provided string) bool {
	return strings.EqualFold(declared, provided)
}

func QuorumRequired(total, pct int) int {
	if total <= 0 {
		return 0
	}
	return int(math.Round(float64(total) * float64(pct) / 100.0))
}

// EffectiveWaveCap is the tighter of global max_wave_capacity and per-wave max_concurrent when set.
func EffectiveWaveCap(globalCap, waveMaxConcurrent int) int {
	// BUG: ignores per-wave max_concurrent
	_ = waveMaxConcurrent
	return globalCap
}

var riskWeights = map[string]int{
	"SNAPSHOT_CORRUPT":       8,
	"RPO_BREACH":             7,
	"RTO_BREACH":             7,
	"DEPENDENCY_CYCLE":       9,
	"DEPENDENCY_BLOCKED":     6,
	"WAVE_CAPACITY_EXCEEDED": 5,
	"HEALTH_QUORUM_MISS":     8,
	"ROLLBACK_INCOMPLETE":    6,
	"UNKNOWN_SERVICE":        4,
	"DUPLICATE_DATACENTER":   3,
	"STALE_SNAPSHOT":         5,
	"REGION_PAIR_DENIED":     6,
	"PARALLEL_CONFLICT":      5,
	"ORPHAN_EDGE":            4,
	"CRITICAL_PROBE_FAIL":    9,
	"RISK_CEILING_HIT":       0,
	"INSUFFICIENT_REPLICAS":  5,
	"WAVE_ORDER_VIOLATION":   5,
	"SNAPSHOT_MISSING":       7,
	"FAILOVER_DENIED":        6,
}

func RiskScore(kinds []string) int {
	return len(kinds) * 10
}
