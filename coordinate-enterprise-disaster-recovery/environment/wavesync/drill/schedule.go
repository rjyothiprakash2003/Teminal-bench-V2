package drill

import "sort"

func EventTieKey(ev Event) string {
	switch ev.Kind {
	case "REGISTER_DATACENTER":
		return ev.RegionClass
	case "DECLARE_SNAPSHOT":
		return ev.SnapshotID
	case "LINK_DEPENDENCY":
		return ev.ToService
	case "START_WAVE":
		return ev.WaveID
	case "RESTORE_SERVICE":
		return ev.ServiceID
	case "PROBE_HEALTH":
		return ev.ProbeID
	case "EXECUTE_ROLLBACK":
		return ev.ServiceID
	case "CLOSE_DRILL":
		return ev.ClosedAt
	default:
		return ""
	}
}

func SortEvents(events []Event) []Event {
	out := append([]Event(nil), events...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Seq != out[j].Seq {
			return out[i].Seq < out[j].Seq
		}
		ci := EventTieKey(out[i])
		cj := EventTieKey(out[j])
		if ci != cj {
			return ci < cj
		}
		return out[i].EventID < out[j].EventID
	})
	return out
}

func FilterDuplicateEvents(events []Event) ([]Event, int) {
	seen := make(map[string]struct{})
	out := make([]Event, 0, len(events))
	skipped := 0
	for _, ev := range events {
		if ev.EventID == "" {
			out = append(out, ev)
			continue
		}
		if _, dup := seen[ev.EventID]; dup {
			skipped++
			continue
		}
		seen[ev.EventID] = struct{}{}
		out = append(out, ev)
	}
	return out, skipped
}
