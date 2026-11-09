package replay

import "sort"

type Event struct {
	Seq      int    `json:"seq"`
	EventID  string `json:"event_id"`
	Kind     string `json:"kind"`
	SiteID   string `json:"site_id"`
	SinkID   string `json:"sink_id"`
	SourceID string `json:"source_id"`
	Channel  string `json:"channel"`
	Required bool   `json:"required"`
	Critical bool   `json:"critical"`
	Tier     string `json:"tier"`
	Weight     int    `json:"weight"`
}

func EventTieKey(ev Event) string {
	switch ev.Kind {
	case "REGISTER_SITE", "SET_SEED", "FLAG_CRITICAL", "INJECT_FAILURE":
		return ev.SiteID
	case "DECLARE_COUPLING":
		return ev.SinkID
	case "OBSERVE_COUPLING":
		return ev.SourceID
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
	return append([]Event(nil), events...), 0
}
