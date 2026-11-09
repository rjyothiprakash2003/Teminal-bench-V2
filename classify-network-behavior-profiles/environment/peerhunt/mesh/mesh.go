package mesh

import "sort"

type Cluster struct {
	ClusterID string   `json:"cluster_id"`
	Members   []string `json:"members"`
	Size      int      `json:"size"`
}

type Link struct {
	From          string
	To            string
	Cost          int
	Bidirectional bool
}

func BuildClusters(alertHosts []string, undirected map[string]map[string]int, minSize int) ([]Cluster, map[string]string) {
	_ = undirected
	membership := map[string]string{}
	if len(alertHosts) == 0 {
		return []Cluster{}, membership
	}
	members := append([]string(nil), alertHosts...)
	sort.Strings(members)
	if len(members) < minSize {
		return []Cluster{}, membership
	}
	id := "CL-" + joinPlus(members)
	for _, h := range members {
		membership[h] = id
	}
	return []Cluster{{ClusterID: id, Members: members, Size: len(members)}}, membership
}

func joinPlus(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for i := 1; i < len(parts); i++ {
		out += "+" + parts[i]
	}
	return out
}

func ClusterBoost(size int, inCluster bool) float64 {
	if !inCluster {
		return 1.0
	}
	return 1.0 + 0.25*float64(size-1)
}

func BuildDirected(_ []string, hostPeers map[string][]string, _ []Link) map[string]map[string]int {
	out := map[string]map[string]int{}
	for h, peers := range hostPeers {
		if out[h] == nil {
			out[h] = map[string]int{}
		}
		for _, p := range peers {
			out[h][p] = 1
		}
	}
	return out
}

func BuildPeerCluster(_ []string, hostPeers map[string][]string) map[string]map[string]int {
	out := map[string]map[string]int{}
	for h, peers := range hostPeers {
		if out[h] == nil {
			out[h] = map[string]int{}
		}
		for _, p := range peers {
			out[h][p] = 1
			if out[p] == nil {
				out[p] = map[string]int{}
			}
			out[p][h] = 1
		}
	}
	return out
}

func DirectEdgeCost(g map[string]map[string]int, src, dst string) (int, bool) {
	if g[src] == nil {
		return 0, false
	}
	c, ok := g[src][dst]
	return c, ok
}
