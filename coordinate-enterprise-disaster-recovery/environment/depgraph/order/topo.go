package order

import "sort"

type Graph map[string]map[string]struct{}

func NewGraph() Graph {
	return Graph{}
}

func (g Graph) AddEdge(from, to string) {
	if g[from] == nil {
		g[from] = make(map[string]struct{})
	}
	g[from][to] = struct{}{}
}

func UnmetProviders(g Graph, service string, restored map[string]bool) string {
	providers := make([]string, 0)
	for p := range g[service] {
		providers = append(providers, p)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(providers)))
	for _, p := range providers {
		if !restored[p] {
			return p
		}
	}
	return ""
}

func DirectDependents(g Graph, target string) []string {
	// BUG: transitive closure instead of direct dependents only
	out := make([]string, 0)
	seen := map[string]struct{}{target: {}}
	queue := []string{target}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for dep, providers := range g {
			if _, ok := providers[cur]; !ok {
				continue
			}
			if _, done := seen[dep]; done {
				continue
			}
			seen[dep] = struct{}{}
			out = append(out, dep)
			queue = append(queue, dep)
		}
	}
	sort.Strings(out)
	return out
}

func DetectCycle(g Graph) string {
	nodes := make([]string, 0, len(g))
	seen := map[string]struct{}{}
	for n, providers := range g {
		if _, ok := seen[n]; !ok {
			seen[n] = struct{}{}
			nodes = append(nodes, n)
		}
		for p := range providers {
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				nodes = append(nodes, p)
			}
		}
	}
	sort.Strings(nodes)

	visited := map[string]struct{}{}
	stack := map[string]struct{}{}
	var path []string
	var found []string

	var dfs func(cur string) bool
	dfs = func(cur string) bool {
		if _, on := stack[cur]; on {
			idx := 0
			for i, n := range path {
				if n == cur {
					idx = i
					break
				}
			}
			cyc := append([]string{}, path[idx:]...)
			cyc = append(cyc, cur)
			detail := rotateCycle(cyc)
			if found == nil || detail < joinCycle(found) {
				found = cyc
			}
			return true
		}
		if _, done := visited[cur]; done {
			return false
		}
		visited[cur] = struct{}{}
		stack[cur] = struct{}{}
		path = append(path, cur)
		providers := make([]string, 0, len(g[cur]))
		for p := range g[cur] {
			providers = append(providers, p)
		}
		sort.Strings(providers)
		hit := false
		for _, p := range providers {
			if dfs(p) {
				hit = true
			}
		}
		path = path[:len(path)-1]
		delete(stack, cur)
		return hit
	}

	for _, n := range nodes {
		dfs(n)
	}
	if found == nil {
		return ""
	}
	return joinCycle(found)
}

func rotateCycle(cyc []string) string {
	if len(cyc) < 2 {
		return joinCycle(cyc)
	}
	body := cyc[:len(cyc)-1]
	best := body
	bestStr := joinCycle(append(append([]string{}, body...), body[0]))
	for i := 1; i < len(body); i++ {
		rot := append(append([]string{}, body[i:]...), body[:i]...)
		s := joinCycle(append(append([]string{}, rot...), rot[0]))
		if s < bestStr {
			best = rot
			bestStr = s
		}
	}
	return joinCycle(append(append([]string{}, best...), best[0]))
}

func joinCycle(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for i := 1; i < len(parts); i++ {
		out += ">" + parts[i]
	}
	return out
}
