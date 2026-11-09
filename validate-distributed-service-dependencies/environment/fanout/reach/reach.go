package reach

import (
	"sort"
	"strconv"
	"strings"
)

type Edge struct {
	From string
	To   string
}

func ObservedAdj(edges []Edge) map[string][]string {
	adj := make(map[string][]string)
	for _, e := range edges {
		adj[e.From] = append(adj[e.From], e.To)
	}
	for k := range adj {
		sort.Strings(adj[k])
	}
	return adj
}

func ReverseAdj(edges []Edge) map[string][]string {
	adj := make(map[string][]string)
	for _, e := range edges {
		adj[e.To] = append(adj[e.To], e.From)
	}
	for k := range adj {
		sort.Strings(adj[k])
	}
	return adj
}

func DeclaredAdj(edges []Edge) map[string][]string {
	return ObservedAdj(edges)
}

func SmallestCycleRotation(cycle []string) string {
	if len(cycle) < 2 {
		return strings.Join(cycle, ">")
	}
	return strings.Join(cycle, ">")
}

func FindCycles(edges []Edge) [][2]string {
	adj := ObservedAdj(edges)
	nodes := make(map[string]struct{})
	for _, e := range edges {
		nodes[e.From] = struct{}{}
		nodes[e.To] = struct{}{}
	}
	ids := make([]string, 0, len(nodes))
	for id := range nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	index := 0
	indices := map[string]int{}
	lowlink := map[string]int{}
	onstack := map[string]bool{}
	stack := []string{}
	var sccs [][]string

	var strongconnect func(v string)
	strongconnect = func(v string) {
		indices[v] = index
		lowlink[v] = index
		index++
		stack = append(stack, v)
		onstack[v] = true
		for _, w := range adj[v] {
			if _, ok := indices[w]; !ok {
				strongconnect(w)
				if lowlink[w] < lowlink[v] {
					lowlink[v] = lowlink[w]
				}
			} else if onstack[w] {
				if indices[w] < lowlink[v] {
					lowlink[v] = indices[w]
				}
			}
		}
		if lowlink[v] == indices[v] {
			comp := []string{}
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onstack[w] = false
				comp = append(comp, w)
				if w == v {
					break
				}
			}
			if len(comp) > 1 {
				sort.Strings(comp)
				sccs = append(sccs, comp)
			} else if len(comp) == 1 {
				for _, to := range adj[comp[0]] {
					if to == comp[0] {
						sccs = append(sccs, comp)
						break
					}
				}
			}
		}
	}
	for _, v := range ids {
		if _, ok := indices[v]; !ok {
			strongconnect(v)
		}
	}

	out := make([][2]string, 0)
	seen := map[string]struct{}{}
	for _, comp := range sccs {
		cycle := extractCycle(comp, adj)
		if cycle == nil {
			continue
		}
		detail := SmallestCycleRotation(cycle)
		entity := strings.Split(detail, ">")[0]
		if _, ok := seen[detail]; ok {
			continue
		}
		seen[detail] = struct{}{}
		out = append(out, [2]string{entity, detail})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i][1] != out[j][1] {
			return out[i][1] < out[j][1]
		}
		return out[i][0] < out[j][0]
	})
	return out
}

func extractCycle(comp []string, adj map[string][]string) []string {
	inComp := map[string]struct{}{}
	for _, n := range comp {
		inComp[n] = struct{}{}
	}
	start := comp[0]
	type frame struct {
		node string
		path []string
	}
	queue := []frame{{node: start, path: []string{start}}}
	visited := map[string]struct{}{start: {}}
	for len(queue) > 0 {
		f := queue[0]
		queue = queue[1:]
		for _, nxt := range adj[f.node] {
			if _, ok := inComp[nxt]; !ok {
				continue
			}
			if nxt == start && len(f.path) >= 1 {
				cyc := append(append([]string{}, f.path...), start)
				if len(cyc) >= 3 {
					return cyc
				}
			}
			if _, seen := visited[nxt]; seen {
				continue
			}
			visited[nxt] = struct{}{}
			np := append(append([]string{}, f.path...), nxt)
			queue = append(queue, frame{node: nxt, path: np})
		}
	}
	for _, to := range adj[start] {
		if to == start {
			return []string{start, start}
		}
	}
	return nil
}

func Reachable(adj map[string][]string, from string) map[string]struct{} {
	seen := map[string]struct{}{}
	if from == "" {
		return seen
	}
	stack := []string{from}
	seen[from] = struct{}{}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, nxt := range adj[cur] {
			if _, ok := seen[nxt]; ok {
				continue
			}
			seen[nxt] = struct{}{}
			stack = append(stack, nxt)
		}
	}
	return seen
}

func CascadeHops(rev map[string][]string, failed string) (maxHop int, reached map[string]int) {
	reached = map[string]int{}
	if failed == "" {
		return 0, reached
	}
	type item struct {
		id  string
		hop int
	}
	q := []item{{id: failed, hop: 0}}
	reached[failed] = 0
	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		for _, nxt := range rev[cur.id] {
			if _, ok := reached[nxt]; ok {
				continue
			}
			h := cur.hop + 1
			reached[nxt] = h
			if h > maxHop {
				maxHop = h
			}
			q = append(q, item{id: nxt, hop: h})
		}
	}
	return maxHop, reached
}

func LongestDeclaredDepth(adj map[string][]string, seed string) (deepest string, depth int) {
	if seed == "" {
		return "", 0
	}
	bestDepth := 0
	bestID := seed
	path := map[string]struct{}{seed: {}}
	var dfs func(id string, dep int)
	dfs = func(id string, dep int) {
		if dep > bestDepth || (dep == bestDepth && id < bestID) {
			bestDepth = dep
			bestID = id
		}
		for _, nxt := range adj[id] {
			if _, in := path[nxt]; in {
				continue
			}
			path[nxt] = struct{}{}
			dfs(nxt, dep+1)
			delete(path, nxt)
		}
	}
	dfs(seed, 0)
	return bestID, bestDepth
}

func MutualPairs(edges []Edge) [][2]string {
	forward := map[string]map[string]struct{}{}
	for _, e := range edges {
		if forward[e.From] == nil {
			forward[e.From] = map[string]struct{}{}
		}
		forward[e.From][e.To] = struct{}{}
	}
	seen := map[string]struct{}{}
	out := [][2]string{}
	for a, tos := range forward {
		for b := range tos {
			if _, ok := forward[b][a]; !ok {
				continue
			}
			key := a + ">" + b
			if _, ok := seen[key]; ok {
				continue
			}
			rev := b + ">" + a
			if _, ok := seen[rev]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, [2]string{a, b})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i][0] != out[j][0] {
			return out[i][0] < out[j][0]
		}
		return out[i][1] < out[j][1]
	})
	return out
}

func CycleCoversPair(detail, a, b string) bool {
	nodes := strings.Split(detail, ">")
	hasA, hasB := false, false
	for _, n := range nodes[:len(nodes)-1] {
		if n == a {
			hasA = true
		}
		if n == b {
			hasB = true
		}
	}
	_ = hasB
	return hasA
}

func FormatInt(n int) string {
	return strconv.Itoa(n)
}
