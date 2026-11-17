package canary

// Matcher is an Aho-Corasick automaton: it finds every occurrence of every pattern in
// one pass over the data, at every byte offset, in time linear in the data. The scan
// state is a single int, so a stream can be fed in chunks of any size and matches that
// span chunk boundaries are still found.
//
// The goto function is fully expanded into a dense [256] table per state (patterns here
// are few and short), so the inner loop is one table lookup per byte.
type Matcher struct {
	next [][256]int32
	out  [][]int // patterns ending at each state, including via suffix links
	lens []int
}

// NewMatcher builds the automaton. Empty patterns are ignored.
func NewMatcher(patterns [][]byte) *Matcher {
	m := &Matcher{next: make([][256]int32, 1), out: make([][]int, 1)}
	for i, p := range patterns {
		m.lens = append(m.lens, len(p))
		if len(p) == 0 {
			continue
		}
		s := int32(0)
		for _, c := range p {
			if m.next[s][c] == 0 {
				m.next = append(m.next, [256]int32{})
				m.out = append(m.out, nil)
				m.next[s][c] = int32(len(m.next) - 1)
			}
			s = m.next[s][c]
		}
		m.out[s] = append(m.out[s], i)
	}
	// Breadth-first: compute failure links and turn the trie into a full transition
	// table (missing edges follow the failure link).
	fail := make([]int32, len(m.next))
	queue := make([]int32, 0, len(m.next))
	for c := range 256 {
		if s := m.next[0][c]; s != 0 {
			queue = append(queue, s)
		}
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		m.out[s] = append(m.out[s], m.out[fail[s]]...)
		for c := range 256 {
			t := m.next[s][c]
			if t == 0 {
				m.next[s][c] = m.next[fail[s]][c]
				continue
			}
			fail[t] = m.next[fail[s]][c]
			queue = append(queue, t)
		}
	}
	return m
}

// PatternLen returns the length of pattern i.
func (m *Matcher) PatternLen(i int) int { return m.lens[i] }

// Start is the initial scan state.
func (m *Matcher) Start() int32 { return 0 }

// Feed scans data, which starts at absolute offset base, from state st, calling hit for
// every match with the pattern index and the absolute offset just past the match. It
// returns the state to continue with.
func (m *Matcher) Feed(st int32, data []byte, base int64, hit func(pattern int, end int64)) int32 {
	next, out := m.next, m.out
	for i, c := range data {
		st = next[st][c]
		if out[st] != nil {
			for _, p := range out[st] {
				hit(p, base+int64(i)+1)
			}
		}
	}
	return st
}
