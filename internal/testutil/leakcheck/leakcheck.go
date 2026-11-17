// Package leakcheck fails a test that leaves goroutines running: a small stand-in for
// go.uber.org/goleak, kept in-tree to avoid a dependency.
//
// Usage, at the top of a (non-parallel) test:
//
//	leakcheck.Check(t)
//
// It records the goroutines alive at that point and, when the test ends, waits up to
// two seconds for every goroutine started since to exit.
package leakcheck

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

// Check registers a cleanup that fails t if goroutines started during the test are
// still running at its end.
func Check(t testing.TB) {
	t.Helper()
	before := goroutines()
	t.Cleanup(func() {
		deadline := time.Now().Add(2 * time.Second)
		for {
			leaked := leakedSince(before)
			if len(leaked) == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Errorf("leakcheck: %d goroutine(s) still running after the test:\n\n%s",
					len(leaked), strings.Join(leaked, "\n\n"))
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

func leakedSince(before map[string]bool) []string {
	var out []string
	for id, stack := range snapshot() {
		if !before[id] && !ignorable(stack) {
			out = append(out, stack)
		}
	}
	return out
}

func goroutines() map[string]bool {
	m := map[string]bool{}
	for id := range snapshot() {
		m[id] = true
	}
	return m
}

// snapshot maps goroutine ID ("goroutine 17") to its stack trace.
func snapshot() map[string]string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	m := map[string]string{}
	for _, g := range strings.Split(string(buf), "\n\n") {
		head, _, _ := strings.Cut(g, " [")
		if strings.HasPrefix(head, "goroutine ") {
			m[head] = g
		}
	}
	return m
}

// ignorable: goroutines the testing and runtime packages start on their own.
func ignorable(stack string) bool {
	for _, s := range []string{
		"testing.(*T).Run(",
		"testing.tRunner(",
		"testing.(*M).",
		"testing.runFuzzing",
		"os/signal.signal_recv",
		"runtime.ensureSigM",
	} {
		if strings.Contains(stack, s) {
			return true
		}
	}
	return false
}
