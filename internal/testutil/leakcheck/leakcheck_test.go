package leakcheck

import (
	"fmt"
	"testing"
)

// fakeTB captures what Check reports, so the checker itself can be tested.
type fakeTB struct {
	testing.TB
	cleanups []func()
	errors   []string
}

func (f *fakeTB) Helper()           {}
func (f *fakeTB) Cleanup(fn func()) { f.cleanups = append(f.cleanups, fn) }
func (f *fakeTB) Errorf(format string, a ...any) {
	f.errors = append(f.errors, fmt.Sprintf(format, a...))
}

func (f *fakeTB) finish() {
	for i := len(f.cleanups) - 1; i >= 0; i-- {
		f.cleanups[i]()
	}
}

func TestDetectsLeak(t *testing.T) {
	ft := &fakeTB{TB: t}
	Check(ft)
	stop := make(chan struct{})
	go func() { <-stop }()
	ft.finish()
	close(stop)
	if len(ft.errors) != 1 {
		t.Fatalf("leak not reported: %v", ft.errors)
	}
}

func TestNoLeak(t *testing.T) {
	ft := &fakeTB{TB: t}
	Check(ft)
	done := make(chan struct{})
	go func() { close(done) }()
	<-done
	ft.finish()
	if len(ft.errors) != 0 {
		t.Fatalf("false positive: %v", ft.errors)
	}
}
