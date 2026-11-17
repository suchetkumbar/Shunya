//go:build brokenwipe

package canary

import "testing"

// With the real brokenwipe engine (it skips the last 1 % but reports success), the
// harness finds residue, all of it in the skipped tail.
func TestHarnessCatchesBrokenEngine(t *testing.T) {
	tg, set, files := prepare(t)
	before := scanTarget(t, tg, set, files)
	wipe(t, tg)
	after := scanTarget(t, tg, set, files)
	skipFrom := int64(testSize - testSize/100/512*512)
	c := Case{Name: "broken-engine", Broken: true, SkipFrom: skipFrom, VerifyExit: 4,
		Before: Phase{Residue: before}, After: Phase{Residue: after}}
	c.Evaluate(files)
	if !c.Pass || after.FirstOffset != skipFrom {
		t.Fatalf("broken engine not caught as expected: %+v %v", after, c.Why)
	}
	t.Logf("caught: %d canary tokens left in bytes %d..%d", after.Tokens, after.FirstOffset, after.LastOffset)
}
