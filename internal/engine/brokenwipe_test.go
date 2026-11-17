package engine

import "testing"

// Every ordinary build (dev, release, labtest) must write everything.
func TestBrokenWipeOnlyInBrokenBuild(t *testing.T) {
	if brokenTailPercent != 0 && !brokenBuild {
		t.Fatalf("brokenTailPercent = %d outside the brokenwipe build", brokenTailPercent)
	}
}
