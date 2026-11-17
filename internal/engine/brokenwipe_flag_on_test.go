//go:build brokenwipe

package engine

import (
	"testing"
)

const brokenBuild = true

// In the broken build exactly the last 1 % (rounded to sectors) keeps its old data.
func TestBrokenWipeSkipsLastPercent(t *testing.T) {
	tg := image(t, "", 200*64*kib, 512)
	p := planFor(t, tg, 64*kib, 64*kib)
	if _, err := run(t, nil, tg, p, &memRecorder{}, RunOptions{}); err != nil {
		t.Fatal(err)
	}
	skip := brokenSkipFrom(tg.Size(), 512)
	checkRange(t, tg, mustPattern(t, p.Passes[0]), 0, skip)
	checkRange(t, tg, nil, skip, tg.Size())
	if skip != tg.Size()-tg.Size()/100/512*512 {
		t.Fatalf("skip from %d", skip)
	}
}
