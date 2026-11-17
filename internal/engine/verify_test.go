package engine

import (
	"bytes"
	"context"
	"math"
	"slices"
	"testing"
)

var seedA = bytes.Repeat([]byte{0xa1}, 32)

func TestSamplePositions(t *testing.T) {
	a := SamplePositions(seedA, "fp1:x", 1<<21, 3000)
	b := SamplePositions(seedA, "fp1:x", 1<<21, 3000)
	if len(a) != 3000 || !slices.Equal(a, b) || !slices.IsSorted(a) {
		t.Fatalf("not deterministic/sorted/sized: %d", len(a))
	}
	if a[0] != 0 || a[len(a)-1] != 1<<21-1 {
		t.Fatal("first/last sector not sampled")
	}
	if len(slices.Compact(slices.Clone(a))) != len(a) {
		t.Fatal("duplicates")
	}
	if c := SamplePositions(bytes.Repeat([]byte{0xa2}, 32), "fp1:x", 1<<21, 3000); slices.Equal(a, c) {
		t.Fatal("another seed gave the same positions")
	}
	if d := SamplePositions(seedA, "fp1:y", 1<<21, 3000); slices.Equal(a, d) {
		t.Fatal("another drive gave the same positions")
	}
	if all := SamplePositions(seedA, "fp1:x", 10, 50); len(all) != 10 {
		t.Fatalf("n > sectors: %d", len(all))
	}
}

// Sampling must find corrupted sectors at the rate the bound promises.
func TestVerifySampledDetects(t *testing.T) {
	const sectors = 8192
	tg := image(t, "", sectors*512, 512)
	p := planFor(t, tg, 64*kib, 64*kib)
	if _, err := run(t, nil, tg, p, &memRecorder{}, RunOptions{}); err != nil {
		t.Fatal(err)
	}
	pat := mustPattern(t, p.Passes[0])
	res, err := VerifySampled(context.Background(), tg, pat, seedA, SeedOperator, 300)
	if err != nil || !res.OK() || res.Samples != 300 || res.BytesRead != 300*512 {
		t.Fatalf("clean: %+v %v", res, err)
	}
	if want := 1 - math.Pow(0.05, 1.0/300); math.Abs(res.Bound95-want) > 1e-12 || res.Bound95 > 0.0101 {
		t.Fatalf("bound %v", res.Bound95)
	}
	// Leave 5 % of sectors unwiped (every 20th): 300 samples miss all of them with
	// probability 0.95^300 ≈ 2e-7.
	old := bytes.Repeat([]byte{0xaa}, 512)
	for s := int64(0); s < sectors; s += 20 {
		tg.WriteAt(old, s*512)
	}
	res, _ = VerifySampled(context.Background(), tg, pat, seedA, SeedOperator, 300)
	if res.OK() || res.BadSectors < 5 {
		t.Fatalf("5 %% unwiped not caught: %+v", res)
	}
	// The last sector is always sampled, so a skipped tail is always caught.
	tg2 := image(t, t.TempDir(), sectors*512, 512)
	p2 := planFor(t, tg2, 64*kib, 64*kib)
	run(t, nil, tg2, p2, &memRecorder{}, RunOptions{})
	tg2.WriteAt(old, (sectors-1)*512)
	if r, _ := VerifySampled(context.Background(), tg2, mustPattern(t, p2.Passes[0]), seedA, SeedOperator, 2); r.OK() || r.FirstBad != (sectors-1)*512 {
		t.Fatalf("tail: %+v", r)
	}
	if _, err := VerifySampled(context.Background(), tg, pat, []byte("short"), SeedOperator, 10); err == nil {
		t.Fatal("short seed accepted")
	}
}

func TestVerifyFullFindsEverything(t *testing.T) {
	tg := image(t, "", 100*512, 512)
	p := planFor(t, tg, 64*kib, 64*kib)
	run(t, nil, tg, p, &memRecorder{}, RunOptions{})
	pat := mustPattern(t, p.Passes[0])
	tg.WriteAt(make([]byte, 1024), 37*512)
	v, err := Verify(context.Background(), tg, pat, 4096)
	if err != nil || v.BadSectors != 2 || v.FirstBad != 37*512 || v.BytesRead != 100*512 {
		t.Fatalf("%+v %v", v, err)
	}
}
