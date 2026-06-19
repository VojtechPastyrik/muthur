package embed

import (
	"math"
	"testing"
)

func TestHashEmbedder_IdenticalText(t *testing.T) {
	e := NewHashEmbedder(256)
	a := e.Embed("PodCrashLoop default critical")
	b := e.Embed("PodCrashLoop default critical")
	if sim := Cosine(a, b); math.Abs(sim-1) > 1e-6 {
		t.Fatalf("identical text cosine = %v, want ~1", sim)
	}
}

func TestHashEmbedder_DifferentText(t *testing.T) {
	e := NewHashEmbedder(256)
	a := e.Embed("PodCrashLoop default critical memory")
	b := e.Embed("DiskFull storage warning filesystem")
	if sim := Cosine(a, b); sim > 0.5 {
		t.Fatalf("unrelated text cosine = %v, want low", sim)
	}
}

func TestHashEmbedder_Overlap(t *testing.T) {
	e := NewHashEmbedder(256)
	a := e.Embed("HighMemory default critical app")
	b := e.Embed("HighMemory default critical worker") // mostly shared tokens
	sim := Cosine(a, b)
	if sim < 0.5 {
		t.Fatalf("overlapping text cosine = %v, want moderately high", sim)
	}
}
