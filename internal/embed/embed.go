// Package embed turns an alert's textual signature into a fixed-length vector so
// the semantic cache can reuse a prior Claude analysis for a near-duplicate
// alert (same root cause, different pod) rather than only an exact key match.
//
// The default Embedder is a local feature-hashing vectorizer: it runs entirely
// in-process with no external API call, which keeps alert data inside the
// cluster — the same privacy property that makes muthur's redact-before-LLM
// design worthwhile. It captures lexical overlap (shared tokens → high cosine
// similarity), which is what catches near-duplicate alerts. The Embedder
// interface leaves room for a model-backed implementation (e.g. Voyage) when a
// deployment is willing to send signatures to an embeddings provider.
package embed

import (
	"hash/fnv"
	"math"
	"strings"
	"unicode"
)

// Embedder maps text to a unit-length vector. Implementations must be
// deterministic and safe for concurrent use.
type Embedder interface {
	Embed(text string) []float32
	Dim() int
}

// HashEmbedder is a feature-hashing (a.k.a. "hashing trick") vectorizer. Tokens
// are hashed into Dim buckets, term frequencies accumulated, and the vector
// L2-normalized so cosine similarity reduces to a dot product.
type HashEmbedder struct {
	dim int
}

// NewHashEmbedder returns a HashEmbedder with the given dimensionality. 256 is
// a good default for short alert signatures.
func NewHashEmbedder(dim int) *HashEmbedder {
	if dim <= 0 {
		dim = 256
	}
	return &HashEmbedder{dim: dim}
}

func (h *HashEmbedder) Dim() int { return h.dim }

func (h *HashEmbedder) Embed(text string) []float32 {
	vec := make([]float32, h.dim)
	for _, tok := range tokenize(text) {
		idx := bucket(tok, h.dim)
		// Signed hashing reduces collision bias: half the tokens add, half
		// subtract, so unrelated collisions tend to cancel.
		if signBit(tok) {
			vec[idx]++
		} else {
			vec[idx]--
		}
	}
	normalize(vec)
	return vec
}

// Cosine returns the cosine similarity of two equal-length unit vectors. For
// vectors produced by Embed (already normalized) this is just the dot product,
// but it renormalizes defensively in case callers pass raw vectors.
func Cosine(a, b []float32) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot, na, nb float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		na += float64(a[i]) * float64(a[i])
		nb += float64(b[i]) * float64(b[i])
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}

func tokenize(text string) []string {
	return strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	})
}

func bucket(tok string, dim int) int {
	hh := fnv.New32a()
	_, _ = hh.Write([]byte(tok))
	return int(hh.Sum32() % uint32(dim))
}

func signBit(tok string) bool {
	hh := fnv.New32()
	_, _ = hh.Write([]byte(tok))
	return hh.Sum32()&1 == 0
}

func normalize(vec []float32) {
	var norm float64
	for _, v := range vec {
		norm += float64(v) * float64(v)
	}
	if norm == 0 {
		return
	}
	inv := float32(1 / math.Sqrt(norm))
	for i := range vec {
		vec[i] *= inv
	}
}
