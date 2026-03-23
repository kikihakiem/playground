package vectorstore

import (
	"context"
	"fmt"
	"math"
	"sort"

	"github.com/tmc/langchaingo/embeddings"
	"github.com/tmc/langchaingo/schema"
	"github.com/tmc/langchaingo/vectorstores"
)

// Ensure InMemory satisfies the VectorStore interface at compile time.
var _ vectorstores.VectorStore = (*InMemory)(nil)

// entry pairs a document with its embedding vector.
type entry struct {
	doc    schema.Document
	vector []float32
}

// InMemory is a simple in-memory vector store that uses cosine similarity.
// It's not production-grade — it re-scans all vectors on every query — but
// it's perfect for learning: zero external deps, easy to debug, and you can
// inspect the similarity scores directly.
type InMemory struct {
	embedder embeddings.Embedder
	entries  []entry
}

// New creates an InMemory vector store backed by the given embedder.
func New(embedder embeddings.Embedder) *InMemory {
	return &InMemory{embedder: embedder}
}

// AddDocuments embeds each document and stores it. Returns generated IDs.
func (m *InMemory) AddDocuments(
	ctx context.Context,
	docs []schema.Document,
	_ ...vectorstores.Option,
) ([]string, error) {
	texts := make([]string, len(docs))
	for i, d := range docs {
		texts[i] = d.PageContent
	}

	vectors, err := m.embedder.EmbedDocuments(ctx, texts)
	if err != nil {
		return nil, fmt.Errorf("embed documents: %w", err)
	}

	ids := make([]string, len(docs))
	for i, d := range docs {
		ids[i] = fmt.Sprintf("doc-%d", len(m.entries))
		m.entries = append(m.entries, entry{doc: d, vector: vectors[i]})
	}

	return ids, nil
}

// SimilaritySearch embeds the query and returns the top numDocuments results
// ranked by cosine similarity.
func (m *InMemory) SimilaritySearch(
	ctx context.Context,
	query string,
	numDocuments int,
	_ ...vectorstores.Option,
) ([]schema.Document, error) {
	qv, err := m.embedder.EmbedQuery(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("embed query: %w", err)
	}

	type scored struct {
		doc   schema.Document
		score float64
	}

	results := make([]scored, len(m.entries))
	for i, e := range m.entries {
		results[i] = scored{doc: e.doc, score: cosine(qv, e.vector)}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].score > results[j].score
	})

	n := numDocuments
	if n > len(results) {
		n = len(results)
	}

	docs := make([]schema.Document, n)
	for i := 0; i < n; i++ {
		docs[i] = results[i].doc
		docs[i].Score = float32(results[i].score)
	}

	return docs, nil
}

// Len returns the number of stored documents (useful for stats/logging).
func (m *InMemory) Len() int {
	return len(m.entries)
}

// cosine computes the cosine similarity between two vectors.
func cosine(a, b []float32) float64 {
	if len(a) != len(b) {
		return 0
	}
	var dot, normA, normB float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		normA += float64(a[i]) * float64(a[i])
		normB += float64(b[i]) * float64(b[i])
	}
	denom := math.Sqrt(normA) * math.Sqrt(normB)
	if denom == 0 {
		return 0
	}
	return dot / denom
}
