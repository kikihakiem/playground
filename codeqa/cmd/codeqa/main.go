package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/tmc/langchaingo/embeddings"
	"github.com/tmc/langchaingo/llms/ollama"

	"github.com/khakiem/playground/codeqa/pkg/hitl"
	"github.com/khakiem/playground/codeqa/pkg/loader"
	"github.com/khakiem/playground/codeqa/pkg/rag"
	"github.com/khakiem/playground/codeqa/pkg/splitter"
	"github.com/khakiem/playground/codeqa/pkg/vectorstore"
)

func main() {
	repo := flag.String("repo", ".", "path to Go repository to index")
	model := flag.String("model", "qwen2.5-coder:14b", "Ollama model for generation")
	embedModel := flag.String("embed-model", "nomic-embed-text", "Ollama model for embeddings")
	server := flag.String("server", "http://localhost:11434", "Ollama server URL")
	chunks := flag.Int("chunks", 4, "number of chunks to retrieve per query")
	noHITL := flag.Bool("no-hitl", false, "disable human-in-the-loop checkpoints")
	skipTests := flag.Bool("skip-tests", false, "skip _test.go files during indexing")
	chunkSize := flag.Int("chunk-size", 1500, "target chunk size in characters")
	chunkOverlap := flag.Int("chunk-overlap", 200, "overlap between chunks in characters")
	flag.Parse()

	ctx := context.Background()

	// ── LLM for generation ───────────────────────────────────────────────
	llm, err := ollama.New(
		ollama.WithModel(*model),
		ollama.WithServerURL(*server),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create LLM: %v\n", err)
		os.Exit(1)
	}

	// ── Embedder (separate model optimised for embeddings) ───────────────
	embedLLM, err := ollama.New(
		ollama.WithModel(*embedModel),
		ollama.WithServerURL(*server),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create embedding LLM: %v\n", err)
		os.Exit(1)
	}
	embedder, err := embeddings.NewEmbedder(embedLLM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create embedder: %v\n", err)
		os.Exit(1)
	}

	// ── Wire up components ───────────────────────────────────────────────
	store := vectorstore.New(embedder)
	goSplitter := splitter.NewGoSplitter(*chunkSize, *chunkOverlap)

	pipeline := &rag.Pipeline{
		LLM:   llm,
		Store: store,
		Loader: &loader.GoLoader{
			SkipTests:  *skipTests,
			SkipVendor: true,
		},
		Splitter: goSplitter,
		NumDocs:  *chunks,
		Logger:   os.Stderr,
	}

	if !*noHITL {
		tr := hitl.TerminalReviewer{}
		pipeline.IndexReviewer = tr
		pipeline.AnswerReviewer = tr
	}

	// ── Banner ───────────────────────────────────────────────────────────
	fmt.Fprintln(os.Stderr, "codeqa — RAG-powered Go codebase Q&A")
	fmt.Fprintf(os.Stderr, "backend  : %s via %s\n", *model, *server)
	fmt.Fprintf(os.Stderr, "embedder : %s\n", *embedModel)
	fmt.Fprintf(os.Stderr, "chunks   : %d per query (size=%d, overlap=%d)\n", *chunks, *chunkSize, *chunkOverlap)
	if *noHITL {
		fmt.Fprintln(os.Stderr, "hitl     : disabled")
	} else {
		fmt.Fprintln(os.Stderr, "hitl     : enabled")
	}
	fmt.Fprintln(os.Stderr)

	// ── Index ────────────────────────────────────────────────────────────
	if err := pipeline.Index(ctx, *repo); err != nil {
		fmt.Fprintf(os.Stderr, "Indexing failed: %v\n", err)
		os.Exit(1)
	}

	// ── Interactive Q&A ──────────────────────────────────────────────────
	if err := pipeline.QueryLoop(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
