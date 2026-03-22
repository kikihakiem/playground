package rag

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/tmc/langchaingo/chains"
	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/memory"
	"github.com/tmc/langchaingo/prompts"
	"github.com/tmc/langchaingo/schema"
	"github.com/tmc/langchaingo/textsplitter"
	"github.com/tmc/langchaingo/vectorstores"

	"github.com/khakiem/playground/codeqa/pkg/hitl"
	"github.com/khakiem/playground/codeqa/pkg/loader"
	vs "github.com/khakiem/playground/codeqa/pkg/vectorstore"
)

// Pipeline orchestrates the full RAG workflow:
//
//	Load files → HITL review → split & embed → interactive Q&A loop with HITL
type Pipeline struct {
	LLM     llms.Model
	Store   *vs.InMemory
	Loader  *loader.GoLoader
	Splitter textsplitter.TextSplitter

	NumDocs int // number of chunks to retrieve per query (default: 4)

	IndexReviewer  hitl.IndexReviewer  // checkpoint 1: review before indexing
	AnswerReviewer hitl.AnswerReviewer // checkpoint 2: review each answer

	Logger io.Writer
}

func (p *Pipeline) logf(format string, args ...any) {
	if p.Logger == nil {
		return
	}
	fmt.Fprintf(p.Logger, format, args...)
}

// Index loads Go files, splits them into chunks, and embeds them into the
// vector store. If an IndexReviewer is configured, it pauses after file
// discovery for human approval.
func (p *Pipeline) Index(ctx context.Context, repoPath string) error {
	p.Loader.Root = repoPath

	// 1. Load all Go files as documents.
	p.logf("Scanning %s for .go files...\n", repoPath)
	docs, err := p.Loader.Load(ctx)
	if err != nil {
		return fmt.Errorf("load files: %w", err)
	}
	if len(docs) == 0 {
		return fmt.Errorf("no .go files found in %s", repoPath)
	}
	p.logf("Found %d file(s)\n", len(docs))

	// 2. Split into chunks.
	chunks, err := textsplitter.SplitDocuments(p.Splitter, docs)
	if err != nil {
		return fmt.Errorf("split documents: %w", err)
	}

	// 2b. Enrich each chunk with a metadata preamble so the embedding model
	// captures file/package context. Without this, a chunk containing
	// `const DefaultModel = "qwen2.5-coder:14b"` has no signal that it's
	// from llm_openai.go or related to AI models.
	for i, c := range chunks {
		src, _ := c.Metadata["source"].(string)
		pkg, _ := c.Metadata["package"].(string)
		if src != "" {
			preamble := fmt.Sprintf("// File: %s  Package: %s\n", src, pkg)
			chunks[i].PageContent = preamble + c.PageContent
		}
	}

	// Collect unique packages for stats.
	pkgSet := make(map[string]struct{})
	for _, d := range docs {
		if pkg, ok := d.Metadata["package"].(string); ok {
			pkgSet[pkg] = struct{}{}
		}
	}
	pkgs := make([]string, 0, len(pkgSet))
	for pkg := range pkgSet {
		pkgs = append(pkgs, pkg)
	}
	sort.Strings(pkgs)

	// ── HITL Checkpoint 1: Index Review ──────────────────────────────────
	if p.IndexReviewer != nil {
		stats := hitl.IndexStats{
			Files:    len(docs),
			Chunks:   len(chunks),
			Packages: pkgs,
		}

		for {
			decision, feedback, revErr := p.IndexReviewer.ReviewIndex(ctx, stats)
			if revErr != nil {
				return fmt.Errorf("index reviewer: %w", revErr)
			}
			switch decision {
			case hitl.Approve:
				p.logf("Index approved.\n")
			case hitl.Revise:
				p.logf("Revision requested: %s\n", feedback)
				p.logf("(Re-configure loader settings and try again.)\n")
				continue
			case hitl.Abort:
				return fmt.Errorf("indexing aborted by reviewer")
			}
			break
		}
	}

	// 3. Embed and store.
	p.logf("Embedding %d chunk(s)...\n", len(chunks))
	_, err = p.Store.AddDocuments(ctx, chunks)
	if err != nil {
		return fmt.Errorf("add documents to store: %w", err)
	}
	p.logf("Indexed %d chunk(s) from %d file(s) [packages: %s]\n\n",
		p.Store.Len(), len(docs), strings.Join(pkgs, ", "))

	return nil
}

// QueryLoop runs an interactive REPL that takes questions from stdin,
// retrieves relevant chunks, generates answers via the LLM, and optionally
// passes each answer through the AnswerReviewer.
func (p *Pipeline) QueryLoop(ctx context.Context) error {
	numDocs := p.NumDocs
	if numDocs <= 0 {
		numDocs = 4
	}

	// Build the conversational retrieval QA chain.
	retriever := vectorstores.ToRetriever(p.Store, numDocs)
	conversationMemory := memory.NewConversationBuffer(
		memory.WithReturnMessages(true),
		// Pin input/output keys so SaveContext knows which values to store.
		// Without these, SaveContext fails with "multiple keys and no input key set"
		// because the chain's output map contains both "text" and "source_documents".
		memory.WithInputKey("question"),
		memory.WithOutputKey("text"),
	)

	p.logf("[debug] memory input_key=%q output_key=%q memory_key=%q\n",
		"question", "text", conversationMemory.GetMemoryKey(ctx))

	// Custom code-aware QA prompt. The default langchaingo prompt says
	// "if you don't know, say I don't know" which causes the model to bail
	// on code questions. This prompt frames the context as Go source code
	// and instructs the model to analyze it.
	codeQAPrompt := prompts.NewPromptTemplate(
		`You are a Go code analyst. You are given fragments of Go source code and a question about them.
Analyze the code carefully and answer the question based on what you can see in the code.
Reference specific functions, types, variables, and packages when relevant.
If the code fragments don't contain enough information, say what you CAN determine and what's missing.

Go source code:
{{.context}}

Question: {{.question}}
Answer:`,
		[]string{"context", "question"},
	)
	qaChain := chains.NewStuffDocuments(chains.NewLLMChain(p.LLM, codeQAPrompt))
	condenseChain := chains.LoadCondenseQuestionGenerator(p.LLM)

	chain := chains.NewConversationalRetrievalQA(
		qaChain,
		condenseChain,
		retriever,
		conversationMemory,
	)
	chain.ReturnSourceDocuments = true

	p.logf("[debug] chain input_key=%q return_source_documents=%v\n",
		chain.InputKey, chain.ReturnSourceDocuments)
	p.logf("[debug] using custom code-aware QA prompt\n")

	fmt.Fprintln(os.Stderr, "Ready. Type your question (or /quit to exit).")
	fmt.Fprintln(os.Stderr)

	scanner := lineScanner(os.Stdin)
	for {
		fmt.Fprint(os.Stderr, "> ")
		if !scanner.Scan() {
			break // EOF
		}
		question := strings.TrimSpace(scanner.Text())
		if question == "" {
			continue
		}
		if question == "/quit" || question == "/exit" {
			break
		}

		answer, sources, err := p.query(ctx, chain, question)
		if err != nil {
			p.logf("Error: %v\n\n", err)
			continue
		}

		// ── HITL Checkpoint 2: Answer Review ─────────────────────────────
		if p.AnswerReviewer != nil {
			ac := hitl.AnswerContext{
				Question: question,
				Answer:   answer,
				Sources:  sources,
			}
			for {
				decision, feedback, revErr := p.AnswerReviewer.ReviewAnswer(ctx, ac)
				if revErr != nil {
					p.logf("Reviewer error: %v\n", revErr)
					break
				}
				switch decision {
				case hitl.Approve:
					// Answer accepted — move to next question.
				case hitl.Revise:
					// Rephrase: run the new question through the chain.
					p.logf("Rephrasing: %s\n", feedback)
					answer, sources, err = p.query(ctx, chain, feedback)
					if err != nil {
						p.logf("Error: %v\n", err)
						break
					}
					ac = hitl.AnswerContext{
						Question: feedback,
						Answer:   answer,
						Sources:  sources,
					}
					continue // re-present for review
				case hitl.Abort:
					fmt.Fprintln(os.Stderr, "Session ended.")
					return nil
				}
				break
			}
		} else {
			// No reviewer — just print the answer and sources.
			fmt.Fprintf(os.Stderr, "\n%s\n", answer)
			if len(sources) > 0 {
				fmt.Fprintln(os.Stderr, "\nSources:")
				for i, s := range sources {
					src, _ := s.Metadata["source"].(string)
					fmt.Fprintf(os.Stderr, "  %d. %s (score: %.2f)\n", i+1, src, s.Score)
				}
			}
			fmt.Fprintln(os.Stderr)
		}
	}

	return nil
}

// query runs a single question through the conversational retrieval QA chain
// and extracts the answer text and source documents.
func (p *Pipeline) query(
	ctx context.Context,
	chain chains.ConversationalRetrievalQA,
	question string,
) (string, []schema.Document, error) {
	input := map[string]any{"question": question}
	p.logf("[debug] chain.Call input keys: %v\n", mapKeys(input))

	result, err := chains.Call(ctx, chain, input)
	if err != nil {
		return "", nil, fmt.Errorf("chain call: %w", err)
	}

	p.logf("[debug] chain.Call output keys: %v\n", mapKeys(result))

	answer, _ := result["text"].(string)

	var sources []schema.Document
	if raw, ok := result["source_documents"]; ok {
		if docs, ok := raw.([]schema.Document); ok {
			sources = docs
			p.logf("[debug] retrieved %d source document(s)\n", len(sources))
		}
	}

	return strings.TrimSpace(answer), sources, nil
}

// mapKeys returns the keys of a map for debug logging.
func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// lineScanner returns a bufio.Scanner for reading lines from r.
func lineScanner(r io.Reader) *bufio.Scanner {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	return s
}
