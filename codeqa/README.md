# codeqa — RAG-powered Go Codebase Q&A

A CLI tool that indexes a Go repository and answers natural-language questions about the code using retrieval-augmented generation (RAG). Built as a hands-on learning project for [langchaingo](https://github.com/tmc/langchaingo).

## How It Works

```
.go files → Document Loader → Text Splitter → Embeddings → Vector Store
                                                                 │
                                              User Question ─────┤
                                                                 ▼
                                              Retriever → LLM → Answer
                                                                 │
                                                          HITL Review
```

1. **Index** — Walks a Go repo, loads each `.go` file as a document, splits at function/type boundaries, and embeds chunks into an in-memory vector store.
2. **Query** — Takes a natural-language question, retrieves the most relevant code chunks via cosine similarity, and feeds them to an LLM to generate an answer.
3. **HITL** — Two human-in-the-loop checkpoints pause the pipeline for review:
   - **Pre-index**: Approve/revise/abort after seeing file and chunk counts.
   - **Post-answer**: Accept the answer, rephrase the question, or exit.

## LangChain Concepts Covered

| Concept | Package | File |
|---|---|---|
| Document loaders | `documentloaders.NewText` | `pkg/loader/goloader.go` |
| Text splitters | `textsplitter.RecursiveCharacter` | `pkg/splitter/codesplitter.go` |
| Embeddings | `embeddings.NewEmbedder` | `cmd/codeqa/main.go` |
| Vector store | `vectorstores.VectorStore` (custom impl) | `pkg/vectorstore/inmemory.go` |
| Retrieval chain | `chains.NewConversationalRetrievalQAFromLLM` | `pkg/rag/pipeline.go` |
| Conversational memory | `memory.NewConversationBuffer` | `pkg/rag/pipeline.go` |

## Prerequisites

- Go 1.21+
- [Ollama](https://ollama.com/) running locally

Pull the required models:

```bash
ollama pull qwen2.5-coder:14b    # generation
ollama pull nomic-embed-text      # embeddings
```

## Usage

```bash
# Index the sibling langchain/ project and start interactive Q&A
go run ./codeqa/cmd/codeqa -repo ./langchain

# Use a different model
go run ./codeqa/cmd/codeqa -repo ./langchain -model llama3:8b

# Disable HITL checkpoints for faster iteration
go run ./codeqa/cmd/codeqa -repo ./langchain -no-hitl

# Skip test files, adjust chunk settings
go run ./codeqa/cmd/codeqa -repo ./langchain -skip-tests -chunk-size 2000 -chunk-overlap 300
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-repo` | `.` | Path to Go repository to index |
| `-model` | `qwen2.5-coder:14b` | Ollama model for generation |
| `-embed-model` | `nomic-embed-text` | Ollama model for embeddings |
| `-server` | `http://localhost:11434` | Ollama server URL |
| `-chunks` | `4` | Number of chunks to retrieve per query |
| `-no-hitl` | `false` | Disable human-in-the-loop checkpoints |
| `-skip-tests` | `false` | Skip `_test.go` files during indexing |
| `-chunk-size` | `1500` | Target chunk size in characters |
| `-chunk-overlap` | `200` | Overlap between chunks in characters |

## Project Structure

```
codeqa/
├── cmd/codeqa/
│   └── main.go              # CLI entry point, wires all components
├── pkg/
│   ├── loader/
│   │   └── goloader.go      # Walks repo, loads .go files via langchaingo Text loader
│   ├── splitter/
│   │   └── codesplitter.go  # Go-aware text splitter (splits at func/type boundaries)
│   ├── vectorstore/
│   │   └── inmemory.go      # In-memory VectorStore impl (cosine similarity)
│   ├── hitl/
│   │   └── reviewer.go      # Tri-state HITL: Approve / Revise / Abort
│   └── rag/
│       └── pipeline.go      # Orchestrates index + conversational Q&A loop
├── go.mod
└── README.md
```

## HITL Flow

Both checkpoints use a tri-state decision model:

- **Approve** — proceed (accept index / accept answer)
- **Revise** — adjust and retry (re-configure indexing / rephrase the question)
- **Abort** — stop immediately

This mirrors the pattern used in the sibling `langchain/` agentic project, where the same tri-state model gates requirement review, flip-flop escape hatches, and post-success compliance review.
