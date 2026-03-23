package splitter

import (
	"github.com/tmc/langchaingo/textsplitter"
)

// NewGoSplitter returns a RecursiveCharacter text splitter configured with
// Go-aware separators. It splits at function/type boundaries first, then
// falls back to blank lines, single newlines, and spaces.
//
// This is a thin wrapper — the real value is the separator list which keeps
// Go functions intact when possible.
func NewGoSplitter(chunkSize, chunkOverlap int) textsplitter.RecursiveCharacter {
	if chunkSize <= 0 {
		chunkSize = 1500
	}
	if chunkOverlap <= 0 {
		chunkOverlap = 200
	}

	return textsplitter.NewRecursiveCharacter(
		textsplitter.WithSeparators([]string{
			"\nfunc ",  // function boundaries (strongest split)
			"\ntype ",  // type declarations
			"\n\n",     // blank lines (paragraph-level)
			"\n",       // single newlines
			" ",        // word boundaries
			"",         // character-level (last resort)
		}),
		textsplitter.WithChunkSize(chunkSize),
		textsplitter.WithChunkOverlap(chunkOverlap),
	)
}
