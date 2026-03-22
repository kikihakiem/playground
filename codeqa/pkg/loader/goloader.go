package loader

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/tmc/langchaingo/documentloaders"
	"github.com/tmc/langchaingo/schema"
)

// Default file extensions to index.
var DefaultExtensions = []string{
	".go", ".md", ".txt", ".yaml", ".yml", ".json", ".toml", ".mod", ".sum",
}

// RepoLoader walks a directory tree and loads text-based files as Documents.
// By default it loads Go source and common project files (README, configs, etc.).
type RepoLoader struct {
	Root       string   // root directory to walk
	Extensions []string // file extensions to include (e.g. ".go", ".md"); nil = DefaultExtensions
	SkipTests  bool     // skip _test.go files
	SkipVendor bool     // skip vendor/ directories
}

// skipDirs are directory names that are always skipped.
var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"__pycache__":  true,
	".idea":        true,
	".vscode":      true,
}

// Load walks the directory tree and returns a Document per matched file.
// Each document carries metadata:
//   - "source":  relative file path
//   - "type":    file extension (e.g. ".go", ".md")
//   - "package": Go package name (only for .go files)
//   - "is_test": true for _test.go files
func (l *RepoLoader) Load(ctx context.Context) ([]schema.Document, error) {
	exts := l.Extensions
	if len(exts) == 0 {
		exts = DefaultExtensions
	}
	extSet := make(map[string]bool, len(exts))
	for _, e := range exts {
		extSet[e] = true
	}

	var docs []schema.Document

	err := filepath.WalkDir(l.Root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			if l.SkipVendor && d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}

		ext := filepath.Ext(path)
		// go.mod and go.sum have no extension — match on full filename.
		base := filepath.Base(path)
		if base == "go.mod" || base == "go.sum" {
			ext = "." + strings.TrimPrefix(base, "go.")
		}
		if !extSet[ext] {
			return nil
		}
		if l.SkipTests && strings.HasSuffix(path, "_test.go") {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		textLoader := documentloaders.NewText(f)
		loaded, err := textLoader.Load(ctx)
		if err != nil {
			return err
		}

		relPath, _ := filepath.Rel(l.Root, path)
		if relPath == "" {
			relPath = path
		}

		for i := range loaded {
			if loaded[i].Metadata == nil {
				loaded[i].Metadata = make(map[string]any)
			}
			loaded[i].Metadata["source"] = relPath
			loaded[i].Metadata["type"] = ext
			loaded[i].Metadata["is_test"] = strings.HasSuffix(path, "_test.go")

			// Go-specific metadata.
			if ext == ".go" {
				loaded[i].Metadata["package"] = parsePackageName(loaded[i].PageContent)
			} else {
				loaded[i].Metadata["package"] = ""
			}

			docs = append(docs, loaded[i])
		}

		return nil
	})

	return docs, err
}

// parsePackageName extracts the package name from the first "package xxx" line.
func parsePackageName(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "package"))
		}
	}
	return "unknown"
}
