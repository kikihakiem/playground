package loader

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/tmc/langchaingo/documentloaders"
	"github.com/tmc/langchaingo/schema"
)

// GoLoader walks a directory tree and loads all .go files as Documents.
// It uses langchaingo's Text document loader under the hood.
type GoLoader struct {
	Root        string // root directory to walk
	SkipTests   bool   // skip _test.go files
	SkipVendor  bool   // skip vendor/ directories
}

// Load walks the directory tree and returns a Document per .go file.
// Each document carries metadata: "source" (file path) and "package" (parsed
// from the first line).
func (l *GoLoader) Load(ctx context.Context) ([]schema.Document, error) {
	var docs []schema.Document

	err := filepath.WalkDir(l.Root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories we don't care about.
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" {
				return filepath.SkipDir
			}
			if l.SkipVendor && name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}

		// Only .go files.
		if !strings.HasSuffix(path, ".go") {
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

		// Use langchaingo's Text loader to read the file content.
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
			loaded[i].Metadata["package"] = parsePackageName(loaded[i].PageContent)
			loaded[i].Metadata["is_test"] = strings.HasSuffix(path, "_test.go")
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
