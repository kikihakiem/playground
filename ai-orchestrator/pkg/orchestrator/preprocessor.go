package orchestrator

import (
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"sort"
	"strings"
)

// Preprocessor transforms Go source before each build attempt.
// Implementations must be safe to apply repeatedly — running the same
// preprocessor twice should produce the same result as running it once.
type Preprocessor interface {
	Process(code string) (string, error)
}

// ── ImportFixer ───────────────────────────────────────────────────────────────

// ImportFixer is a Preprocessor that automatically adds missing standard-library
// imports to generated Go source.
//
// How it works:
//  1. Parse the source with go/ast.
//  2. Collect all identifiers that the parser left unresolved — package names
//     from the import block are never locally declared, so they stay unresolved.
//  3. Walk every ast.SelectorExpr (pkg.Ident) whose left side is one of those
//     unresolved identifiers and whose name appears in the stdlib map.
//  4. Inject missing import paths into the source, then reformat with gofmt.
//
// Code that doesn't parse is returned unchanged so the build step can surface
// the syntax error to the LLM.
type ImportFixer struct{}

// Process implements Preprocessor.
func (ImportFixer) Process(code string) (string, error) {
	fixed, err := fixMissingImports(code)
	if err != nil {
		return code, err // return original on any error
	}
	return fixed, nil
}

// stdlibByName maps the package qualifier used in source (e.g. "http") to its
// full import path (e.g. "net/http").  Covers the stdlib packages that appear
// most often in LLM-generated Go code.
var stdlibByName = map[string]string{
	// Single-segment paths (package name == import path)
	"bufio":    "bufio",
	"bytes":    "bytes",
	"context":  "context",
	"errors":   "errors",
	"flag":     "flag",
	"fmt":      "fmt",
	"io":       "io",
	"log":      "log",
	"math":     "math",
	"net":      "net",
	"os":       "os",
	"path":     "path",
	"reflect":  "reflect",
	"regexp":   "regexp",
	"runtime":  "runtime",
	"sort":     "sort",
	"strconv":  "strconv",
	"strings":  "strings",
	"sync":     "sync",
	"testing":  "testing",
	"time":     "time",
	"unicode":  "unicode",
	// Multi-segment paths (package name is the last segment)
	"atomic":    "sync/atomic",
	"base64":    "encoding/base64",
	"big":       "math/big",
	"binary":    "encoding/binary",
	"bits":      "math/bits",
	"color":     "image/color",
	"csv":       "encoding/csv",
	"exec":      "os/exec",
	"filepath":  "path/filepath",
	"gob":       "encoding/gob",
	"gzip":      "compress/gzip",
	"heap":      "container/heap",
	"hex":       "encoding/hex",
	"http":      "net/http",
	"image":     "image",
	"ioutil":    "io/ioutil",
	"json":      "encoding/json",
	"list":      "container/list",
	"md5":       "crypto/md5",
	"pprof":     "runtime/pprof",
	"rand":      "math/rand",
	"rsa":       "crypto/rsa",
	"sha256":    "crypto/sha256",
	"sha512":    "crypto/sha512",
	"signal":    "os/signal",
	"slog":      "log/slog",
	"sql":       "database/sql",
	"tabwriter": "text/tabwriter",
	"tar":       "archive/tar",
	"template":  "text/template",
	"tls":       "crypto/tls",
	"url":       "net/url",
	"user":      "os/user",
	"utf8":      "unicode/utf8",
	"x509":      "crypto/x509",
	"xml":       "encoding/xml",
	"zip":       "archive/zip",
}

func fixMissingImports(src string) (string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", src, parser.ParseComments)
	if err != nil {
		// Code doesn't parse — return it unchanged so go build can surface the
		// syntax error to the judge.
		return src, nil
	}

	// Build a set of identifiers that the parser left unresolved.
	// Imported package names are never declared within the file, so they
	// always appear in f.Unresolved — this is the key to distinguishing
	// "package qualifier" from "local variable field access".
	unresolved := make(map[*ast.Ident]bool, len(f.Unresolved))
	for _, id := range f.Unresolved {
		unresolved[id] = true
	}

	// Collect names that are already imported (by alias or last-segment name).
	imported := make(map[string]bool, len(f.Imports))
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		name := path[strings.LastIndex(path, "/")+1:]
		if imp.Name != nil && imp.Name.Name != "_" && imp.Name.Name != "." {
			name = imp.Name.Name
		}
		imported[name] = true
	}

	// Walk every selector expression (pkg.Ident) where the left-hand side is
	// an unresolved identifier whose name maps to a known stdlib package.
	needed := make(map[string]bool)
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || !unresolved[id] || imported[id.Name] {
			return true
		}
		if _, known := stdlibByName[id.Name]; known {
			needed[id.Name] = true
		}
		return true
	})

	if len(needed) == 0 {
		return src, nil
	}

	// Build a sorted list of import paths for deterministic output.
	paths := make([]string, 0, len(needed))
	for name := range needed {
		paths = append(paths, stdlibByName[name])
	}
	sort.Strings(paths)

	// Inject the paths into the source text, then reformat.
	patched := injectImports(src, paths)
	formatted, fmtErr := format.Source([]byte(patched))
	if fmtErr != nil {
		// Formatting failed (unlikely if parsing passed), but the imports are
		// syntactically correct — return the unformatted patched source.
		return patched, nil
	}
	return string(formatted), nil
}

// injectImports adds paths to the first "import (...)" block in src.
// If no grouped import block exists, a new one is created after the
// "package" declaration line.
// importDiff returns the import paths present in after but not in before.
// Both inputs are Go source strings; unparseable input yields an empty result.
func importDiff(before, after string) []string {
	extract := func(src string) map[string]bool {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "", src, 0)
		if err != nil {
			return nil
		}
		m := make(map[string]bool, len(f.Imports))
		for _, imp := range f.Imports {
			m[strings.Trim(imp.Path.Value, `"`)] = true
		}
		return m
	}
	beforeSet := extract(before)
	afterSet := extract(after)
	var added []string
	for p := range afterSet {
		if !beforeSet[p] {
			added = append(added, p)
		}
	}
	sort.Strings(added)
	return added
}

func injectImports(src string, paths []string) string {
	var b strings.Builder
	for _, p := range paths {
		fmt.Fprintf(&b, "\t%q\n", p)
	}
	extra := b.String()

	// Case 1: existing grouped import block — insert before the closing ")".
	if blockStart := strings.Index(src, "import ("); blockStart >= 0 {
		if closeOff := strings.Index(src[blockStart:], ")"); closeOff >= 0 {
			ins := blockStart + closeOff
			return src[:ins] + extra + src[ins:]
		}
	}

	// Case 2: no grouped block — insert a new one after the package line.
	for i, ch := range src {
		if ch != '\n' {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(src[:i]), "package ") {
			return src[:i+1] + "\nimport (\n" + extra + ")\n" + src[i+1:]
		}
		break
	}
	return src
}
