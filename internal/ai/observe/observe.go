package observe

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Observer runs the OBSERVE phase against a codebase.
// It walks source files, parses ASTs, and extracts security-relevant sections.
type Observer struct {
	parser   *Parser
	maxFiles int // 0 = unlimited
}

// NewObserver creates an Observer with default security patterns.
func NewObserver() *Observer {
	return &Observer{
		parser: DefaultPatternParser(),
	}
}

// NewObserverWithPatterns creates an Observer with custom patterns.
func NewObserverWithPatterns(patterns []SecurityPattern) *Observer {
	return &Observer{
		parser: NewParser(patterns),
	}
}

// DefaultPatternParser returns a Parser configured with all built-in patterns.
func DefaultPatternParser() *Parser {
	return NewParser(DefaultPatterns())
}

// SetMaxFiles limits the number of files processed (0 = unlimited).
func (o *Observer) SetMaxFiles(n int) {
	o.maxFiles = n
}

// Observe runs the OBSERVE phase on a target directory.
// Auto-detects language: Go (native AST) or Python (subprocess).
// Returns structured results for downstream TRACE phase.
func (o *Observer) Observe(target string) (*ObserveResult, error) {
	// Collect Go files
	goFiles, _ := collectGoFiles(target, o.maxFiles)
	// Collect Python files
	pyFiles, _ := collectPyFiles(target, o.maxFiles)

	if len(goFiles) == 0 && len(pyFiles) == 0 {
		return &ObserveResult{}, nil
	}

	var (
		allSections []ObservedSection
		errs        []string
		totalFiles  int
	)

	// Go analysis
	if len(goFiles) > 0 {
		totalFiles += len(goFiles)
		sections, goErrs := o.parseGoFiles(goFiles)
		allSections = append(allSections, sections...)
		errs = append(errs, goErrs...)
	}

	// Python analysis
	if len(pyFiles) > 0 {
		totalFiles += len(pyFiles)
		sections, pyErrs := o.parsePyFiles(pyFiles)
		allSections = append(allSections, sections...)
		errs = append(errs, pyErrs...)
	}

	result := buildResult(allSections)
	result.TotalFiles = totalFiles

	// Build cross-file call graph for Go projects (v4.1)
	if len(goFiles) > 0 {
		cg, cgErr := BuildCallGraph(target)
		if cgErr != nil {
			errs = append(errs, fmt.Sprintf("callgraph: %v", cgErr))
		} else {
			result.CallGraph = cg
		}
	}

	if len(errs) > 0 {
		return result, fmt.Errorf("observe: %d parse errors (first: %s)", len(errs), errs[0])
	}
	return result, nil
}

// parseGoFiles processes Go files in parallel.
func (o *Observer) parseGoFiles(files []string) ([]ObservedSection, []string) {
	var (
		allSections []ObservedSection
		mu          sync.Mutex
		wg          sync.WaitGroup
		errs        []string
		sem         = make(chan struct{}, 8)
	)

	for _, f := range files {
		wg.Add(1)
		go func(filePath string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			sections, err := o.parser.ParseFile(filePath, nil)
			if err != nil {
				mu.Lock()
				errs = append(errs, filePath+": "+err.Error())
				mu.Unlock()
				return
			}
			if len(sections) > 0 {
				mu.Lock()
				allSections = append(allSections, sections...)
				mu.Unlock()
			}
		}(f)
	}
	wg.Wait()
	return allSections, errs
}

// parsePyFiles processes Python files via subprocess.
func (o *Observer) parsePyFiles(files []string) ([]ObservedSection, []string) {
	po := NewPythonObserver()
	var allSections []ObservedSection
	var errs []string

	for _, f := range files {
		result, err := po.ObserveFile(f)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		allSections = append(allSections, result.Sections...)
	}
	return allSections, errs
}

// ObserveFiles runs OBSERVE on specific Go source files.
func (o *Observer) ObserveFiles(files []string) (*ObserveResult, error) {
	var allSections []ObservedSection

	for _, f := range files {
		sections, err := o.parser.ParseFile(f, nil)
		if err != nil {
			continue
		}
		allSections = append(allSections, sections...)
	}

	result := buildResult(allSections)
	return result, nil
}

// ObserveDiff runs OBSERVE only on files that changed between two git refs.
// changedFiles should be the output of `git diff --name-only base HEAD`.
func (o *Observer) ObserveDiff(target string, changedFiles []string) (*ObserveResult, error) {
	var goFiles []string
	for _, cf := range changedFiles {
		if strings.HasSuffix(cf, ".go") && !strings.HasSuffix(cf, "_test.go") {
			fullPath := filepath.Join(target, cf)
			if _, err := os.Stat(fullPath); err == nil {
				goFiles = append(goFiles, fullPath)
			}
		}
	}

	if len(goFiles) == 0 {
		return &ObserveResult{}, nil
	}

	return o.ObserveFiles(goFiles)
}

// --- internals ---

// collectGoFiles finds all .go files (excluding tests) in a directory tree.
func collectGoFiles(target string, maxFiles int) ([]string, error) {
	var files []string

	err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == "vendor" || base == ".git" || base == "testdata" ||
				strings.HasPrefix(base, ".") || base == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		base := filepath.Base(path)
		if !strings.HasSuffix(base, ".go") || strings.HasSuffix(base, "_test.go") {
			return nil
		}
		files = append(files, path)
		if maxFiles > 0 && len(files) >= maxFiles {
			return filepath.SkipAll
		}
		return nil
	})

	return files, err
}

// collectPyFiles finds all .py files (excluding tests) in a directory tree.
func collectPyFiles(target string, maxFiles int) ([]string, error) {
	var files []string
	err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == "vendor" || base == ".git" || base == "testdata" ||
				base == "venv" || base == ".venv" || base == "__pycache__" ||
				strings.HasPrefix(base, ".") || base == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		base := filepath.Base(path)
		if !strings.HasSuffix(base, ".py") || strings.HasSuffix(base, "_test.py") || strings.HasPrefix(base, "test_") {
			return nil
		}
		files = append(files, path)
		if maxFiles > 0 && len(files) >= maxFiles {
			return filepath.SkipAll
		}
		return nil
	})
	return files, err
}

// buildResult creates an ObserveResult from collected sections.
func buildResult(sections []ObservedSection) *ObserveResult {
	// Sort by severity heuristic: more concerns + isHandler = more interesting
	sort.Slice(sections, func(i, j int) bool {
		si, sj := sections[i], sections[j]
		// Handlers first
		if si.IsHandler != sj.IsHandler {
			return si.IsHandler
		}
		// More concerns = more interesting
		if len(si.Concerns) != len(sj.Concerns) {
			return len(si.Concerns) > len(sj.Concerns)
		}
		// By file path, then line
		if si.FilePath != sj.FilePath {
			return si.FilePath < sj.FilePath
		}
		return si.LineStart < sj.LineStart
	})

	// Count concerns
	concernCounts := make(map[ConcernType]int)
	totalFuncs := 0
	for _, s := range sections {
		for _, c := range s.Concerns {
			concernCounts[c]++
		}
		totalFuncs++
	}

	return &ObserveResult{
		Sections:      sections,
		TotalFiles:    0, // set by caller
		TotalFuncs:    totalFuncs,
		TotalSections: len(sections),
		ConcernCounts: concernCounts,
	}
}

// --- result helpers ---

// Summary returns a human-readable summary of observe results.
func (r *ObserveResult) Summary() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("OBSERVE: %d files → %d sections\n", r.TotalFiles, r.TotalSections))

	// Sort concern counts by frequency
	type kv struct {
		k ConcernType
		v int
	}
	var sorted []kv
	for k, v := range r.ConcernCounts {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].v > sorted[j].v
	})

	for _, item := range sorted {
		sb.WriteString(fmt.Sprintf("  %-20s %d\n", item.k, item.v))
	}
	return sb.String()
}

// PrioritySections returns sections with the most security concerns first,
// limited to top N.
func (r *ObserveResult) PrioritySections(n int) []ObservedSection {
	if n >= len(r.Sections) {
		return r.Sections
	}
	return r.Sections[:n]
}

// HandlerSections returns only HTTP handler sections.
func (r *ObserveResult) HandlerSections() []ObservedSection {
	var handlers []ObservedSection
	for _, s := range r.Sections {
		if s.IsHandler {
			handlers = append(handlers, s)
		}
	}
	return handlers
}

// SectionsByConcern returns sections matching a specific concern type.
func (r *ObserveResult) SectionsByConcern(c ConcernType) []ObservedSection {
	var matched []ObservedSection
	for _, s := range r.Sections {
		for _, sc := range s.Concerns {
			if sc == c {
				matched = append(matched, s)
				break
			}
		}
	}
	return matched
}
