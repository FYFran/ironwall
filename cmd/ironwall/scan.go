package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/FYFran/ironwall/internal/ai"
	"github.com/FYFran/ironwall/internal/config"
	"github.com/FYFran/ironwall/internal/pipeline"
	"github.com/FYFran/ironwall/internal/report"
)

func newScanCmd() *cobra.Command {
	var (
		outputFormat string
		outputFile   string
		quickMode    bool
		fullMode     bool
		noColor      bool
		verbose      bool
		aiEnabled     bool
		aiModel       string
		timeout       int
		deepAnalysis  bool
	deepStrict   bool
	)

	cmd := &cobra.Command{
		Use:   "scan [target]",
		Short: "Run multi-scanner security audit on a target directory",
		Long: `Run the 8-step security audit pipeline (semgrep + gosec + bandit + gitleaks + more).

By default all steps run locally. Use --ai to enable AI noise filtering (requires DEEPSEEK_API_KEY).
Use --deep to enable AI-powered deep analysis (OBSERVE→TRACE→VERIFY) that finds vulnerabilities SAST misses.
Use --quick for a fast scan (secrets + hardcoded patterns only).

Examples:
  ironwall scan .
  ironwall scan ./my-project --ai --format markdown
  ironwall scan ./my-project --ai --deep
  ironwall scan /path/to/code --quick --format json`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) > 0 {
				target = args[0]
			}

			cfg := config.Defaults()
			cfg.Target = target
			cfg.OutputFormat = outputFormat
			cfg.OutputFile = outputFile
			cfg.QuickMode = quickMode
			cfg.FullMode = fullMode
			cfg.NoColor = noColor
			cfg.Verbose = verbose
			cfg.AIEnabled = aiEnabled
			cfg.AIModel = aiModel
			cfg.TimeoutSeconds = timeout
			cfg.DeepAnalysis = deepAnalysis
			cfg.DeepStrict = deepStrict
			cfg.ResolveAIKey()

			// When --deep is active, ensure timeout is long enough for Phase B AI pipeline.
			// Phase B runs OBSERVE→TRACE→VERIFY→MISSING→CONFIG, each making multiple API calls.
			// DeepSeek R1 can take 60-180s per call. Default: 900s (15 min) for deep mode.
			if cfg.DeepAnalysis && cfg.TimeoutSeconds < 900 {
				log.Printf("Deep analysis requires longer timeout. Overriding %ds → 900s (use --timeout to set higher).",
					cfg.TimeoutSeconds)
				cfg.TimeoutSeconds = 900
			}

			return runScan(cfg)
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "format", "f", "terminal", "Report format: terminal, markdown, json, html, sarif, agent-report")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path (auto-generated if empty)")
	cmd.Flags().BoolVar(&quickMode, "quick", false, "Quick scan: only steps 1+4 (gitleaks + hardcoded secrets)")
	cmd.Flags().BoolVar(&fullMode, "full", true, "Full scan: all 7 steps (default)")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	cmd.Flags().BoolVar(&aiEnabled, "ai", false, "Enable AI-assisted analysis (requires IRONWALL_AI_KEY or DEEPSEEK_API_KEY)")
	cmd.Flags().StringVar(&aiModel, "ai-model", "deepseek-chat", "AI model to use")
	cmd.Flags().IntVar(&timeout, "timeout", 300, "Scan timeout in seconds")
	cmd.Flags().BoolVar(&deepAnalysis, "deep", false, "Enable AI deep analysis: AST inspection + LLM data flow tracing (requires --ai)")
	cmd.Flags().BoolVar(&deepStrict, "deep-strict", false, "Only report CRITICAL+HIGH Phase B findings (reduces noise)")

	return cmd
}

func newQuickCmd() *cobra.Command {
	var formatFlag, outputFlag string

	cmd := &cobra.Command{
		Use:   "quick [target]",
		Short: "Quick scan: gitleaks + hardcoded secrets only (< 30s)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) > 0 {
				target = args[0]
			}

			cfg := config.Defaults()
			cfg.Target = target
			cfg.QuickMode = true
			cfg.FullMode = false
			cfg.TimeoutSeconds = 60
			cfg.OutputFormat = formatFlag
			cfg.OutputFile = outputFlag
			cfg.ResolveAIKey()

			return runScan(cfg)
		},
	}

	cmd.Flags().StringVarP(&formatFlag, "format", "f", "terminal", "Output format: terminal, markdown, json, sarif")
	cmd.Flags().StringVarP(&outputFlag, "output", "o", "", "Output file path")

	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("ironwall v%s\n", config.Version)
			fmt.Println("7-Step Security Audit CLI — https://github.com/FYFran/ironwall")
		},
	}
}

// detectLanguages checks whether the target directory contains Go and/or Python source files.
func detectLanguages(target string) (hasGo, hasPython bool) {
	filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".go":
			hasGo = true
		case ".py":
			hasPython = true
		}
		if hasGo && hasPython {
			return filepath.SkipAll // both found, stop walking
		}
		return nil
	})
	return
}

func runScan(cfg *config.Config) error {
	// Build AI engine if enabled (dual-model: triage + deep verify)
	var engine *ai.Engine
	if cfg.AIEnabled && cfg.AIKey != "" {
		triageClient := ai.NewClient(cfg.AIEndpoint, cfg.AIKey, cfg.AIModel)
		deepClient := ai.NewClient(cfg.AIEndpoint, cfg.AIKey, cfg.AIDeepModel)
		engine = ai.NewEngine(triageClient, deepClient)

		// Auto-detect target languages for conditional prompt rules
		hasGo, hasPython := detectLanguages(cfg.Target)
		engine.SetLanguages(hasGo, hasPython)
	}

	// Build pipeline
	pipe := pipeline.New(cfg)

	// Register steps based on mode
	if cfg.QuickMode {
		pipe.Register(&pipeline.Step1Secrets{})
		pipe.Register(pipeline.NewStep4Hardcoded(engine))
	} else {
		pipe.Register(&pipeline.Step1Secrets{})
		pipe.Register(pipeline.NewStep2SAST(engine))
		pipe.Register(pipeline.NewStep3Endpoints(engine))
		pipe.Register(pipeline.NewStep4Hardcoded(engine))
		pipe.Register(&pipeline.Step5Deps{})
		pipe.Register(&pipeline.Step6Server{})
		pipe.Register(&pipeline.Step7Database{})
		pipe.Register(&pipeline.Step8SupplyChain{})
		pipe.Register(pipeline.NewStep9Missing(engine))
	}

	// Handle interrupt signal
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.TimeoutSeconds)*time.Second)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Println("\n⚠ Interrupted. Generating partial report...")
		cancel()
	}()

	// Run pipeline
	result, err := pipe.Run(ctx, cfg.Target)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Phase B: AI deep analysis (OBSERVE→TRACE→VERIFY→MISSING→CONFIG)
	if cfg.DeepAnalysis && engine != nil && engine.Available() {
		log.Println("\n--- Phase B: AI Deep Analysis ---")
		deepResult, deepErr := engine.AnalyzeDeep(ctx, cfg.Target)
		if deepErr != nil {
			log.Printf("Deep analysis error: %v", deepErr)
		} else if deepResult != nil {
			newCount := 0
			if len(deepResult.Verified) > 0 {
				aiFindings := engine.ConvertToFindings(deepResult.Verified)
				for i := range aiFindings {
					aiFindings[i].Step = 9
					result.Findings = append(result.Findings, aiFindings[i])
				}
				newCount += len(aiFindings)
			}
			if len(deepResult.MissingCtrls) > 0 {
				missFindings := engine.ConvertMissingToFindings(deepResult.MissingCtrls)
				for i := range missFindings {
					missFindings[i].Step = 9
					result.Findings = append(result.Findings, missFindings[i])
				}
				newCount += len(missFindings)
			}
			if len(deepResult.ConfigIssues) > 0 {
				cfgFindings := engine.ConvertConfigToFindings(deepResult.ConfigIssues)
				for i := range cfgFindings {
					cfgFindings[i].Step = 9
					result.Findings = append(result.Findings, cfgFindings[i])
				}
				newCount += len(cfgFindings)
			}
			// Dedup Phase B findings against SAST findings
			beforeDedup := newCount
			phaseBStart := len(result.Findings) - newCount
			if phaseBStart >= 0 && phaseBStart < len(result.Findings) {
				phaseBOnly := result.Findings[phaseBStart:]
				uniqueOnly := ai.DeduplicatePhaseB(phaseBOnly, result.Findings[:phaseBStart])
				result.Findings = result.Findings[:phaseBStart]
				result.Findings = append(result.Findings, uniqueOnly...)
				newCount = len(uniqueOnly)
				log.Printf("AI dedup: %d PhaseB -> %d unique (%d SAST overlaps)", beforeDedup, newCount, beforeDedup-newCount)
			}
			// --deep-strict: only report CRITICAL+HIGH Phase B findings
			if cfg.DeepStrict {
				phaseBStart := len(result.Findings) - newCount
				var filtered []report.Finding
				for _, f := range result.Findings[phaseBStart:] {
					if f.Severity <= 1 { // CRITICAL(0) or HIGH(1)
						filtered = append(filtered, f)
					}
				}
				if len(filtered) < newCount {
					result.Findings = result.Findings[:phaseBStart]
					result.Findings = append(result.Findings, filtered...)
					log.Printf("AI strict: %d -> %d (CRITICAL+HIGH only)", newCount, len(filtered))
					newCount = len(filtered)
				}
			}
			log.Printf("AI deep analysis: %d unique findings (%d trace, %d missing, %d config)",
				newCount, len(deepResult.Verified), len(deepResult.MissingCtrls), len(deepResult.ConfigIssues))
			log.Printf("AI cost: %s", deepResult.Cost)
		}
	}

	// Generate report
	switch cfg.OutputFormat {
	case "json":
		return report.WriteJSON(result, cfg)
	case "markdown":
		return report.WriteMarkdown(result, cfg)
	case "html":
		return report.WriteHTML(result, cfg)
	case "sarif":
		return report.WriteSARIF(result, cfg)
	case "agent-report":
		return report.WriteAgentReport(result, cfg)
	default:
		report.PrintTerminal(result, cfg)
		if cfg.OutputFile != "" || cfg.OutputFormat == "markdown" {
			return report.WriteMarkdown(result, cfg)
		}
	}
	return nil
}
