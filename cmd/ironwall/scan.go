package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

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
		noTestFilter  bool
	)

	cmd := &cobra.Command{
		Use:   "scan [target]",
		Short: "Run security audit on a target directory",
		Long: `Run the full 7-step security audit pipeline on a target directory.
By default all 7 steps run. Use --quick for a fast scan (steps 1+4 only).

Examples:
  ironwall scan .
  ironwall scan ./my-project --format markdown
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
			cfg.NoTestFilter = noTestFilter
			cfg.ResolveAIKey()

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
	cmd.Flags().BoolVar(&noTestFilter, "no-test-filter", false, "Disable AI test-file heuristic (for benchmarks)")

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

func runScan(cfg *config.Config) error {
	// Build AI engine if enabled (dual-model: triage + deep verify)
	var engine *ai.Engine
	if cfg.AIEnabled && cfg.AIKey != "" {
		triageClient := ai.NewClient(cfg.AIEndpoint, cfg.AIKey, cfg.AIModel)
		deepClient := ai.NewClient(cfg.AIEndpoint, cfg.AIKey, cfg.AIDeepModel)
		engine = ai.NewEngine(triageClient, deepClient, cfg.NoTestFilter)
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
	}

	// Handle interrupt signal
	ctx, cancel := context.WithCancel(context.Background())
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
