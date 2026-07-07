package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ofaruk/mcp-x-ray/internal/diff"
	"github.com/ofaruk/mcp-x-ray/internal/llmreview"
	"github.com/ofaruk/mcp-x-ray/internal/parser"
	"github.com/ofaruk/mcp-x-ray/internal/report"
	"github.com/ofaruk/mcp-x-ray/internal/rules"
	"github.com/ofaruk/mcp-x-ray/internal/sandbox"
)

type scanOptions struct {
	format         string
	output         string
	timeout        time.Duration
	runtime        bool
	runtimeTimeout time.Duration
	llmVerify      bool
	llmEndpoint    string
	llmModel       string
	llmTimeout     time.Duration
}

func newScanCmd() *cobra.Command {
	var opts scanOptions

	cmd := &cobra.Command{
		Use:   "scan <target-dir>",
		Short: "Scan an MCP server's declared tools, prompts, and resources",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(args[0], opts)
		},
	}

	cmd.Flags().StringVar(&opts.format, "format", "json", "output format: json|sarif")
	cmd.Flags().StringVar(&opts.output, "output", "", "write report to this file instead of stdout")
	cmd.Flags().DurationVar(&opts.timeout, "timeout", 10*time.Second, "time to wait for the server to respond during introspection")
	cmd.Flags().BoolVar(&opts.runtime, "runtime", false, "also run the sandboxed runtime pass (requires Docker)")
	cmd.Flags().DurationVar(&opts.runtimeTimeout, "runtime-timeout", 60*time.Second, "time budget for the sandboxed runtime pass")
	cmd.Flags().BoolVar(&opts.llmVerify, "llm-verify", false, "double-check ambiguous static findings against a local Ollama model (requires Ollama)")
	cmd.Flags().StringVar(&opts.llmEndpoint, "llm-endpoint", llmreview.DefaultEndpoint, "Ollama endpoint for --llm-verify")
	cmd.Flags().StringVar(&opts.llmModel, "llm-model", llmreview.DefaultModel, "Ollama model for --llm-verify")
	cmd.Flags().DurationVar(&opts.llmTimeout, "llm-timeout", 60*time.Second, "time budget for the whole --llm-verify pass")

	return cmd
}

func runScan(targetPath string, opts scanOptions) error {
	target, err := resolveTarget(targetPath)
	if err != nil {
		return err
	}

	started := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	manifest, err := parser.FetchManifest(ctx, target)
	cancel()
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", targetPath, err)
	}
	manifest.PackageRef = inferPackageRef(target.Command, target.Args)

	findings := rules.Default().Run(manifest)
	capabilityDiffs := []report.CapabilityDiff{}

	if opts.runtime {
		runtimeCtx, runtimeCancel := context.WithTimeout(context.Background(), opts.runtimeTimeout)
		result, err := sandbox.Run(runtimeCtx, target, manifest)
		runtimeCancel()
		if err != nil {
			return fmt.Errorf("runtime pass (requires Docker): %w", err)
		}
		obs := sandbox.ParseTrace(result.TraceLog)
		var runtimeFindings []report.Finding
		capabilityDiffs, runtimeFindings = diff.Compare(manifest, obs)
		findings = append(findings, runtimeFindings...)
	}

	var llmSummary *report.LLMVerification
	if opts.llmVerify {
		llmSummary = runLLMVerify(&findings, manifest, opts)
	}

	rpt := &report.Report{
		Scan: report.ScanMeta{
			Target:          targetPath,
			Source:          "local",
			Transport:       "stdio",
			StartedAt:       started,
			DurationMs:      time.Since(started).Milliseconds(),
			RiskScore:       report.RiskScore(findings),
			LLMVerification: llmSummary,
		},
		Findings:       findings,
		CapabilityDiff: capabilityDiffs,
	}

	w := os.Stdout
	if opts.output != "" {
		f, err := os.Create(opts.output)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	switch opts.format {
	case "json":
		return report.WriteJSON(w, rpt)
	case "sarif":
		return report.WriteSARIF(w, rpt)
	default:
		return fmt.Errorf("unknown format %q (want json or sarif)", opts.format)
	}
}

// runLLMVerify runs the optional LLM double-check pass, failing open: if
// Ollama isn't reachable, it warns on stderr and leaves findings untouched
// rather than aborting a scan that otherwise succeeded.
func runLLMVerify(findings *[]report.Finding, manifest *parser.Manifest, opts scanOptions) *report.LLMVerification {
	client := llmreview.New(opts.llmEndpoint, opts.llmModel)

	llmCtx, llmCancel := context.WithTimeout(context.Background(), opts.llmTimeout)
	defer llmCancel()

	if err := client.Ping(llmCtx); err != nil {
		fmt.Fprintf(os.Stderr, "llm-verify: Ollama unreachable at %s, skipping verification: %v\n", opts.llmEndpoint, err)
		return nil
	}

	kept, summary := llmreview.Verify(llmCtx, client, *findings, manifest, os.Stderr)
	*findings = kept
	return &summary
}
