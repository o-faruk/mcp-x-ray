package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ofaruk/mcp-x-ray/internal/diff"
	"github.com/ofaruk/mcp-x-ray/internal/parser"
	"github.com/ofaruk/mcp-x-ray/internal/report"
	"github.com/ofaruk/mcp-x-ray/internal/rules"
	"github.com/ofaruk/mcp-x-ray/internal/sandbox"
)

func newScanCmd() *cobra.Command {
	var format string
	var output string
	var timeout time.Duration
	var runtime bool
	var runtimeTimeout time.Duration

	cmd := &cobra.Command{
		Use:   "scan <target-dir>",
		Short: "Scan an MCP server's declared tools, prompts, and resources",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(args[0], format, output, timeout, runtime, runtimeTimeout)
		},
	}

	cmd.Flags().StringVar(&format, "format", "json", "output format: json|sarif")
	cmd.Flags().StringVar(&output, "output", "", "write report to this file instead of stdout")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "time to wait for the server to respond during introspection")
	cmd.Flags().BoolVar(&runtime, "runtime", false, "also run the sandboxed runtime pass (requires Docker)")
	cmd.Flags().DurationVar(&runtimeTimeout, "runtime-timeout", 60*time.Second, "time budget for the sandboxed runtime pass")

	return cmd
}

func runScan(targetPath, format, output string, timeout time.Duration, runtime bool, runtimeTimeout time.Duration) error {
	target, err := resolveTarget(targetPath)
	if err != nil {
		return err
	}

	started := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	manifest, err := parser.FetchManifest(ctx, target)
	cancel()
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", targetPath, err)
	}
	manifest.PackageRef = inferPackageRef(target.Command, target.Args)

	findings := rules.Default().Run(manifest)
	capabilityDiffs := []report.CapabilityDiff{}

	if runtime {
		runtimeCtx, runtimeCancel := context.WithTimeout(context.Background(), runtimeTimeout)
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

	rpt := &report.Report{
		Scan: report.ScanMeta{
			Target:     targetPath,
			Source:     "local",
			Transport:  "stdio",
			StartedAt:  started,
			DurationMs: time.Since(started).Milliseconds(),
			RiskScore:  report.RiskScore(findings),
		},
		Findings:       findings,
		CapabilityDiff: capabilityDiffs,
	}

	w := os.Stdout
	if output != "" {
		f, err := os.Create(output)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	switch format {
	case "json":
		return report.WriteJSON(w, rpt)
	case "sarif":
		return report.WriteSARIF(w, rpt)
	default:
		return fmt.Errorf("unknown format %q (want json or sarif)", format)
	}
}
