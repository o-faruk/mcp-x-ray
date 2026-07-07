package main

import "github.com/spf13/cobra"

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcpxray",
		Short: "Offline security scanner for MCP servers",
	}
	cmd.AddCommand(newScanCmd())
	return cmd
}
