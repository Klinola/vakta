package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "vakta",
		Short: "vakta — Linux runtime event-processing agent",
	}
	root.AddCommand(newAgentCmd())
	root.AddCommand(newRulesCmd())
	root.AddCommand(newVersionCmd())
	return root
}
