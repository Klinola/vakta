package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is the build version, overridable at link time:
//   go build -ldflags "-X main.Version=v0.3.0"
var Version = "dev"

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(c *cobra.Command, _ []string) {
			fmt.Fprintf(c.OutOrStdout(), "vakta %s\n", Version)
		},
	}
}
