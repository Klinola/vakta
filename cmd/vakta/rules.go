package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/vakta-project/vakta/internal/engine"
	"github.com/vakta-project/vakta/internal/normalizer"
)

func newRulesCmd() *cobra.Command {
	c := &cobra.Command{Use: "rules", Short: "Manage rules"}
	c.AddCommand(newRulesLintCmd())
	c.AddCommand(newRulesTestCmd())
	return c
}

func newRulesLintCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lint <file>",
		Short: "Validate rule YAML and CEL compilation",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			path := args[0]
			info, err := os.Stat(path)
			if err != nil {
				return err
			}
			dir := path
			if !info.IsDir() {
				dir = filepath.Dir(path)
				if other := otherYamlSiblings(dir, path); len(other) > 0 {
					return fmt.Errorf("rules lint expects a single-file dir; siblings present: %v", other)
				}
			}
			_, err = engine.New([]string{dir})
			if err != nil {
				return err
			}
			fmt.Fprintln(c.OutOrStdout(), "OK")
			return nil
		},
	}
}

func newRulesTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test <file> <event-json>",
		Short: "Evaluate a rule file against a single event",
		Args:  cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			path := args[0]
			info, err := os.Stat(path)
			if err != nil {
				return err
			}
			dir := path
			if !info.IsDir() {
				dir = filepath.Dir(path)
				if other := otherYamlSiblings(dir, path); len(other) > 0 {
					return fmt.Errorf("rules test expects a single-file dir; siblings present: %v", other)
				}
			}
			e, err := engine.New([]string{dir})
			if err != nil {
				return err
			}
			var ev normalizer.Event
			if err := json.Unmarshal([]byte(args[1]), &ev); err != nil {
				return fmt.Errorf("parse event-json: %w", err)
			}
			ms := e.Evaluate(ev)
			b, _ := json.MarshalIndent(map[string]any{"matches": ms}, "", "  ")
			fmt.Fprintln(c.OutOrStdout(), string(b))
			return nil
		},
	}
}

func otherYamlSiblings(dir, exclude string) []string {
	es, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range es {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if filepath.Ext(n) == ".yaml" || filepath.Ext(n) == ".yml" {
			full := filepath.Join(dir, n)
			if full != exclude {
				out = append(out, full)
			}
		}
	}
	return out
}
