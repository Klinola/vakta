package engine

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Rule is the YAML-decoded form of a single policy.
type Rule struct {
	ID        string   `yaml:"id"`
	Name      string   `yaml:"name"`
	Severity  string   `yaml:"severity"`
	Source    string   `yaml:"source"`
	EventType string   `yaml:"event_type"`
	Condition string   `yaml:"condition"`
	Tags      []string `yaml:"tags"`
	ActionID  string   `yaml:"action_id"`
}

type ruleFile struct {
	Rules []Rule `yaml:"rules"`
}

// loadRulesFromDir reads every *.yaml in dir (non-recursive) and returns all rules.
// Returns empty slice (no error) if dir doesn't exist.
func loadRulesFromDir(dir string) ([]Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("readdir %s: %w", dir, err)
	}
	var out []Rule
	for _, e := range entries {
		if e.IsDir() || (filepath.Ext(e.Name()) != ".yaml" && filepath.Ext(e.Name()) != ".yml") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var rf ruleFile
		if err := yaml.Unmarshal(b, &rf); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out = append(out, rf.Rules...)
	}
	return out, nil
}

// severityOrder gives a sort weight (lower = higher priority).
func severityOrder(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "warning":
		return 2
	case "info":
		return 3
	default:
		return 99
	}
}
