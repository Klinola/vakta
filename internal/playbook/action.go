// Package playbook executes response actions when rule matches fire.
package playbook

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Action is one named playbook (ordered sequence of steps).
type Action struct {
	ID     string `yaml:"id"`
	Name   string `yaml:"name"`
	DryRun bool   `yaml:"dry_run"`
	Steps  []Step `yaml:"steps"`
}

// Step is one action invocation.
type Step struct {
	ID        string         `yaml:"id"`
	Action    string         `yaml:"action"` // see handlers.go
	Params    map[string]any `yaml:"params"`
	Condition string         `yaml:"condition"`
}

type actionFile struct {
	Actions []Action `yaml:"actions"`
}

func loadActionsFromDir(dir string) ([]Action, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("readdir: %w", err)
	}
	var out []Action
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var f actionFile
		if err := yaml.Unmarshal(b, &f); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out = append(out, f.Actions...)
	}
	return out, nil
}
