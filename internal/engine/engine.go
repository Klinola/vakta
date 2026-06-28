package engine

import (
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/google/cel-go/cel"

	"gopkg.in/yaml.v3"

	"github.com/Klinola/vakta/internal/normalizer"
)

//go:embed builtin_rules/*.yaml
var builtinRulesFS embed.FS

// Match is produced when a rule's condition evaluates true for an Event.
type Match struct {
	Rule  Rule
	Event normalizer.Event
	At    time.Time
}

// Engine loads rules, compiles CEL programs, evaluates events.
type Engine struct {
	ruleDirs []string
	env      *cel.Env

	mu       sync.RWMutex
	rules    []Rule
	programs map[string]cel.Program // keyed by rule ID
}

// New loads rules from ruleDirs (built-in dir first, then user dirs).
// Compiles all CEL conditions; returns error if any fail.
func New(ruleDirs []string) (*Engine, error) {
	env, err := NewCELEnv()
	if err != nil {
		return nil, fmt.Errorf("cel env: %w", err)
	}
	e := &Engine{ruleDirs: ruleDirs, env: env}
	if err := e.load(); err != nil {
		return nil, err
	}
	return e, nil
}

// load reads built-in rules (embedded) then user dirs (overrides by id),
// compiles, and atomically swaps the rule set.
func (e *Engine) load() error {
	seen := map[string]int{}
	var all []Rule

	// 1) Built-in rules embedded in the binary.
	builtins, err := loadBuiltinRules()
	if err != nil {
		return fmt.Errorf("load builtin rules: %w", err)
	}
	for _, r := range builtins {
		seen[r.ID] = len(all)
		all = append(all, r)
	}

	// 2) User rules from disk; same-id user rules override built-in.
	for _, dir := range e.ruleDirs {
		rs, err := loadRulesFromDir(dir)
		if err != nil {
			return err
		}
		for _, r := range rs {
			if idx, ok := seen[r.ID]; ok {
				all[idx] = r
				continue
			}
			seen[r.ID] = len(all)
			all = append(all, r)
		}
	}
	progs := make(map[string]cel.Program, len(all))
	for _, r := range all {
		p, err := CELCompile(e.env, r.Condition)
		if err != nil {
			return fmt.Errorf("rule %s: %w", r.ID, err)
		}
		progs[r.ID] = p
	}
	e.mu.Lock()
	e.rules = all
	e.programs = progs
	e.mu.Unlock()
	return nil
}

// Reload re-reads rules from the same dirs.
func (e *Engine) Reload() error { return e.load() }

// Rules returns a copy of the currently loaded rule set.
func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

// Evaluate returns all matching rules for ev, ordered by severity then ID.
func (e *Engine) Evaluate(ev normalizer.Event) []Match {
	e.mu.RLock()
	rules := e.rules
	progs := e.programs
	e.mu.RUnlock()

	act := activationFor(ev)
	now := time.Now()
	var matches []Match
	for _, r := range rules {
		if r.EventType != "" && r.EventType != ev.Type {
			continue
		}
		if r.Source != "" && !sourceMatches(r.Source, ev.Source) {
			continue
		}
		prg, ok := progs[r.ID]
		if !ok {
			continue
		}
		out, _, err := prg.Eval(act)
		if err != nil {
			continue
		}
		if b, ok := out.Value().(bool); ok && b {
			matches = append(matches, Match{Rule: r, Event: ev, At: now})
		}
	}
	sort.SliceStable(matches, func(i, j int) bool {
		si, sj := severityOrder(matches[i].Rule.Severity), severityOrder(matches[j].Rule.Severity)
		if si != sj {
			return si < sj
		}
		return matches[i].Rule.ID < matches[j].Rule.ID
	})
	return matches
}

// loadBuiltinRules parses every yaml under the embedded builtin_rules dir.
func loadBuiltinRules() ([]Rule, error) {
	var out []Rule
	err := fs.WalkDir(builtinRulesFS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if ext := filepath.Ext(p); ext != ".yaml" && ext != ".yml" {
			return nil
		}
		b, err := builtinRulesFS.ReadFile(p)
		if err != nil {
			return err
		}
		var rf ruleFile
		if err := yaml.Unmarshal(b, &rf); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		out = append(out, rf.Rules...)
		return nil
	})
	return out, err
}

func sourceMatches(want string, got normalizer.Source) bool {
	switch want {
	case "ebpf":
		return got == normalizer.SourceEBPF
	case "auditd":
		return got == normalizer.SourceAuditd
	case "k8s_audit":
		return got == normalizer.SourceK8sAudit
	}
	return false
}
