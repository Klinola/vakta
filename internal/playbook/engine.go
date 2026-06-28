package playbook

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/cel-go/cel"

	"github.com/vakta-project/vakta/internal/alertmanager"
	"github.com/vakta-project/vakta/internal/engine"
	"github.com/vakta-project/vakta/internal/storage"
)

// EngineOptions configures playbook execution.
type EngineOptions struct {
	AllowExecRun bool // mirrors config.playbook.allow_exec_run
	DryRunGlobal bool // mirrors config.playbook.dry_run (overrides per-action dry_run=false)
}

// ActionRun is one execution record for an action.
type ActionRun struct {
	ActionID   string
	AlertID    int64
	DryRun     bool
	Status     string // completed | failed
	Steps      []StepResult
	StartedAt  time.Time
	FinishedAt time.Time
}

type StepResult struct {
	ID      string
	Skipped bool
	Output  string
	Err     string
}

// Engine loads action definitions and dispatches Run requests.
type Engine struct {
	mu       sync.RWMutex
	actions  map[string]Action
	store    *storage.DB
	celEnv   *cel.Env
	handlers *handlerCtx
	opts     EngineOptions
}

func New(actionDirs []string, store *storage.DB, am *alertmanager.Client, opts EngineOptions) (*Engine, error) {
	env, err := cel.NewEnv(
		cel.Variable("event", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, fmt.Errorf("cel env: %w", err)
	}
	actions := map[string]Action{}
	for _, dir := range actionDirs {
		as, err := loadActionsFromDir(dir)
		if err != nil {
			return nil, err
		}
		for _, a := range as {
			actions[a.ID] = a
		}
	}
	return &Engine{
		actions:  actions,
		store:    store,
		celEnv:   env,
		handlers: &handlerCtx{am: am, allowExecRun: opts.AllowExecRun},
		opts:     opts,
	}, nil
}

func (e *Engine) Close() {} // reserved for future resources

// Run executes the action with the given ID, linking the action run to the
// alert that fired it (use 0 if no alert applies, e.g. manual invocation).
// Errors only when the action is unknown; per-step failures are recorded in
// the returned ActionRun.
func (e *Engine) Run(ctx context.Context, actionID string, alertID int64, m engine.Match) (ActionRun, error) {
	e.mu.RLock()
	a, ok := e.actions[actionID]
	e.mu.RUnlock()
	if !ok {
		return ActionRun{}, fmt.Errorf("unknown action: %s", actionID)
	}

	dry := a.DryRun || e.opts.DryRunGlobal
	run := ActionRun{
		ActionID:  actionID,
		AlertID:   alertID,
		DryRun:    dry,
		StartedAt: time.Now(),
		Status:    "completed",
	}
	for _, s := range a.Steps {
		sr := StepResult{ID: s.ID}
		if s.Condition != "" {
			pass, err := e.evalCondition(s.Condition, m)
			if err != nil {
				sr.Err = err.Error()
				run.Status = "failed"
				run.Steps = append(run.Steps, sr)
				continue
			}
			if !pass {
				sr.Skipped = true
				run.Steps = append(run.Steps, sr)
				continue
			}
		}
		params, err := renderParams(s.Params, m)
		if err != nil {
			sr.Err = err.Error()
			run.Status = "failed"
			run.Steps = append(run.Steps, sr)
			continue
		}
		if dry {
			sr.Output = fmt.Sprintf("[dry-run] action=%s params=%v", s.Action, params)
			run.Steps = append(run.Steps, sr)
			continue
		}
		out, err := e.handlers.runHandler(ctx, s, params, m)
		sr.Output = out
		if err != nil {
			sr.Err = err.Error()
			run.Status = "failed"
		}
		run.Steps = append(run.Steps, sr)
	}
	run.FinishedAt = time.Now()

	// Persist the run; ignore errors from storage so the action run still returns.
	if e.store != nil {
		stepsJSON, _ := json.Marshal(run.Steps)
		if _, err := e.store.InsertActionRun(ctx, actionID, run.AlertID,
			run.DryRun, run.Status, stepsJSON, run.StartedAt, run.FinishedAt); err != nil {
			slog.Warn("playbook: persist run", "err", err)
		}
	}
	return run, nil
}

// Actions returns a copy of the loaded action set.
func (e *Engine) Actions() []Action {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Action, 0, len(e.actions))
	for _, a := range e.actions {
		out = append(out, a)
	}
	return out
}

func (e *Engine) evalCondition(expr string, m engine.Match) (bool, error) {
	ast, iss := e.celEnv.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return false, iss.Err()
	}
	prg, err := e.celEnv.Program(ast)
	if err != nil {
		return false, err
	}
	act := map[string]any{
		"event": map[string]any{
			"type": m.Event.Type, "pid": int(m.Event.PID), "uid": int(m.Event.UID),
			"comm": m.Event.Comm, "ret": m.Event.Ret,
		},
	}
	out, _, err := prg.Eval(act)
	if err != nil {
		return false, err
	}
	b, ok := out.Value().(bool)
	return ok && b, nil
}
