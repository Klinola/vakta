package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"net/http"

	"github.com/spf13/cobra"

	"github.com/vakta-project/vakta/config"
	"github.com/vakta-project/vakta/internal/alertmanager"
	"github.com/vakta-project/vakta/internal/api"
	"github.com/vakta-project/vakta/internal/engine"
	"github.com/vakta-project/vakta/internal/k8saudit"
	"github.com/vakta-project/vakta/internal/loki"
	"github.com/vakta-project/vakta/internal/normalizer"
	"github.com/vakta-project/vakta/internal/playbook"
	"github.com/vakta-project/vakta/internal/probe"
	"github.com/vakta-project/vakta/internal/storage"
)

func newAgentCmd() *cobra.Command {
	var cfgPath, modeOverride string
	c := &cobra.Command{
		Use:   "agent",
		Short: "Run the vakta agent",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return fmt.Errorf("config: %w", err)
			}
			if modeOverride != "" {
				cfg.Agent.Mode = modeOverride
				if err := cfg.Validate(); err != nil {
					return err
				}
			}
			return runAgent(cmd.Context(), cfg)
		},
	}
	c.Flags().StringVar(&cfgPath, "config", "/etc/vakta/config.yaml", "Path to config file")
	c.Flags().StringVar(&modeOverride, "mode", "", "Override agent mode (host|k8s)")
	return c
}

func runAgent(parent context.Context, cfg *config.Config) error {
	configureLogger(cfg.Log)
	host := cfg.Agent.NodeName
	if host == "" {
		host, _ = os.Hostname()
	}

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	// Wire SIGINT/SIGTERM cancellation.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigCh
		slog.Info("agent: signal received", "signal", s.String())
		cancel()
	}()

	// 1) Storage
	store, err := storage.Open(cfg.Storage.SQLitePath, cfg.Storage.RetentionDays)
	if err != nil {
		return fmt.Errorf("storage: %w", err)
	}
	defer func() { _ = store.Close() }()

	// 2) Probe layer (optional)
	var probeCh <-chan probe.Event
	var probeMgr *probe.Manager
	if cfg.Sources.EBPF {
		mgr, ch, err := probe.New(ctx)
		if err != nil {
			slog.Warn("probe disabled", "err", err)
		} else {
			probeMgr = mgr
			probeCh = ch
			defer func() { _ = probeMgr.Close() }()
		}
	}

	// 3) Optional k8s audit log tailer
	var k8sCh <-chan k8saudit.Entry
	if cfg.Sources.K8sAudit && cfg.Agent.Mode == "k8s" {
		tl, err := k8saudit.New(ctx, cfg.Sources.K8sAuditLog)
		if err != nil {
			slog.Warn("k8saudit disabled", "err", err)
		} else {
			defer func() { _ = tl.Close() }()
			k8sCh = tl.Entries()
		}
	}

	// 4) Normalizer (auditd channel still nil — Task 6 reader exists but no wiring goroutine here yet)
	n := normalizer.New(probeCh, nil, k8sCh, host)
	defer n.Close()

	// 4) Engine
	eng, err := engine.New([]string{cfg.RulesDir})
	if err != nil {
		return fmt.Errorf("engine: %w", err)
	}

	// 5) Outputs
	am := alertmanager.New(cfg.Outputs.Alertmanager, 10*time.Second)
	var lokiC *loki.Client
	if cfg.Outputs.Loki != "" {
		lokiC = loki.New(cfg.Outputs.Loki, cfg.Outputs.LokiFlushInterval, cfg.Outputs.LokiBatchSize)
		defer func() { _ = lokiC.Close() }()
	}

	// 6) Playbook
	pb, err := playbook.New([]string{cfg.ActionsDir}, store, am, playbook.EngineOptions{
		AllowExecRun: cfg.Playbook.AllowExecRun,
		DryRunGlobal: cfg.Playbook.DryRun,
	})
	if err != nil {
		return fmt.Errorf("playbook: %w", err)
	}
	defer pb.Close()

	// 7) API server + SSE bus
	bus := api.NewEventBus()
	apiSrv := api.New(cfg.UI.Addr, store, eng, bus, pb, api.ServerOptions{
		Auth: cfg.UI.Auth, Username: cfg.UI.Username, Password: cfg.UI.Password,
	})
	if cfg.UI.Enabled {
		go func() {
			if err := apiSrv.Start(); err != nil && err != http.ErrServerClosed {
				slog.Error("api: server", "err", err)
			}
		}()
		defer func() { _ = apiSrv.Close() }()
	}

	// 8) Prune ticker
	pruneT := time.NewTicker(1 * time.Hour)
	defer pruneT.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-pruneT.C:
				if err := store.Prune(ctx); err != nil {
					slog.Warn("prune", "err", err)
				}
			}
		}
	}()

	// 8) Main event loop: normalizer -> store + engine + loki + playbook
	slog.Info("agent: starting", "mode", cfg.Agent.Mode, "host", host)
	for {
		select {
		case <-ctx.Done():
			slog.Info("agent: shutting down")
			return nil
		case ev, ok := <-n.Events():
			if !ok {
				return errors.New("normalizer channel closed unexpectedly")
			}
			handleEvent(ctx, ev, store, eng, am, lokiC, pb, bus)
		}
	}
}

func handleEvent(
	ctx context.Context, ev normalizer.Event,
	store *storage.DB, eng *engine.Engine,
	am *alertmanager.Client, lokiC *loki.Client, pb *playbook.Engine,
	bus *api.EventBus,
) {
	if bus != nil {
		bus.Publish(ev)
	}
	if lokiC != nil {
		lokiC.Push(ev)
	}
	evID, err := store.InsertEvent(ctx, ev)
	if err != nil {
		slog.Warn("store event", "err", err)
	}
	matches := eng.Evaluate(ev)
	for _, m := range matches {
		alertID, err := store.InsertAlert(ctx, storage.Alert{
			RuleID: m.Rule.ID, RuleName: m.Rule.Name, Severity: m.Rule.Severity,
			EventID: evID, ActionID: m.Rule.ActionID,
			Status: "firing", Tags: m.Rule.Tags, FiredAt: m.At,
		})
		if err != nil {
			slog.Warn("store alert", "err", err)
		}
		am.Send(ctx, []alertmanager.Alert{{
			Labels: map[string]string{
				"alertname": m.Rule.Name,
				"severity":  m.Rule.Severity,
				"rule_id":   m.Rule.ID,
				"host":      ev.Host,
			},
			Annotations: map[string]string{
				"summary": fmt.Sprintf("%s on %s (pid=%d)", m.Rule.Name, ev.Host, ev.PID),
			},
			StartsAt: m.At,
		}})
		if m.Rule.ActionID != "" {
			if _, err := pb.Run(ctx, m.Rule.ActionID, alertID, m); err != nil {
				slog.Warn("playbook run", "action", m.Rule.ActionID, "err", err)
			}
		}
	}
}

func configureLogger(lc config.LogSection) {
	level := slog.LevelInfo
	switch lc.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	var h slog.Handler
	opts := &slog.HandlerOptions{Level: level}
	if lc.Format == "text" {
		h = slog.NewTextHandler(os.Stderr, opts)
	} else {
		h = slog.NewJSONHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(h))
}
