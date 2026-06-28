package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/Klinola/vakta/config"
	"github.com/Klinola/vakta/internal/alertmanager"
	"github.com/Klinola/vakta/internal/api"
	"github.com/Klinola/vakta/internal/engine"
	"github.com/Klinola/vakta/internal/hub"
	"github.com/Klinola/vakta/internal/normalizer"
	"github.com/Klinola/vakta/internal/playbook"
	"github.com/Klinola/vakta/internal/storage"
)

const hubEventChannelBuffer = 8192

func newHubCmd() *cobra.Command {
	var cfgPath string
	c := &cobra.Command{
		Use:   "hub",
		Short: "Run the vakta hub (centralized event processing for multi-node deployments)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return fmt.Errorf("config: %w", err)
			}
			return runHub(cmd.Context(), cfg)
		},
	}
	c.Flags().StringVar(&cfgPath, "config", "/etc/vakta/config.yaml", "Path to config file")
	return c
}

func runHub(parent context.Context, cfg *config.Config) error {
	configureLogger(cfg.Log)
	host := cfg.Agent.NodeName
	if host == "" {
		host, _ = os.Hostname()
	}

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigCh
		slog.Info("hub: signal received", "signal", s.String())
		cancel()
	}()

	store, err := storage.Open(cfg.Storage.SQLitePath, cfg.Storage.RetentionDays)
	if err != nil {
		return fmt.Errorf("storage: %w", err)
	}
	defer func() { _ = store.Close() }()

	eng, err := engine.New([]string{cfg.RulesDir})
	if err != nil {
		return fmt.Errorf("engine: %w", err)
	}

	am := alertmanager.New(cfg.Outputs.Alertmanager, 10*time.Second)

	pb, err := playbook.New([]string{cfg.ActionsDir}, store, am, playbook.EngineOptions{
		AllowExecRun: cfg.Playbook.AllowExecRun,
		DryRunGlobal: cfg.Playbook.DryRun,
	})
	if err != nil {
		return fmt.Errorf("playbook: %w", err)
	}
	defer pb.Close()

	bus := api.NewEventBus()
	apiSrv := api.New(cfg.UI.Addr, store, eng, bus, pb, api.ServerOptions{
		Auth: cfg.UI.Auth, Username: cfg.UI.Username, Password: cfg.UI.Password,
	})
	if cfg.UI.Enabled {
		go func() {
			if err := apiSrv.Start(); err != nil && err != http.ErrServerClosed {
				slog.Error("hub: api server", "err", err)
			}
		}()
		defer func() { _ = apiSrv.Close() }()
	}

	eventCh := make(chan normalizer.Event, hubEventChannelBuffer)
	ingestSrv := hub.New(cfg.Hub.IngestAddr, eventCh)
	go func() {
		if err := ingestSrv.Start(); err != nil && err != http.ErrServerClosed {
			slog.Error("hub: ingest server", "err", err)
			cancel()
		}
	}()
	defer func() { _ = ingestSrv.Close() }()

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

	slog.Info("hub: starting", "host", host, "ingest_addr", cfg.Hub.IngestAddr)
	for {
		select {
		case <-ctx.Done():
			slog.Info("hub: shutting down")
			return nil
		case ev, ok := <-eventCh:
			if !ok {
				return errors.New("hub: event channel closed unexpectedly")
			}
			handleEvent(ctx, ev, store, eng, am, nil, pb, bus, cfg.Agent.ClusterName)
		}
	}
}
