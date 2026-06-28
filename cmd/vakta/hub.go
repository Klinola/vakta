package main

import (
	"context"
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

const (
	hubEventChannelBuffer = 65536           // absorbs agent burst when dispatcher is mid-flush
	hubBatchSize          = 100             // flush threshold by count
	hubBatchInterval      = 100 * time.Millisecond
)

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

	slog.Info("hub: starting",
		"host", host, "ingest_addr", cfg.Hub.IngestAddr,
		"batch_size", hubBatchSize, "batch_interval", hubBatchInterval)
	runHubDispatcher(ctx, eventCh, store, eng, am, pb, bus, cfg.Agent.ClusterName)
	slog.Info("hub: shutting down")
	return nil
}

// runHubDispatcher consumes events from eventCh in batches and processes each
// batch with flushBatch. One dispatcher goroutine (not a pool) keeps the
// single-writer SQLite invariant intact while batching amortizes WAL fsync
// cost across many inserts.
func runHubDispatcher(
	ctx context.Context,
	eventCh <-chan normalizer.Event,
	store *storage.DB, eng *engine.Engine,
	am *alertmanager.Client, pb *playbook.Engine,
	bus *api.EventBus,
	cluster string,
) {
	batch := make([]normalizer.Event, 0, hubBatchSize)
	ticker := time.NewTicker(hubBatchInterval)
	defer ticker.Stop()

	flush := func(c context.Context) {
		if len(batch) == 0 {
			return
		}
		flushBatch(c, batch, store, eng, am, pb, bus, cluster)
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			// Drain remaining buffered events using a background context so
			// the final flush completes even though the parent is cancelled.
			drainCtx := context.Background()
			for {
				select {
				case ev := <-eventCh:
					batch = append(batch, ev)
					if len(batch) >= hubBatchSize {
						flushBatch(drainCtx, batch, store, eng, am, pb, bus, cluster)
						batch = batch[:0]
					}
				default:
					if len(batch) > 0 {
						flushBatch(drainCtx, batch, store, eng, am, pb, bus, cluster)
					}
					return
				}
			}
		case ev := <-eventCh:
			batch = append(batch, ev)
			if len(batch) >= hubBatchSize {
				flush(ctx)
			}
		case <-ticker.C:
			flush(ctx)
		}
	}
}

// flushBatch is the batch equivalent of handleEvent: SSE fanout, one INSERT
// tx for events, rule eval per event, one INSERT tx for alerts, batched
// Alertmanager POST, async playbook runs.
func flushBatch(
	ctx context.Context,
	batch []normalizer.Event,
	store *storage.DB, eng *engine.Engine,
	am *alertmanager.Client, pb *playbook.Engine,
	bus *api.EventBus,
	cluster string,
) {
	// 1. SSE fanout — in-memory, no IO.
	if bus != nil {
		for i := range batch {
			bus.Publish(batch[i])
		}
	}

	// 2. Single-tx event INSERT.
	evIDs, err := store.InsertEventsBatch(ctx, batch)
	if err != nil {
		slog.Warn("hub: insert events batch", "err", err, "n", len(batch))
		// Best-effort: zero IDs so alerts can still fire but won't link back.
		evIDs = make([]int64, len(batch))
	}

	// 3. Rule eval per event; collect alert rows + AM alerts.
	var alertsForDB []storage.Alert
	var amAlerts []alertmanager.Alert
	type pbReq struct {
		actionID string
		match    engine.Match
		idx      int // index into alertsForDB → alertIDs after batch INSERT
	}
	var pbReqs []pbReq

	for i := range batch {
		ev := batch[i]
		matches := eng.Evaluate(ev)
		for _, m := range matches {
			alertsForDB = append(alertsForDB, storage.Alert{
				RuleID:   m.Rule.ID,
				RuleName: m.Rule.Name,
				Severity: m.Rule.Severity,
				EventID:  evIDs[i],
				ActionID: m.Rule.ActionID,
				Status:   "firing",
				Tags:     m.Rule.Tags,
				FiredAt:  m.At,
			})
			amAlerts = append(amAlerts, alertmanager.Alert{
				Labels: map[string]string{
					"alertname":      m.Rule.Name,
					"severity":       severityToP(m.Rule.Severity),
					"vakta_severity": m.Rule.Severity,
					"rule_id":        m.Rule.ID,
					"event_type":     ev.Type,
					"cluster":        cluster,
					"node":           ev.Host,
				},
				Annotations: map[string]string{
					"summary": fmt.Sprintf("[%s/%s] %s — %s pid=%d",
						cluster, ev.Host, m.Rule.Name, ev.Comm, ev.PID),
					"description": fmt.Sprintf("rule=%s severity=%s type=%s",
						m.Rule.ID, m.Rule.Severity, ev.Type),
				},
				StartsAt: m.At,
			})
			if m.Rule.ActionID != "" {
				pbReqs = append(pbReqs, pbReq{
					actionID: m.Rule.ActionID,
					match:    m,
					idx:      len(alertsForDB) - 1,
				})
			}
		}
	}

	if len(alertsForDB) == 0 {
		return
	}

	// 4. Single-tx alert INSERT.
	alertIDs, err := store.InsertAlertsBatch(ctx, alertsForDB)
	if err != nil {
		slog.Warn("hub: insert alerts batch", "err", err, "n", len(alertsForDB))
		alertIDs = make([]int64, len(alertsForDB))
	}

	// 5. Alertmanager — single POST with the full batch.
	am.Send(ctx, amAlerts)

	// 6. Playbook runs async so dispatcher doesn't block on action exec.
	for _, r := range pbReqs {
		go func(actionID string, alertID int64, m engine.Match) {
			if _, err := pb.Run(context.Background(), actionID, alertID, m); err != nil {
				slog.Warn("playbook run", "action", actionID, "err", err)
			}
		}(r.actionID, alertIDs[r.idx], r.match)
	}
}
