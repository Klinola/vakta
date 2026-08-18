package main

import (
	"context"
	"log/slog"

	"github.com/Klinola/vakta/internal/alertmanager"
	"github.com/Klinola/vakta/internal/engine"
	"github.com/Klinola/vakta/internal/normalizer"
)

// droppedAlertBuffer bounds the alerts queued from the drop path. Rule matches
// are rare even under overload, so a small buffer is ample; if it ever fills,
// the callback logs rather than blocking the ingest handler.
const droppedAlertBuffer = 256

// newDropEvaluator returns the callback the ingest server invokes for events
// the dispatcher could not accept.
//
// The hub sheds load by dropping events when the dispatcher is saturated
// (hundreds of thousands a day in a busy cluster). Those events used to be
// discarded *before* rule evaluation, so a critical detection that arrived
// during a slow flush disappeared leaving nothing but an aggregate counter in
// the log — the one class of event that must never be silently lost.
//
// Rule evaluation is in-memory and cheap, so it runs here even though the
// SQLite write cannot: writes belong to the single dispatcher goroutine and
// moving them here would break that invariant. The alert therefore fires with
// no event_id behind it, which is accurate — there is no stored event.
//
// Alertmanager delivery is handed to a goroutine because this callback runs on
// the ingest request goroutine and must not block on network IO.
func newDropEvaluator(
	ctx context.Context,
	eng *engine.Engine,
	am *alertmanager.Client,
	cluster string,
) func(normalizer.Event) {
	ch := make(chan alertmanager.Alert, droppedAlertBuffer)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case a := <-ch:
				batch := []alertmanager.Alert{a}
				// Coalesce whatever else is already queued into one POST.
			drain:
				for {
					select {
					case more := <-ch:
						batch = append(batch, more)
					default:
						break drain
					}
				}
				am.Send(ctx, batch)
			}
		}
	}()

	return func(ev normalizer.Event) {
		for _, m := range eng.Evaluate(ev) {
			slog.Warn("hub: rule matched an event dropped before storage",
				"rule", m.Rule.ID, "severity", m.Rule.Severity,
				"host", ev.Host, "comm", ev.Comm, "pid", ev.PID, "type", ev.Type)
			select {
			case ch <- buildAMAlert(m, cluster):
			default:
				slog.Error("hub: drop-path alert queue full, alert not delivered",
					"rule", m.Rule.ID, "host", ev.Host)
			}
		}
	}
}
