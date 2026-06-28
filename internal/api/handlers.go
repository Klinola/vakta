package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/Klinola/vakta/internal/normalizer"
	"github.com/Klinola/vakta/internal/storage"
)

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (s *Server) handleGetEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := storage.EventFilter{}
	if v := q.Get("source"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Source = &n
		}
	}
	if v := q.Get("type"); v != "" {
		f.Type = &v
	}
	if v := q.Get("pid"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			p := uint32(n)
			f.PID = &p
		}
	}
	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Since = &t
		}
	}
	if v := q.Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Until = &t
		}
	}
	if v := q.Get("cursor"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			f.Cursor = &n
		}
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Limit = n
		}
	}
	evs, err := s.db.QueryEvents(r.Context(), f)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"events": evs})
}

func (s *Server) handleGetAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := storage.AlertFilter{}
	if v := q.Get("rule_id"); v != "" {
		f.RuleID = &v
	}
	if v := q.Get("severity"); v != "" {
		f.Severity = &v
	}
	if v := q.Get("status"); v != "" {
		f.Status = &v
	}
	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Since = &t
		}
	}
	if v := q.Get("cursor"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			f.Cursor = &n
		}
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Limit = n
		}
	}
	as, err := s.db.QueryAlerts(r.Context(), f)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"alerts": as})
}

func (s *Server) handleGetRules(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"rules": s.eng.Rules()})
}

func (s *Server) handleReloadRules(w http.ResponseWriter, _ *http.Request) {
	if err := s.eng.Reload(); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "count": len(s.eng.Rules())})
}

func (s *Server) handleTestRule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Event normalizer.Event `json:"event"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	matches := s.eng.Evaluate(body.Event)
	writeJSON(w, 200, map[string]any{"matches": matches})
}

func (s *Server) handleGetActions(w http.ResponseWriter, _ *http.Request) {
	if s.pb == nil {
		writeJSON(w, 200, map[string]any{"actions": []any{}})
		return
	}
	writeJSON(w, 200, map[string]any{"actions": s.pb.Actions()})
}

func (s *Server) handleGetActionRuns(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := storage.ActionRunFilter{}
	if v := q.Get("action_id"); v != "" {
		f.ActionID = &v
	}
	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Since = &t
		}
	}
	runs, err := s.db.QueryActionRuns(r.Context(), f)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"action_runs": runs})
}

func (s *Server) handleGetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	stats := map[string]any{
		"rules": len(s.eng.Rules()),
	}
	if n, err := s.db.CountEvents(ctx); err == nil {
		stats["events_total"] = n
	}
	if n, err := s.db.CountAlerts(ctx); err == nil {
		stats["alerts_total"] = n
	}
	if n, err := s.db.CountActionRuns(ctx); err == nil {
		stats["action_runs_total"] = n
	}
	if s.pb != nil {
		stats["actions"] = len(s.pb.Actions())
	}
	writeJSON(w, 200, stats)
}
