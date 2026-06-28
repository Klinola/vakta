package playbook

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/vakta-project/vakta/internal/engine"
)

// renderParams renders any string value in params through text/template,
// passing the match's event/rule as the template context. Non-strings pass through.
func renderParams(params map[string]any, m engine.Match) (map[string]any, error) {
	ctx := map[string]any{
		"event": map[string]any{
			"type": m.Event.Type, "pid": m.Event.PID, "ppid": m.Event.PPID,
			"uid": m.Event.UID, "comm": m.Event.Comm, "host": m.Event.Host,
			"cgroup_id": m.Event.CgroupID, "ret": m.Event.Ret,
		},
		"rule": map[string]any{
			"id": m.Rule.ID, "name": m.Rule.Name, "severity": m.Rule.Severity,
		},
	}
	out := make(map[string]any, len(params))
	for k, v := range params {
		s, ok := v.(string)
		if !ok {
			out[k] = v
			continue
		}
		t, err := template.New(k).Parse(s)
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", k, err)
		}
		var buf bytes.Buffer
		if err := t.Execute(&buf, ctx); err != nil {
			return nil, fmt.Errorf("template %s: %w", k, err)
		}
		out[k] = buf.String()
	}
	return out, nil
}
