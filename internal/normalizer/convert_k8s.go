package normalizer

import (
	"encoding/json"
	"time"
)

// K8sEntryView mirrors internal/k8saudit (Task 10). Re-declared here so the
// normalizer compiles standalone.
type K8sEntryView struct {
	Timestamp          time.Time
	Verb               string
	Resource           string
	Namespace          string
	Name               string
	Username           string
	SourceIP           string
	ResponseStatusCode int32
	RequestBody        json.RawMessage
}

// FromK8s converts a k8s audit entry into an Event.
func FromK8s(e K8sEntryView, host string) Event {
	return Event{
		Ts:     e.Timestamp,
		Source: SourceK8sAudit,
		Host:   host,
		Type:   k8sEventType(e.Resource, e.Verb),
		Detail: &K8sDetail{
			Verb: e.Verb, Resource: e.Resource, Namespace: e.Namespace,
			Name: e.Name, Username: e.Username, SourceIP: e.SourceIP,
		},
	}
}

// k8sEventType produces a Type string from resource+verb. Distinguishes
// secret access from other reads for rule matching ergonomics.
func k8sEventType(resource, verb string) string {
	if resource == "secrets" && (verb == "get" || verb == "list") {
		return "K8S_SECRET_ACCESS"
	}
	return "K8S_AUDIT"
}
