package normalizer

import (
	"github.com/vakta-project/vakta/internal/k8saudit"
)

// K8sEntry is re-exported for the normalizer's input signature.
type K8sEntry = k8saudit.Entry

// FromK8s converts a k8s audit entry into an Event.
func FromK8s(e K8sEntry, host string) Event {
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

func k8sEventType(resource, verb string) string {
	if resource == "secrets" && (verb == "get" || verb == "list") {
		return "K8S_SECRET_ACCESS"
	}
	return "K8S_AUDIT"
}
