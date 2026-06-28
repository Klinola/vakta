// Package k8saudit follows a Kubernetes API server audit log file and
// emits parsed Entry values.
package k8saudit

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/nxadm/tail"
)

// Entry is one parsed k8s audit event.
type Entry struct {
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

// Tailer follows the audit log, delivering Entry values on Entries().
type Tailer struct {
	t            *tail.Tail
	out          chan Entry
	closeOnce    sync.Once
	cancel       context.CancelFunc
	skipStatusGE int32 // entries with responseStatus.code >= this are dropped
}

// Options configures Tailer behavior. Zero values use sensible defaults.
type Options struct {
	// SkipStatusCodeGE drops entries whose responseStatus.code >= this value.
	// Default 400 (skip errors).
	SkipStatusCodeGE int32
}

// New opens the audit log file and begins tailing with default options.
func New(ctx context.Context, path string) (*Tailer, error) {
	return NewWithOptions(ctx, path, Options{})
}

// NewWithOptions opens the audit log file with explicit options.
func NewWithOptions(ctx context.Context, path string, opts Options) (*Tailer, error) {
	t, err := tail.TailFile(path, tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: false,
		Poll:      false,
	})
	if err != nil {
		return nil, err
	}
	if opts.SkipStatusCodeGE == 0 {
		opts.SkipStatusCodeGE = 400
	}
	ctx, cancel := context.WithCancel(ctx)
	tr := &Tailer{
		t:            t,
		out:          make(chan Entry, 512),
		cancel:       cancel,
		skipStatusGE: opts.SkipStatusCodeGE,
	}
	go tr.run(ctx)
	return tr, nil
}

func (tr *Tailer) Entries() <-chan Entry { return tr.out }

func (tr *Tailer) Close() error {
	tr.closeOnce.Do(func() {
		tr.cancel()
		_ = tr.t.Stop()
		tr.t.Cleanup()
	})
	return nil
}

func (tr *Tailer) run(ctx context.Context) {
	defer close(tr.out)
	for {
		select {
		case <-ctx.Done():
			return
		case line, ok := <-tr.t.Lines:
			if !ok {
				return
			}
			if line.Err != nil {
				slog.Warn("k8saudit: tail error", "err", line.Err)
				continue
			}
			e, ok := parse(line.Text, tr.skipStatusGE)
			if !ok {
				continue
			}
			select {
			case tr.out <- e:
			case <-ctx.Done():
				return
			}
		}
	}
}

// raw is the subset of the k8s audit event JSON we consume.
type raw struct {
	RequestReceivedTimestamp string `json:"requestReceivedTimestamp"`
	Verb                     string `json:"verb"`
	ObjectRef                struct {
		Resource  string `json:"resource"`
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	} `json:"objectRef"`
	User struct {
		Username string `json:"username"`
	} `json:"user"`
	SourceIPs      []string `json:"sourceIPs"`
	ResponseStatus struct {
		Code int32 `json:"code"`
	} `json:"responseStatus"`
	RequestObject json.RawMessage `json:"requestObject"`
}

func parse(line string, skipStatusGE int32) (Entry, bool) {
	var r raw
	if err := json.Unmarshal([]byte(line), &r); err != nil {
		return Entry{}, false
	}
	if r.ResponseStatus.Code >= skipStatusGE {
		return Entry{}, false
	}
	ts, _ := time.Parse(time.RFC3339Nano, r.RequestReceivedTimestamp)
	srcIP := ""
	if len(r.SourceIPs) > 0 {
		srcIP = r.SourceIPs[0]
	}
	return Entry{
		Timestamp:          ts,
		Verb:               r.Verb,
		Resource:           r.ObjectRef.Resource,
		Namespace:          r.ObjectRef.Namespace,
		Name:               r.ObjectRef.Name,
		Username:           r.User.Username,
		SourceIP:           srcIP,
		ResponseStatusCode: r.ResponseStatus.Code,
		RequestBody:        r.RequestObject,
	}, true
}
