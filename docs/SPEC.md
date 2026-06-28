# vakta — Technical Specification

**vakta** is a Linux runtime event-processing agent. It collects syscall-level events
from the kernel via eBPF probes and from the kernel audit subsystem via netlink, evaluates
configurable policies against those events, stores matched records, and forwards
notifications to external systems.

The probe layer (`internal/probe/`) is **already implemented and tested**. This spec
covers everything above it.

---

## Architecture Overview

```
eBPF probe layer  ──────────────────────────────────────────┐
  (<-chan probe.Event, already implemented)                  │
                                                             ▼
auditd netlink reader                              Event Normalizer
  (internal/auditd/)  ──────────────────────────► (internal/normalizer/)
                                                             │
k8s audit log tailer  (optional, k8s mode)                  │
  (internal/k8saudit/)  ─────────────────────────────────── ┘
                                                             │
                                                             ▼
                                               Policy Engine (CEL)
                                               (internal/engine/)
                                                      │       │
                                                      │       ▼
                                                      │   SQLite Store
                                                      │   (internal/storage/)
                                                      │
                                                      ▼
                                          Alertmanager Client
                                          (internal/alertmanager/)
                                                      │
                                          Loki Push Client
                                          (internal/loki/)
                                                      │
                                          Action Engine (Playbook)
                                          (internal/playbook/)
                                                      │
                                          REST API ◄──┘
                                          (internal/api/)
                                                      │
                                          Web UI (embedded)
                                          (web/)
```

**Deployment modes** (same binary, `--mode` flag):
- `host` — systemd service on bare-metal/VM
- `k8s` — DaemonSet, additionally reads k8s audit log from hostPath

---

## Component Specifications

### 1. auditd Reader (`internal/auditd/`)

Reads the kernel audit subsystem via netlink using
[`github.com/elastic/go-libaudit/v2`](https://github.com/elastic/go-libaudit).

**Interface:**

```go
package auditd

// Record is the parsed form of one auditd netlink message.
type Record struct {
    Seq       uint32
    Timestamp time.Time
    Type      string // e.g. "SYSCALL", "PATH", "EXECVE", "AVC"
    Fields    map[string]string
}

// Reader streams Records from the kernel audit subsystem.
type Reader struct { /* unexported */ }

// New connects to the kernel audit netlink socket.
// Rules are pre-configured via auditctl/augenrules outside vakta.
func New(ctx context.Context) (*Reader, error)

// Records returns the channel of parsed records.
func (r *Reader) Records() <-chan Record

// Close shuts down the netlink connection.
func (r *Reader) Close() error
```

**Notes:**
- Requires `CAP_AUDIT_READ` (present when running as root or with the capability).
- Records arrive as raw netlink messages; go-libaudit handles reassembly of multi-part
  messages (AUDIT_EOE sequence).
- The reader goroutine logs and skips malformed records; it never blocks the channel.

---

### 2. k8s Audit Log Tailer (`internal/k8saudit/`)

Tails a JSON-per-line k8s API server audit log file (hostPath mount in DaemonSet mode).

**Interface:**

```go
package k8saudit

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
    RequestBody        json.RawMessage // nil for Metadata-level events
}

// Tailer follows a JSON audit log file, delivering Entry values.
type Tailer struct { /* unexported */ }

func New(ctx context.Context, path string) (*Tailer, error)
func (t *Tailer) Entries() <-chan Entry
func (t *Tailer) Close() error
```

**Notes:**
- Uses `github.com/nxadm/tail` for file following (handles log rotation via inotify).
- Only enabled when `--mode=k8s` and the audit log path is accessible.
- Skips entries with `responseStatus.code >= 400` by default (configurable).

---

### 3. Event Normalizer (`internal/normalizer/`)

Merges the three input streams into a single `chan Event` with a unified schema.

**Unified Event:**

```go
package normalizer

// Source identifies which subsystem produced the event.
type Source uint8

const (
    SourceEBPF    Source = 1
    SourceAuditd  Source = 2
    SourceK8sAudit Source = 3
)

// Event is the normalizer's output: one record from any source,
// converted to a common schema. Fields not applicable to a source
// are left at zero value.
type Event struct {
    ID        uint64    // monotonic, normalizer-assigned
    Ts        time.Time
    Source    Source
    Type      string    // e.g. "EXEC", "CONNECT", "OPEN", "CLONE", "K8S_SECRET_ACCESS"
    Host      string    // os.Hostname()
    CgroupID  uint64    // from eBPF header (0 for auditd/k8s events)

    // Process context (populated from eBPF or auditd SYSCALL records)
    PID   uint32
    PPID  uint32
    UID   uint32
    GID   uint32
    Comm  string

    // Outcome (from sys_exit pair; 0 = success or not applicable)
    Ret int64

    // Type-specific payload: one of the structs below, or nil.
    Detail any
}

// Detail types — one per event type:

type ExecDetail struct {
    Filename string
    Argv     []string
}

type ConnectDetail struct {
    DstIP   netip.Addr
    DstPort uint16
    Family  uint16
    Errno   int32 // negative errno if Ret < 0
}

type OpenDetail struct {
    Path  string
    Flags int32
}

type CloneDetail    struct{ CloneFlags uint64 }
type UnshareDetail  struct{ UnshareFlags uint64 }
type PtraceDetail   struct{ Request int64; TargetPID uint32 }
type ModuleDetail   struct{ Name string }
type BPFLoadDetail  struct{ ProgType uint32 }
type MemfdDetail    struct{ Name string; Flags uint32 }
type ChmodDetail    struct{ Path string; Mode uint32; SUID bool; SGID bool }
type MmapExecDetail struct{ Addr uint64; Len uint64; Prot uint32 }
type ProcProbeDetail struct{ TargetPID uint32 }

// AuditFIMDetail covers auditd FIM events (WATCH writes).
type AuditFIMDetail struct {
    Path    string
    AuditKey string // the -k tag from the audit rule
    Op      string // "write", "attr"
}

// K8sDetail covers k8s audit entries.
type K8sDetail struct {
    Verb      string
    Resource  string
    Namespace string
    Name      string
    Username  string
    SourceIP  string
}
```

**Interface:**

```go
// Normalizer fans in three streams and emits unified Events.
type Normalizer struct { /* unexported */ }

func New(
    ebpfCh   <-chan probe.Event,
    auditCh  <-chan auditd.Record,  // nil disables auditd
    k8sCh    <-chan k8saudit.Entry, // nil disables k8s audit
) *Normalizer

func (n *Normalizer) Events() <-chan Event
func (n *Normalizer) Close()
```

**Notes:**
- Runs one goroutine per non-nil input channel; merges into one output channel (cap 8192).
- auditd SYSCALL+PATH multi-record correlation: buffer SYSCALL records by `seq`, merge
  associated PATH records (same seq) within a 50ms window, then emit one AuditFIMDetail.
- Normalizer does not filter. All events pass through regardless of policy match.

---

### 4. Policy Engine (`internal/engine/`)

Evaluates policies (rules) against each Event using
[CEL](https://github.com/google/cel-go) expressions.

**Rule YAML schema:**

```yaml
rules:
  - id: string            # unique, slug format
    name: string          # human-readable
    severity: string      # "critical" | "high" | "warning" | "info"
    source: string        # "ebpf" | "auditd" | "k8s_audit" | "" (any)
    event_type: string    # matches Event.Type; "" matches any
    condition: string     # CEL expression, see CEL Environment below
    tags: [string]
    action_id: string     # optional: ID of action to run on match
```

**CEL Environment — variables available in `condition`:**

| Variable | Type | Description |
|---|---|---|
| `event.type` | string | normalizer Event.Type |
| `event.source` | int | 1=ebpf, 2=auditd, 3=k8s |
| `event.pid` | int | process PID |
| `event.ppid` | int | parent PID |
| `event.uid` | int | user ID |
| `event.comm` | string | process name (comm[16]) |
| `event.ret` | int | syscall return value |
| `event.cgroup_id` | int | cgroup v2 ID |
| `detail.*` | any | type-specific fields (see Detail types above) |
| `host.name` | string | hostname |

Example conditions:
```
detail.dst_port in [4444, 8443, 1337] && event.uid != 0
detail.suid == true && !event.comm.matches("^(dpkg|apt|rpm)$")
event.type == "K8S_SECRET_ACCESS" && detail.username.startsWith("system:") == false
```

**Interface:**

```go
package engine

// Match is produced when a rule's condition evaluates true for an Event.
type Match struct {
    Rule  Rule
    Event normalizer.Event
    At    time.Time
}

// Engine loads rules, compiles CEL programs, and evaluates events.
type Engine struct { /* unexported */ }

// New loads rules from the given directories (built-in + user).
// Returns error if any rule fails CEL compilation.
func New(ruleDirs []string) (*Engine, error)

// Evaluate runs all rules against ev and returns all matches.
// Order: critical first, then by rule ID lexicographically.
func (e *Engine) Evaluate(ev normalizer.Event) []Match

// Reload atomically replaces the rule set from the same dirs. Hot-reload.
func (e *Engine) Reload() error

// Rules returns the current loaded rule set (copy).
func (e *Engine) Rules() []Rule
```

**Notes:**
- CEL programs are compiled once at load time (not per-event). `Reload()` recompiles.
- Unknown fields in CEL expressions return `false` (not error) via protectd activation.
- Rule files in `rules/built-in/` are embedded with `go:embed` and loaded first.
  User rules from config `rules_dir` override built-in rules with the same `id`.

---

### 5. SQLite Store (`internal/storage/`)

Persists events and alerts. Uses `modernc.org/sqlite` (pure Go, no CGo).

**Schema:**

```sql
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,          -- Unix nanoseconds
    host        TEXT    NOT NULL,
    source      INTEGER NOT NULL,          -- 1/2/3
    type        TEXT    NOT NULL,
    cgroup_id   INTEGER NOT NULL DEFAULT 0,
    pid         INTEGER,
    ppid        INTEGER,
    uid         INTEGER,
    comm        TEXT,
    ret         INTEGER NOT NULL DEFAULT 0,
    detail_json TEXT    NOT NULL DEFAULT '{}',
    created_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(type, ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_pid  ON events(pid, ts DESC);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY,
    rule_id     TEXT    NOT NULL,
    rule_name   TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    event_id    INTEGER REFERENCES events(id),
    action_id   TEXT,
    status      TEXT    NOT NULL DEFAULT 'firing',  -- firing|resolved|suppressed
    tags_json   TEXT    NOT NULL DEFAULT '[]',
    fired_at    INTEGER NOT NULL,
    resolved_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_alerts_fired   ON alerts(fired_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_rule    ON alerts(rule_id, fired_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status  ON alerts(status, fired_at DESC);

CREATE TABLE IF NOT EXISTS action_runs (
    id           INTEGER PRIMARY KEY,
    action_id    TEXT    NOT NULL,
    alert_id     INTEGER REFERENCES alerts(id),
    dry_run      INTEGER NOT NULL DEFAULT 0,  -- 0|1
    status       TEXT    NOT NULL,            -- running|completed|failed
    steps_json   TEXT    NOT NULL DEFAULT '[]',
    started_at   INTEGER NOT NULL,
    finished_at  INTEGER
);
```

**Interface:**

```go
package storage

type DB struct { /* unexported */ }

func Open(path string, retentionDays int) (*DB, error)
func (db *DB) Close() error

// InsertEvent stores a normalizer.Event and returns its assigned ID.
func (db *DB) InsertEvent(ctx context.Context, ev normalizer.Event) (int64, error)

// InsertAlert stores a match-derived alert and returns its ID.
func (db *DB) InsertAlert(ctx context.Context, a Alert) (int64, error)

// QueryEvents returns events matching the filter, newest first, limit 500.
func (db *DB) QueryEvents(ctx context.Context, f EventFilter) ([]StoredEvent, error)

// QueryAlerts returns alerts matching the filter, newest first, limit 200.
func (db *DB) QueryAlerts(ctx context.Context, f AlertFilter) ([]StoredAlert, error)

// Prune deletes events and resolved alerts older than retentionDays. Call periodically.
func (db *DB) Prune(ctx context.Context) error

type EventFilter struct {
    Source    *int
    Type      *string
    PID       *uint32
    Since     *time.Time
    Until     *time.Time
}

type AlertFilter struct {
    RuleID   *string
    Severity *string
    Status   *string
    Since    *time.Time
}
```

---

### 6. Alertmanager Client (`internal/alertmanager/`)

POSTs alerts to Alertmanager's `/api/v2/alerts` endpoint.

**Interface:**

```go
package alertmanager

type Client struct { /* unexported */ }

// New creates a client. baseURL example: "http://alertmanager:9093"
func New(baseURL string, timeout time.Duration) *Client

// Send posts one or more firing alerts. Non-blocking: sends in a goroutine,
// logs on failure. Does not retry (Alertmanager is idempotent on re-send).
func (c *Client) Send(ctx context.Context, alerts []Alert)

// Resolve marks alerts as resolved (EndsAt = now).
func (c *Client) Resolve(ctx context.Context, labels map[string]string)

type Alert struct {
    Labels      map[string]string // must include "alertname"
    Annotations map[string]string
    StartsAt    time.Time
    EndsAt      time.Time // zero = firing
    GeneratorURL string
}
```

**Wire format** (POST body, `application/json`):
```json
[{
  "labels":      {"alertname": "...", "severity": "...", "host": "...", "rule_id": "..."},
  "annotations": {"summary": "...", "detail": "..."},
  "startsAt":    "2026-01-01T00:00:00Z"
}]
```

---

### 7. Loki Push Client (`internal/loki/`)

Async-pushes events to Loki via the HTTP push API (`/loki/api/v1/push`).

**Interface:**

```go
package loki

type Client struct { /* unexported */ }

// New creates a client with an internal buffer (cap 10000 log lines).
// Flushes automatically every flushInterval or when buffer reaches batchSize.
func New(baseURL string, flushInterval time.Duration, batchSize int) *Client

// Push enqueues an event for async delivery. Never blocks; drops if buffer full
// (increments internal drop counter accessible via Stats()).
func (c *Client) Push(ev normalizer.Event)

func (c *Client) Stats() LokiStats
func (c *Client) Close() error

type LokiStats struct {
    Enqueued uint64
    Flushed  uint64
    Dropped  uint64
    Errors   uint64
}
```

**Wire format** — Loki protobuf push (or JSON fallback if `LOKI_USE_JSON=1`):
```json
{
  "streams": [{
    "stream": {"host": "<host>", "source": "<ebpf|auditd|k8s>", "type": "<event_type>"},
    "values": [["<ts_ns>", "<json_of_event>"]]
  }]
}
```

---

### 8. Action Engine (`internal/playbook/`)

Executes response actions when a rule match has a non-empty `action_id`.

**Action definition YAML schema:**

```yaml
actions:
  - id: string
    name: string
    dry_run: bool       # default false; if true, log steps but do not execute
    steps:
      - id: string
        action: string  # see built-in action types below
        params: {}      # action-specific; support Go template syntax: {{ .event.pid }}
        condition: string  # CEL expression; skip step if false
```

**Built-in action types:**

| `action` value | Params | Effect |
|---|---|---|
| `notify` | `severity`, `message` | POST to Alertmanager (delegates to alertmanager.Client) |
| `network.block_ip` | `ip`, `direction`, `tool` (`iptables`\|`nftables`), `duration` (seconds) | Run iptables/nftables to block IP |
| `process.kill` | `pid`, `signal` (`SIGKILL`\|`SIGTERM`) | `kill(pid, sig)` |
| `container.pause` | `cgroup_id` | `docker pause` by container ID resolved from cgroup_id |
| `storage.snapshot` | `include` (list) | Capture process_tree / open_files / net_connections for event's PID into storage |
| `exec.run` | `command` (string) | Run arbitrary shell command (requires `allow_exec_run: true` in config) |

**Interface:**

```go
package playbook

type Engine struct { /* unexported */ }

// New loads action definitions from actionDirs.
func New(actionDirs []string, store *storage.DB, amClient *alertmanager.Client) (*Engine, error)

// Run executes the action with the given ID for the match.
// Returns an ActionRun record (also persisted to storage).
// Non-blocking option: call in a goroutine if caller must not block.
func (e *Engine) Run(ctx context.Context, actionID string, m engine.Match) (ActionRun, error)

type ActionRun struct {
    ActionID  string
    AlertID   int64
    DryRun    bool
    Status    string // "completed" | "failed"
    Steps     []StepResult
    StartedAt time.Time
    FinishedAt time.Time
}

type StepResult struct {
    ID      string
    Skipped bool   // condition evaluated false
    Output  string
    Err     string
}
```

---

### 9. REST API (`internal/api/`)

HTTP server serving the Web UI assets and JSON API. Listens on `:9090` by default.

**Endpoints:**

```
GET  /api/v1/events            ?source=&type=&pid=&since=&until=&limit=
GET  /api/v1/alerts            ?rule_id=&severity=&status=&since=&limit=
GET  /api/v1/rules             (current rule set)
POST /api/v1/rules/reload      (hot-reload from disk)
GET  /api/v1/rules/test        body: {"event": {...}} → {"matches": [...]}
GET  /api/v1/actions           (current action set)
GET  /api/v1/action-runs       ?action_id=&since=
GET  /api/v1/stats             (probe stats + engine stats + storage row counts)
GET  /                         serves embedded web/dist/
```

All responses are `application/json`. Pagination: `limit` (max 500) + `cursor` (event ID).

**Auth:** Basic auth if `ui.auth: basic` in config (username/password from config).
No auth if `ui.auth: none`.

---

### 10. Web UI (`web/`)

React + Vite SPA, built to `web/dist/`, embedded into the Go binary via `go:embed`.

**Pages:**

| Page | Route | Content |
|------|-------|---------|
| Timeline | `/` | Real-time event stream via SSE (`/api/v1/events/stream`), filterable, click to expand detail |
| Alerts | `/alerts` | Alert list, status, action run history |
| Rules | `/rules` | Built-in (read-only) + user rules (CRUD), rule test panel |
| Config | `/config` | Source toggles, output connections, retention, dry-run global switch |

**SSE stream endpoint** (added to REST API):
```
GET /api/v1/events/stream    text/event-stream; one JSON Event per "data:" line
```

---

### 11. CLI Entrypoint (`cmd/vakta/`)

```
vakta agent [--config /etc/vakta/config.yaml] [--mode host|k8s]
vakta rules lint <file>         # validate rule YAML + CEL compilation
vakta rules test <file> <event-json>
vakta version
```

Uses `github.com/spf13/cobra`.

---

## Configuration (`config/`)

```yaml
agent:
  mode: host          # host | k8s
  node_name: ""       # defaults to os.Hostname()

sources:
  ebpf:      true
  auditd:    true
  k8s_audit: false
  k8s_audit_log: /var/log/k8s-audit.log

rules_dir: /etc/vakta/rules         # user rules; built-in always loaded
actions_dir: /etc/vakta/actions     # user actions; built-in always loaded

outputs:
  alertmanager: ""    # e.g. "http://alertmanager:9093"; empty = disabled
  loki: ""            # e.g. "http://loki:3100"; empty = disabled
  loki_flush_interval: 5s
  loki_batch_size: 100

storage:
  sqlite_path: /var/lib/vakta/events.db
  retention_days: 30

ui:
  enabled: true
  addr: ":9090"
  auth: none          # none | basic
  username: ""
  password: ""

playbook:
  allow_exec_run: false   # must be true to enable exec.run action type
  dry_run: false          # global dry_run override

log:
  level: info   # debug | info | warn | error
  format: json  # json | text
```

---

## Go Dependencies (to add)

```
github.com/elastic/go-libaudit/v2   v2.x    # auditd netlink
github.com/google/cel-go            v0.x    # CEL policy evaluation
modernc.org/sqlite                  v1.x    # pure-Go SQLite (no CGo)
gopkg.in/yaml.v3                    v3.x    # YAML parsing
github.com/spf13/cobra              v1.x    # CLI
github.com/nxadm/tail               v1.x    # k8s audit log tailing
```

All are pure Go or have pure-Go build modes (`CGO_ENABLED=0 go build ./...` must work).

---

## Build & Test

```bash
# Build (no CGo needed for non-probe packages)
CGO_ENABLED=0 go build ./...

# Unit tests (no root, no kernel required)
CGO_ENABLED=0 go test ./internal/auditd/... ./internal/normalizer/... \
    ./internal/engine/... ./internal/storage/... ./internal/alertmanager/... \
    ./internal/loki/... ./internal/playbook/... ./internal/api/... \
    ./config/... ./cmd/...

# Integration test (probe layer, requires root + kernel >= 5.8)
sudo go test -v -tags integration ./internal/probe/...

# Frontend
cd web && npm ci && npm run build
```

---

## Implementation Order (suggested for plan writing)

1. `config/` — load + validate config YAML
2. `internal/normalizer/` — unified Event type + fan-in logic (no external deps)
3. `internal/storage/` — SQLite schema + CRUD (pure Go)
4. `internal/engine/` — CEL rule loader + evaluator
5. `internal/alertmanager/` — HTTP client
6. `internal/auditd/` — go-libaudit reader + auditd→normalizer converter
7. `internal/loki/` — async push client
8. `internal/playbook/` — action engine
9. `cmd/vakta/` — agent main loop wiring all components
10. `internal/k8saudit/` — k8s audit log tailer
11. `internal/api/` — REST API + SSE
12. `web/` — React SPA
13. `deploy/` — systemd unit + Helm chart
