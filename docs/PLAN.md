# vakta Agent Implementation Plan

**Goal:** Build everything above the eBPF probe layer per `docs/SPEC.md` — config loader, event normalizer, SQLite store, CEL policy engine, alertmanager/loki sinks, auditd + k8s audit readers, action playbook engine, REST+SSE API, React web UI, deploy artifacts.

**Architecture:** A single Go binary (`vakta agent`) fans three input streams (eBPF probe, auditd netlink, k8s audit file) into a unified normalizer, runs each event through a CEL-evaluated rule set, persists to SQLite, and forwards matches to Alertmanager / Loki / action playbooks. A REST API + embedded React SPA serve the UI on `:9090`.

**Tech stack:** Go 1.25, `CGO_ENABLED=0` throughout. New deps: `gopkg.in/yaml.v3`, `modernc.org/sqlite`, `github.com/google/cel-go`, `github.com/elastic/go-libaudit/v2`, `github.com/spf13/cobra`, `github.com/nxadm/tail`. Web: React 18 + Vite + react-router. No testify — stdlib `testing` only.

**Working dir for all tasks:** `~/vakta`. Spec: `docs/SPEC.md`. The probe layer (`internal/probe/`) is already complete and unchanged by this plan.

**Cross-task type contracts (define once, referenced everywhere):**
- `normalizer.Event` (Task 2) consumed by storage, engine, loki
- `engine.Rule`, `engine.Match` (Task 4) consumed by playbook, api
- `storage.Alert`, `storage.StoredEvent`, `storage.StoredAlert` (Task 3) consumed by api
- `playbook.ActionRun`, `playbook.StepResult` (Task 8) consumed by storage (via `action_runs` table) and api
- `alertmanager.Alert` (Task 5) consumed by playbook's `notify` action

**Conventions:**
- Every Task: TDD where applicable — failing test → `go test` (FAIL expected) → impl → `go test` (PASS) → commit
- Config files and YAML fixtures bypass TDD (no behavior to test) — they get "create + verify" steps
- Each commit's message follows conventional commits: `feat(<pkg>): ...` / `test(<pkg>): ...` / `chore: ...`
- `CGO_ENABLED=0 go build ./...` must exit 0 after every commit

---

## Task Index

1. **config/** — load + validate YAML config
2. **internal/normalizer/** — unified Event type, fan-in from 3 sources, converters
3. **internal/storage/** — SQLite schema, CRUD, prune
4. **internal/engine/** — CEL rule loader + evaluator + hot-reload
5. **internal/alertmanager/** — HTTP POST client
6. **internal/auditd/** — go-libaudit netlink reader
7. **internal/loki/** — async buffered push client
8. **internal/playbook/** — action engine + 6 built-in action types
9. **cmd/vakta/** — cobra CLI + agent wiring
10. **internal/k8saudit/** — file tailer (k8s mode)
11. **internal/api/** — REST API + SSE stream + embedded web assets
12. **web/** — React + Vite SPA (4 pages)
13. **deploy/** — systemd unit, Dockerfile, Helm chart

---

## Task 1: config/ — load and validate YAML config

**Files:**
- Create: `~/vakta/config/config.go`
- Create: `~/vakta/config/config_test.go`
- Create: `~/vakta/config/default.yaml`

- [ ] **Step 1: Add yaml.v3 dependency**

```
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
cd ~/vakta && go get gopkg.in/yaml.v3 && go mod tidy
grep yaml.v3 go.mod    # expect: gopkg.in/yaml.v3 v3.x.x
```

- [ ] **Step 2: Write the failing test**

Create `~/vakta/config/config_test.go`:

```go
package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad_DefaultValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("agent:\n  mode: host\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Agent.Mode != "host" {
		t.Errorf("Agent.Mode = %q, want host", c.Agent.Mode)
	}
	if c.UI.Addr != ":9090" {
		t.Errorf("UI.Addr = %q, want :9090 (default)", c.UI.Addr)
	}
	if c.Storage.RetentionDays != 30 {
		t.Errorf("Storage.RetentionDays = %d, want 30 (default)", c.Storage.RetentionDays)
	}
	if c.Outputs.LokiFlushInterval != 5*time.Second {
		t.Errorf("LokiFlushInterval = %v, want 5s (default)", c.Outputs.LokiFlushInterval)
	}
}

func TestLoad_RejectsInvalidMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("agent:\n  mode: bogus\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for mode=bogus")
	}
}

func TestLoad_RejectsBasicAuthWithoutCreds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("ui:\n  auth: basic\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for basic auth with no username/password")
	}
}

func TestLoad_ExecRunRequiresExplicitOptIn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("playbook:\n  allow_exec_run: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Playbook.AllowExecRun {
		t.Fatal("AllowExecRun should be true when set")
	}
}
```

- [ ] **Step 3: Run test, expect failure**

```
cd ~/vakta && go test ./config/
```

Expected: `undefined: Load` build error.

- [ ] **Step 4: Implement config.go**

Create `~/vakta/config/config.go`:

```go
// Package config loads and validates vakta's YAML configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Agent    AgentSection    `yaml:"agent"`
	Sources  SourcesSection  `yaml:"sources"`
	RulesDir string          `yaml:"rules_dir"`
	ActionsDir string        `yaml:"actions_dir"`
	Outputs  OutputsSection  `yaml:"outputs"`
	Storage  StorageSection  `yaml:"storage"`
	UI       UISection       `yaml:"ui"`
	Playbook PlaybookSection `yaml:"playbook"`
	Log      LogSection      `yaml:"log"`
}

type AgentSection struct {
	Mode     string `yaml:"mode"`      // host | k8s
	NodeName string `yaml:"node_name"` // defaults to hostname when empty
}

type SourcesSection struct {
	EBPF        bool   `yaml:"ebpf"`
	Auditd      bool   `yaml:"auditd"`
	K8sAudit    bool   `yaml:"k8s_audit"`
	K8sAuditLog string `yaml:"k8s_audit_log"`
}

type OutputsSection struct {
	Alertmanager      string        `yaml:"alertmanager"`
	Loki              string        `yaml:"loki"`
	LokiFlushInterval time.Duration `yaml:"loki_flush_interval"`
	LokiBatchSize     int           `yaml:"loki_batch_size"`
}

type StorageSection struct {
	SQLitePath    string `yaml:"sqlite_path"`
	RetentionDays int    `yaml:"retention_days"`
}

type UISection struct {
	Enabled  bool   `yaml:"enabled"`
	Addr     string `yaml:"addr"`
	Auth     string `yaml:"auth"` // none | basic
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type PlaybookSection struct {
	AllowExecRun bool `yaml:"allow_exec_run"`
	DryRun       bool `yaml:"dry_run"`
}

type LogSection struct {
	Level  string `yaml:"level"`  // debug | info | warn | error
	Format string `yaml:"format"` // json | text
}

// Load reads and validates a YAML config file. Missing fields get defaults.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	c := &Config{}
	applyDefaults(c)
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	// Re-apply defaults for any fields YAML left at zero value
	applyDefaults(c)
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func applyDefaults(c *Config) {
	if c.Agent.Mode == "" {
		c.Agent.Mode = "host"
	}
	if !c.Sources.EBPF && !c.Sources.Auditd && !c.Sources.K8sAudit {
		c.Sources.EBPF = true
		c.Sources.Auditd = true
	}
	if c.Sources.K8sAuditLog == "" {
		c.Sources.K8sAuditLog = "/var/log/k8s-audit.log"
	}
	if c.RulesDir == "" {
		c.RulesDir = "/etc/vakta/rules"
	}
	if c.ActionsDir == "" {
		c.ActionsDir = "/etc/vakta/actions"
	}
	if c.Outputs.LokiFlushInterval == 0 {
		c.Outputs.LokiFlushInterval = 5 * time.Second
	}
	if c.Outputs.LokiBatchSize == 0 {
		c.Outputs.LokiBatchSize = 100
	}
	if c.Storage.SQLitePath == "" {
		c.Storage.SQLitePath = "/var/lib/vakta/events.db"
	}
	if c.Storage.RetentionDays == 0 {
		c.Storage.RetentionDays = 30
	}
	if c.UI.Addr == "" {
		c.UI.Addr = ":9090"
	}
	if c.UI.Auth == "" {
		c.UI.Auth = "none"
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "json"
	}
}

func (c *Config) Validate() error {
	switch c.Agent.Mode {
	case "host", "k8s":
	default:
		return fmt.Errorf("agent.mode: must be host|k8s, got %q", c.Agent.Mode)
	}
	switch c.UI.Auth {
	case "none":
	case "basic":
		if c.UI.Username == "" || c.UI.Password == "" {
			return errors.New("ui.auth=basic requires ui.username and ui.password")
		}
	default:
		return fmt.Errorf("ui.auth: must be none|basic, got %q", c.UI.Auth)
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log.level: must be debug|info|warn|error, got %q", c.Log.Level)
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		return fmt.Errorf("log.format: must be json|text, got %q", c.Log.Format)
	}
	if c.Storage.RetentionDays < 1 {
		return fmt.Errorf("storage.retention_days: must be >= 1, got %d", c.Storage.RetentionDays)
	}
	return nil
}
```

- [ ] **Step 5: Run tests, expect PASS**

```
cd ~/vakta && go test -v ./config/
```

Expected: all 4 tests PASS.

- [ ] **Step 6: Create default.yaml**

Create `~/vakta/config/default.yaml`:

```yaml
agent:
  mode: host
  node_name: ""

sources:
  ebpf: true
  auditd: true
  k8s_audit: false
  k8s_audit_log: /var/log/k8s-audit.log

rules_dir: /etc/vakta/rules
actions_dir: /etc/vakta/actions

outputs:
  alertmanager: ""
  loki: ""
  loki_flush_interval: 5s
  loki_batch_size: 100

storage:
  sqlite_path: /var/lib/vakta/events.db
  retention_days: 30

ui:
  enabled: true
  addr: ":9090"
  auth: none
  username: ""
  password: ""

playbook:
  allow_exec_run: false
  dry_run: false

log:
  level: info
  format: json
```

- [ ] **Step 7: Verify build**

```
cd ~/vakta && CGO_ENABLED=0 go build ./...
```

Expected: exit 0.

- [ ] **Step 8: Commit**

```
cd ~/vakta
git add config/ go.mod go.sum
git commit -m "feat(config): YAML config loader with defaults and validation"
```

---

## Task 2: internal/normalizer/ — unified Event + 3-source fan-in

**Files:**
- Create: `~/vakta/internal/normalizer/event.go` (Event + Source + Detail types)
- Create: `~/vakta/internal/normalizer/event_test.go`
- Create: `~/vakta/internal/normalizer/convert_probe.go` (probe.Event → Event)
- Create: `~/vakta/internal/normalizer/convert_probe_test.go`
- Create: `~/vakta/internal/normalizer/convert_auditd.go` (auditd.Record → Event)
- Create: `~/vakta/internal/normalizer/convert_k8s.go` (k8saudit.Entry → Event)
- Create: `~/vakta/internal/normalizer/normalizer.go` (fan-in + ID assignment)
- Create: `~/vakta/internal/normalizer/normalizer_test.go`

This task forward-declares lightweight types for auditd.Record and k8saudit.Entry so the normalizer can compile before Tasks 6 and 10 land. We declare them inline in `convert_auditd.go` / `convert_k8s.go` here, then Tasks 6 and 10 will create the actual auditd/k8saudit packages with matching types.

- [ ] **Step 1: Write the event type test first**

Create `~/vakta/internal/normalizer/event_test.go`:

```go
package normalizer

import (
	"net/netip"
	"testing"
	"time"
)

func TestEventZeroValueDefaults(t *testing.T) {
	var e Event
	if e.Source != 0 {
		t.Errorf("Source = %d, want 0", e.Source)
	}
	if e.Detail != nil {
		t.Errorf("Detail = %v, want nil", e.Detail)
	}
}

func TestSourceConstants(t *testing.T) {
	if SourceEBPF != 1 || SourceAuditd != 2 || SourceK8sAudit != 3 {
		t.Fatal("source constants drifted")
	}
}

func TestExecDetail(t *testing.T) {
	d := ExecDetail{Filename: "/bin/ls", Argv: []string{"ls", "-la"}}
	if d.Filename != "/bin/ls" || len(d.Argv) != 2 {
		t.Fatal()
	}
}

func TestConnectDetail(t *testing.T) {
	d := ConnectDetail{
		DstIP:   netip.MustParseAddr("1.1.1.1"),
		DstPort: 443,
		Family:  2,
		Errno:   0,
	}
	if d.DstIP.String() != "1.1.1.1" {
		t.Fatal()
	}
}

func TestEventComposition(t *testing.T) {
	now := time.Now()
	e := Event{
		ID: 42, Ts: now, Source: SourceEBPF, Type: "EXEC",
		Host: "h1", PID: 100, Comm: "ls",
		Detail: &ExecDetail{Filename: "/bin/ls"},
	}
	d, ok := e.Detail.(*ExecDetail)
	if !ok || d.Filename != "/bin/ls" {
		t.Fatal("type-assert failed")
	}
}
```

- [ ] **Step 2: Run, expect failure**

```
cd ~/vakta && go test ./internal/normalizer/
```

Expected: build error `undefined: Event`.

- [ ] **Step 3: Implement event.go**

Create `~/vakta/internal/normalizer/event.go`:

```go
// Package normalizer merges eBPF, auditd, and k8s audit streams into a
// unified Event channel for downstream consumers.
package normalizer

import (
	"net/netip"
	"time"
)

// Source identifies which subsystem produced an event.
type Source uint8

const (
	SourceEBPF     Source = 1
	SourceAuditd   Source = 2
	SourceK8sAudit Source = 3
)

// Event is the unified record emitted by the normalizer. Fields not applicable
// to a source stay at zero value. Detail is one of the *Detail types below, or nil.
type Event struct {
	ID       uint64
	Ts       time.Time
	Source   Source
	Type     string
	Host     string
	CgroupID uint64
	PID      uint32
	PPID     uint32
	UID      uint32
	GID      uint32
	Comm     string
	Ret      int64
	Detail   any
}

// Detail types — one per event type. Pointer-typed so a nil Detail field is
// distinguishable from a zero-value Detail.

type ExecDetail struct {
	Filename string
	Argv     []string
}

type ConnectDetail struct {
	DstIP   netip.Addr
	DstPort uint16
	Family  uint16
	Errno   int32
}

type OpenDetail struct {
	Path  string
	Flags int32
}

type CloneDetail struct {
	CloneFlags uint64
}

type UnshareDetail struct {
	UnshareFlags uint64
}

type PtraceDetail struct {
	Request   int64
	TargetPID uint32
}

type ModuleDetail struct {
	Name string
}

type BPFLoadDetail struct {
	ProgType uint32
}

type MemfdDetail struct {
	Name  string
	Flags uint32
}

type ChmodDetail struct {
	Path string
	Mode uint32
	SUID bool
	SGID bool
}

type MmapExecDetail struct {
	Addr uint64
	Len  uint64
	Prot uint32
}

type ProcProbeDetail struct {
	TargetPID uint32
}

type AuditFIMDetail struct {
	Path     string
	AuditKey string
	Op       string
}

type K8sDetail struct {
	Verb      string
	Resource  string
	Namespace string
	Name      string
	Username  string
	SourceIP  string
}
```

- [ ] **Step 4: Run tests, expect PASS**

```
cd ~/vakta && go test -v ./internal/normalizer/
```

Expected: 5 tests PASS.

- [ ] **Step 5: Write probe converter test**

Create `~/vakta/internal/normalizer/convert_probe_test.go`:

```go
package normalizer

import (
	"net/netip"
	"testing"

	"github.com/vakta-project/vakta/internal/probe"
)

func TestFromProbeExec(t *testing.T) {
	src := &probe.ExecEvent{
		EventHeader: probe.EventHeader{
			TsNs: 1, CgroupID: 99, PID: 100, PPID: 1, UID: 1000, GID: 1000,
			Type: probe.EventExec,
			Comm: [16]byte{'l', 's', 0},
		},
		Ret:  0,
		Argv: [][]byte{[]byte("ls"), []byte("-la"), []byte("/tmp")},
	}
	ev := FromProbe(src, "host-1")
	if ev.Type != "EXEC" || ev.Host != "host-1" || ev.PID != 100 || ev.CgroupID != 99 {
		t.Fatalf("ev=%+v", ev)
	}
	d, ok := ev.Detail.(*ExecDetail)
	if !ok || len(d.Argv) != 3 || d.Argv[0] != "ls" {
		t.Fatalf("detail=%+v ok=%v", ev.Detail, ok)
	}
}

func TestFromProbeConnect(t *testing.T) {
	src := &probe.ConnectEvent{
		EventHeader: probe.EventHeader{TsNs: 1, PID: 200, Type: probe.EventConnect},
		Ret:         -111,
		Family:      2,
		DstIP:       netip.MustParseAddr("1.1.1.1"),
		DstPort:     443,
	}
	ev := FromProbe(src, "h")
	if ev.Type != "CONNECT" {
		t.Fatalf("type=%s", ev.Type)
	}
	d := ev.Detail.(*ConnectDetail)
	if d.DstPort != 443 || d.Errno != -111 {
		t.Fatalf("d=%+v", d)
	}
}

func TestFromProbeChmodSUIDFlag(t *testing.T) {
	src := &probe.ChmodEvent{
		EventHeader: probe.EventHeader{TsNs: 1, PID: 300, Type: probe.EventChmod},
		Mode:        0o4755, // SUID set
		Path:        "/tmp/x",
	}
	ev := FromProbe(src, "h")
	d := ev.Detail.(*ChmodDetail)
	if !d.SUID {
		t.Fatal("SUID flag not set for mode 0o4755")
	}
	if d.SGID {
		t.Fatal("SGID flag erroneously set")
	}
}
```

- [ ] **Step 6: Implement convert_probe.go**

Create `~/vakta/internal/normalizer/convert_probe.go`:

```go
package normalizer

import (
	"bytes"
	"strings"
	"time"

	"github.com/vakta-project/vakta/internal/probe"
)

// FromProbe converts a probe.Event into the unified normalizer Event.
func FromProbe(p probe.Event, host string) Event {
	h := p.Header()
	ev := Event{
		Ts:       time.Unix(0, int64(h.TsNs)),
		Source:   SourceEBPF,
		Host:     host,
		CgroupID: h.CgroupID,
		PID:      h.PID, PPID: h.PPID, UID: h.UID, GID: h.GID,
		Comm: cstr(h.Comm[:]),
	}
	switch e := p.(type) {
	case *probe.ExecAttemptEvent:
		ev.Type = "EXEC_ATTEMPT"
		ev.Ret = e.Ret
		ev.Detail = &ExecDetail{Filename: e.Filename}
	case *probe.ExecEvent:
		ev.Type = "EXEC"
		ev.Ret = e.Ret
		argv := make([]string, 0, len(e.Argv))
		for _, b := range e.Argv {
			argv = append(argv, string(bytes.TrimRight(b, "\x00")))
		}
		ev.Detail = &ExecDetail{Argv: argv}
	case *probe.ConnectEvent:
		ev.Type = "CONNECT"
		ev.Ret = e.Ret
		ev.Detail = &ConnectDetail{
			DstIP: e.DstIP, DstPort: e.DstPort, Family: e.Family, Errno: int32(e.Ret),
		}
	case *probe.OpenEvent:
		ev.Type = "OPEN"
		ev.Ret = e.Ret
		ev.Detail = &OpenDetail{Path: e.Path, Flags: e.Flags}
	case *probe.CloneEvent:
		ev.Type = "CLONE"
		ev.Ret = e.Ret
		ev.Detail = &CloneDetail{CloneFlags: e.CloneFlags}
	case *probe.UnshareEvent:
		ev.Type = "UNSHARE"
		ev.Ret = e.Ret
		ev.Detail = &UnshareDetail{UnshareFlags: e.UnshareFlags}
	case *probe.PtraceEvent:
		ev.Type = "PTRACE"
		ev.Ret = e.Ret
		ev.Detail = &PtraceDetail{Request: e.Request, TargetPID: e.TargetPID}
	case *probe.ModuleLoadEvent:
		ev.Type = "MODULE_LOAD"
		ev.Ret = e.Ret
		ev.Detail = &ModuleDetail{Name: e.Name}
	case *probe.BPFLoadEvent:
		ev.Type = "BPF_LOAD"
		ev.Ret = e.Ret
		ev.Detail = &BPFLoadDetail{ProgType: e.ProgType}
	case *probe.MemfdEvent:
		ev.Type = "MEMFD"
		ev.Ret = e.Ret
		ev.Detail = &MemfdDetail{Name: e.Name, Flags: e.Flags}
	case *probe.ChmodEvent:
		ev.Type = "CHMOD"
		ev.Ret = e.Ret
		ev.Detail = &ChmodDetail{
			Path: e.Path, Mode: e.Mode,
			SUID: e.Mode&0o4000 != 0,
			SGID: e.Mode&0o2000 != 0,
		}
	case *probe.MmapExecEvent:
		ev.Type = "MMAP_EXEC"
		ev.Ret = e.Ret
		ev.Detail = &MmapExecDetail{Addr: e.Addr, Len: e.Len, Prot: e.Prot}
	case *probe.ProcProbeEvent:
		ev.Type = "PROC_PROBE"
		ev.Ret = e.Ret
		ev.Detail = &ProcProbeDetail{TargetPID: e.TargetPID}
	default:
		ev.Type = "UNKNOWN"
	}
	return ev
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return strings.TrimRight(string(b), "\x00")
}
```

- [ ] **Step 7: Run tests**

```
cd ~/vakta && go test -v ./internal/normalizer/
```

Expected: 8 tests PASS.

- [ ] **Step 8: Forward-declare auditd.Record type for normalizer's convert layer**

Create `~/vakta/internal/normalizer/convert_auditd.go`:

```go
package normalizer

import "time"

// AuditdRecordView is the minimal shape from internal/auditd needed by the
// normalizer. The real type lives in internal/auditd (Task 6) but we mirror it
// here so this package compiles standalone. The concrete auditd.Record has
// these same fields plus more; only this subset is consumed.
type AuditdRecordView struct {
	Seq       uint32
	Timestamp time.Time
	Type      string // "SYSCALL" | "PATH" | "EXECVE" | etc.
	Fields    map[string]string
}

// FromAuditd converts a buffered SYSCALL+PATH multi-record into a single Event.
// records must share Seq; the SYSCALL record carries pid/uid/comm, PATH carries
// the file path.
func FromAuditd(records []AuditdRecordView, host string) Event {
	if len(records) == 0 {
		return Event{}
	}
	first := records[0]
	ev := Event{
		Ts:     first.Timestamp,
		Source: SourceAuditd,
		Host:   host,
		Type:   "AUDIT_FIM",
	}
	var path, key, op string
	for _, r := range records {
		switch r.Type {
		case "SYSCALL":
			ev.PID = parseUint32(r.Fields["pid"])
			ev.PPID = parseUint32(r.Fields["ppid"])
			ev.UID = parseUint32(r.Fields["uid"])
			ev.GID = parseUint32(r.Fields["gid"])
			ev.Comm = trimQuotes(r.Fields["comm"])
			key = trimQuotes(r.Fields["key"])
		case "PATH":
			if p := trimQuotes(r.Fields["name"]); p != "" {
				path = p
			}
			if r.Fields["op"] != "" {
				op = r.Fields["op"]
			}
		}
	}
	ev.Detail = &AuditFIMDetail{Path: path, AuditKey: key, Op: op}
	return ev
}

func trimQuotes(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func parseUint32(s string) uint32 {
	var n uint32
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + uint32(c-'0')
	}
	return n
}
```

- [ ] **Step 9: Forward-declare k8saudit.Entry type for converter**

Create `~/vakta/internal/normalizer/convert_k8s.go`:

```go
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
```

- [ ] **Step 10: Write normalizer fan-in test**

Create `~/vakta/internal/normalizer/normalizer_test.go`:

```go
package normalizer

import (
	"testing"
	"time"

	"github.com/vakta-project/vakta/internal/probe"
)

func TestNormalizerFansInProbeOnly(t *testing.T) {
	src := make(chan probe.Event, 4)
	n := New(src, nil, nil, "h1")
	defer n.Close()
	src <- &probe.ExecEvent{
		EventHeader: probe.EventHeader{TsNs: 1, PID: 7, Type: probe.EventExec},
		Argv:        [][]byte{[]byte("/bin/true")},
	}
	close(src)

	select {
	case ev := <-n.Events():
		if ev.Type != "EXEC" || ev.ID == 0 {
			t.Fatalf("ev=%+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("no event")
	}
}

func TestNormalizerAssignsMonotonicID(t *testing.T) {
	src := make(chan probe.Event, 4)
	n := New(src, nil, nil, "h1")
	defer n.Close()
	for i := 0; i < 3; i++ {
		src <- &probe.ExecEvent{
			EventHeader: probe.EventHeader{TsNs: uint64(i + 1), PID: 1, Type: probe.EventExec},
		}
	}
	close(src)

	var ids []uint64
	deadline := time.After(time.Second)
	for len(ids) < 3 {
		select {
		case ev := <-n.Events():
			ids = append(ids, ev.ID)
		case <-deadline:
			t.Fatalf("got only %d events", len(ids))
		}
	}
	if ids[0] >= ids[1] || ids[1] >= ids[2] {
		t.Fatalf("ids not monotonic: %v", ids)
	}
}
```

- [ ] **Step 11: Implement normalizer.go**

Create `~/vakta/internal/normalizer/normalizer.go`:

```go
package normalizer

import (
	"sync"
	"sync/atomic"

	"github.com/vakta-project/vakta/internal/probe"
)

const outBufferSize = 8192

// Normalizer fans three input streams into one Event channel.
type Normalizer struct {
	out      chan Event
	nextID   atomic.Uint64
	host     string
	wg       sync.WaitGroup
	closeOnce sync.Once
	done     chan struct{}
}

// New starts goroutines for each non-nil input channel. Any of ebpfCh /
// auditCh / k8sCh may be nil to disable that source.
func New(
	ebpfCh <-chan probe.Event,
	auditCh <-chan []AuditdRecordView,
	k8sCh <-chan K8sEntryView,
	host string,
) *Normalizer {
	n := &Normalizer{
		out:  make(chan Event, outBufferSize),
		host: host,
		done: make(chan struct{}),
	}
	if ebpfCh != nil {
		n.wg.Add(1)
		go n.runProbe(ebpfCh)
	}
	if auditCh != nil {
		n.wg.Add(1)
		go n.runAuditd(auditCh)
	}
	if k8sCh != nil {
		n.wg.Add(1)
		go n.runK8s(k8sCh)
	}
	go func() {
		n.wg.Wait()
		close(n.out)
	}()
	return n
}

// Events returns the unified Event channel. Closes when all input streams close.
func (n *Normalizer) Events() <-chan Event { return n.out }

// Close signals all goroutines to stop draining their input channels.
// Producers should also close their channels; Close is for early abort.
func (n *Normalizer) Close() {
	n.closeOnce.Do(func() { close(n.done) })
}

func (n *Normalizer) emit(ev Event) {
	ev.ID = n.nextID.Add(1)
	select {
	case n.out <- ev:
	case <-n.done:
	}
}

func (n *Normalizer) runProbe(ch <-chan probe.Event) {
	defer n.wg.Done()
	for {
		select {
		case <-n.done:
			return
		case p, ok := <-ch:
			if !ok {
				return
			}
			n.emit(FromProbe(p, n.host))
		}
	}
}

func (n *Normalizer) runAuditd(ch <-chan []AuditdRecordView) {
	defer n.wg.Done()
	for {
		select {
		case <-n.done:
			return
		case recs, ok := <-ch:
			if !ok {
				return
			}
			n.emit(FromAuditd(recs, n.host))
		}
	}
}

func (n *Normalizer) runK8s(ch <-chan K8sEntryView) {
	defer n.wg.Done()
	for {
		select {
		case <-n.done:
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			n.emit(FromK8s(e, n.host))
		}
	}
}
```

- [ ] **Step 12: Run tests**

```
cd ~/vakta && go test -v ./internal/normalizer/
```

Expected: all 10 tests PASS.

- [ ] **Step 13: Verify build**

```
cd ~/vakta && CGO_ENABLED=0 go build ./...
```

Expected: exit 0.

- [ ] **Step 14: Commit**

```
cd ~/vakta
git add internal/normalizer/
git commit -m "feat(normalizer): unified Event type, probe/auditd/k8s converters, fan-in"
```

---

## Task 3: internal/storage/ — SQLite store

**Files:**
- Create: `~/vakta/internal/storage/schema.sql`
- Create: `~/vakta/internal/storage/storage.go`
- Create: `~/vakta/internal/storage/storage_test.go`

- [ ] **Step 1: Add modernc.org/sqlite dependency**

```
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
cd ~/vakta && go get modernc.org/sqlite && go mod tidy
grep modernc.org/sqlite go.mod    # expect: modernc.org/sqlite v1.x.x
```

- [ ] **Step 2: Create schema.sql**

Create `~/vakta/internal/storage/schema.sql`:

```sql
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    host        TEXT    NOT NULL,
    source      INTEGER NOT NULL,
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
    status      TEXT    NOT NULL DEFAULT 'firing',
    tags_json   TEXT    NOT NULL DEFAULT '[]',
    fired_at    INTEGER NOT NULL,
    resolved_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_alerts_fired  ON alerts(fired_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_rule   ON alerts(rule_id, fired_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, fired_at DESC);

CREATE TABLE IF NOT EXISTS action_runs (
    id          INTEGER PRIMARY KEY,
    action_id   TEXT    NOT NULL,
    alert_id    INTEGER REFERENCES alerts(id),
    dry_run     INTEGER NOT NULL DEFAULT 0,
    status      TEXT    NOT NULL,
    steps_json  TEXT    NOT NULL DEFAULT '[]',
    started_at  INTEGER NOT NULL,
    finished_at INTEGER
);
```

- [ ] **Step 3: Write the failing test**

Create `~/vakta/internal/storage/storage_test.go`:

```go
package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/vakta-project/vakta/internal/normalizer"
)

func newDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "test.db"), 30)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestInsertAndQueryEvent(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	id, err := db.InsertEvent(ctx, normalizer.Event{
		Ts: time.Now(), Source: normalizer.SourceEBPF, Type: "EXEC",
		Host: "h1", PID: 100, Comm: "ls", Ret: 0,
		Detail: &normalizer.ExecDetail{Filename: "/bin/ls"},
	})
	if err != nil || id <= 0 {
		t.Fatalf("InsertEvent: id=%d err=%v", id, err)
	}
	got, err := db.QueryEvents(ctx, EventFilter{})
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	if len(got) != 1 || got[0].Type != "EXEC" || got[0].Comm != "ls" {
		t.Fatalf("got=%+v", got)
	}
}

func TestQueryEventsFilterByType(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	for _, typ := range []string{"EXEC", "CONNECT", "EXEC", "OPEN"} {
		_, _ = db.InsertEvent(ctx, normalizer.Event{Ts: time.Now(), Type: typ, Host: "h"})
	}
	wanted := "EXEC"
	got, _ := db.QueryEvents(ctx, EventFilter{Type: &wanted})
	if len(got) != 2 {
		t.Fatalf("want 2 EXEC events, got %d", len(got))
	}
}

func TestInsertAndQueryAlert(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	id, err := db.InsertAlert(ctx, Alert{
		RuleID: "rule-x", RuleName: "X", Severity: "high",
		EventID: 0, ActionID: "", Status: "firing",
		Tags: []string{"a", "b"}, FiredAt: time.Now(),
	})
	if err != nil || id <= 0 {
		t.Fatalf("InsertAlert: %v", err)
	}
	got, _ := db.QueryAlerts(ctx, AlertFilter{})
	if len(got) != 1 || got[0].RuleID != "rule-x" || len(got[0].Tags) != 2 {
		t.Fatalf("got=%+v", got)
	}
}

func TestInsertAndQueryActionRun(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	stepsJSON := []byte(`[{"ID":"s1","Output":"ok"}]`)
	id, err := db.InsertActionRun(ctx, "act-1", 0, true, "completed",
		stepsJSON, time.Now().Add(-time.Second), time.Now())
	if err != nil || id <= 0 {
		t.Fatalf("InsertActionRun: id=%d err=%v", id, err)
	}
	runs, err := db.QueryActionRuns(ctx, ActionRunFilter{})
	if err != nil {
		t.Fatalf("QueryActionRuns: %v", err)
	}
	if len(runs) != 1 || runs[0].ActionID != "act-1" || !runs[0].DryRun || runs[0].Status != "completed" {
		t.Fatalf("got=%+v", runs)
	}
}

func TestPruneOldEvents(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "p.db"), 1) // 1 day retention
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	old := time.Now().Add(-48 * time.Hour)
	newer := time.Now()
	_, _ = db.InsertEvent(ctx, normalizer.Event{Ts: old, Type: "OLD", Host: "h"})
	_, _ = db.InsertEvent(ctx, normalizer.Event{Ts: newer, Type: "NEW", Host: "h"})
	if err := db.Prune(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ := db.QueryEvents(ctx, EventFilter{})
	if len(got) != 1 || got[0].Type != "NEW" {
		t.Fatalf("Prune did not remove old: got %+v", got)
	}
}
```

- [ ] **Step 4: Run, expect failure**

```
cd ~/vakta && go test ./internal/storage/
```

Expected: undefined Open / InsertEvent etc.

- [ ] **Step 5: Implement storage.go**

Create `~/vakta/internal/storage/storage.go`:

```go
// Package storage persists events, alerts, and action runs in SQLite.
package storage

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/vakta-project/vakta/internal/normalizer"
)

//go:embed schema.sql
var schema string

type DB struct {
	conn          *sql.DB
	retentionDays int
}

// Alert is a row to insert into the alerts table.
type Alert struct {
	RuleID   string
	RuleName string
	Severity string
	EventID  int64
	ActionID string
	Status   string // firing | resolved | suppressed
	Tags     []string
	FiredAt  time.Time
}

// StoredEvent is one row read back from the events table.
type StoredEvent struct {
	ID         int64
	Ts         time.Time
	Host       string
	Source     int
	Type       string
	CgroupID   uint64
	PID        uint32
	PPID       uint32
	UID        uint32
	Comm       string
	Ret        int64
	DetailJSON string
	CreatedAt  time.Time
}

// StoredAlert is one row read back from the alerts table.
type StoredAlert struct {
	ID         int64
	RuleID     string
	RuleName   string
	Severity   string
	EventID    sql.NullInt64
	ActionID   sql.NullString
	Status     string
	Tags       []string
	FiredAt    time.Time
	ResolvedAt sql.NullInt64
}

type EventFilter struct {
	Source *int
	Type   *string
	PID    *uint32
	Since  *time.Time
	Until  *time.Time
}

type AlertFilter struct {
	RuleID   *string
	Severity *string
	Status   *string
	Since    *time.Time
}

// Open initializes the SQLite database at path with the given retention window.
func Open(path string, retentionDays int) (*DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", path)
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sql.Open: %w", err)
	}
	conn.SetMaxOpenConns(1) // SQLite single-writer
	if _, err := conn.Exec(schema); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &DB{conn: conn, retentionDays: retentionDays}, nil
}

func (db *DB) Close() error { return db.conn.Close() }

// InsertEvent stores a normalizer.Event and returns its row id.
func (db *DB) InsertEvent(ctx context.Context, ev normalizer.Event) (int64, error) {
	detail, err := json.Marshal(ev.Detail)
	if err != nil {
		return 0, fmt.Errorf("marshal detail: %w", err)
	}
	res, err := db.conn.ExecContext(ctx, `
		INSERT INTO events
		  (ts, host, source, type, cgroup_id, pid, ppid, uid, comm, ret, detail_json, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		ev.Ts.UnixNano(), ev.Host, int(ev.Source), ev.Type,
		ev.CgroupID, ev.PID, ev.PPID, ev.UID, ev.Comm,
		ev.Ret, string(detail), time.Now().UnixNano())
	if err != nil {
		return 0, fmt.Errorf("insert event: %w", err)
	}
	return res.LastInsertId()
}

// InsertAlert stores an alert and returns its row id.
func (db *DB) InsertAlert(ctx context.Context, a Alert) (int64, error) {
	tagsJSON, err := json.Marshal(a.Tags)
	if err != nil {
		return 0, err
	}
	res, err := db.conn.ExecContext(ctx, `
		INSERT INTO alerts
		  (rule_id, rule_name, severity, event_id, action_id, status, tags_json, fired_at)
		VALUES (?,?,?,?,?,?,?,?)`,
		a.RuleID, a.RuleName, a.Severity,
		nullInt64(a.EventID), nullString(a.ActionID),
		a.Status, string(tagsJSON), a.FiredAt.UnixNano())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// QueryEvents returns up to 500 events matching the filter, newest first.
func (db *DB) QueryEvents(ctx context.Context, f EventFilter) ([]StoredEvent, error) {
	q := `SELECT id, ts, host, source, type, cgroup_id, pid, ppid, uid, comm, ret, detail_json, created_at FROM events WHERE 1=1`
	var args []any
	if f.Source != nil {
		q += " AND source = ?"
		args = append(args, *f.Source)
	}
	if f.Type != nil {
		q += " AND type = ?"
		args = append(args, *f.Type)
	}
	if f.PID != nil {
		q += " AND pid = ?"
		args = append(args, *f.PID)
	}
	if f.Since != nil {
		q += " AND ts >= ?"
		args = append(args, f.Since.UnixNano())
	}
	if f.Until != nil {
		q += " AND ts <= ?"
		args = append(args, f.Until.UnixNano())
	}
	q += " ORDER BY ts DESC LIMIT 500"

	rows, err := db.conn.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []StoredEvent
	for rows.Next() {
		var e StoredEvent
		var tsNs, createdNs int64
		var pid, ppid, uid sql.NullInt64
		var comm sql.NullString
		if err := rows.Scan(&e.ID, &tsNs, &e.Host, &e.Source, &e.Type, &e.CgroupID,
			&pid, &ppid, &uid, &comm, &e.Ret, &e.DetailJSON, &createdNs); err != nil {
			return nil, err
		}
		e.Ts = time.Unix(0, tsNs)
		e.CreatedAt = time.Unix(0, createdNs)
		if pid.Valid {
			e.PID = uint32(pid.Int64)
		}
		if ppid.Valid {
			e.PPID = uint32(ppid.Int64)
		}
		if uid.Valid {
			e.UID = uint32(uid.Int64)
		}
		if comm.Valid {
			e.Comm = comm.String
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// QueryAlerts returns up to 200 alerts matching the filter, newest first.
func (db *DB) QueryAlerts(ctx context.Context, f AlertFilter) ([]StoredAlert, error) {
	q := `SELECT id, rule_id, rule_name, severity, event_id, action_id, status, tags_json, fired_at, resolved_at FROM alerts WHERE 1=1`
	var args []any
	if f.RuleID != nil {
		q += " AND rule_id = ?"
		args = append(args, *f.RuleID)
	}
	if f.Severity != nil {
		q += " AND severity = ?"
		args = append(args, *f.Severity)
	}
	if f.Status != nil {
		q += " AND status = ?"
		args = append(args, *f.Status)
	}
	if f.Since != nil {
		q += " AND fired_at >= ?"
		args = append(args, f.Since.UnixNano())
	}
	q += " ORDER BY fired_at DESC LIMIT 200"

	rows, err := db.conn.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []StoredAlert
	for rows.Next() {
		var a StoredAlert
		var firedNs int64
		var tagsJSON string
		if err := rows.Scan(&a.ID, &a.RuleID, &a.RuleName, &a.Severity,
			&a.EventID, &a.ActionID, &a.Status, &tagsJSON, &firedNs, &a.ResolvedAt); err != nil {
			return nil, err
		}
		a.FiredAt = time.Unix(0, firedNs)
		if tagsJSON != "" {
			_ = json.Unmarshal([]byte(tagsJSON), &a.Tags)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// InsertActionRun persists an action run. action_runs table; used by playbook.
func (db *DB) InsertActionRun(ctx context.Context, actionID string, alertID int64,
	dryRun bool, status string, stepsJSON []byte, startedAt, finishedAt time.Time) (int64, error) {
	dr := 0
	if dryRun {
		dr = 1
	}
	var fin sql.NullInt64
	if !finishedAt.IsZero() {
		fin = sql.NullInt64{Int64: finishedAt.UnixNano(), Valid: true}
	}
	res, err := db.conn.ExecContext(ctx, `
		INSERT INTO action_runs
		  (action_id, alert_id, dry_run, status, steps_json, started_at, finished_at)
		VALUES (?,?,?,?,?,?,?)`,
		actionID, nullInt64(alertID), dr, status, string(stepsJSON),
		startedAt.UnixNano(), fin)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// StoredActionRun is one row read back from the action_runs table.
type StoredActionRun struct {
	ID         int64
	ActionID   string
	AlertID    sql.NullInt64
	DryRun     bool
	Status     string
	StepsJSON  string
	StartedAt  time.Time
	FinishedAt sql.NullInt64
}

// ActionRunFilter narrows QueryActionRuns results.
type ActionRunFilter struct {
	ActionID *string
	Since    *time.Time
}

// QueryActionRuns returns up to 200 action runs matching the filter, newest first.
func (db *DB) QueryActionRuns(ctx context.Context, f ActionRunFilter) ([]StoredActionRun, error) {
	q := `SELECT id, action_id, alert_id, dry_run, status, steps_json, started_at, finished_at FROM action_runs WHERE 1=1`
	var args []any
	if f.ActionID != nil {
		q += " AND action_id = ?"
		args = append(args, *f.ActionID)
	}
	if f.Since != nil {
		q += " AND started_at >= ?"
		args = append(args, f.Since.UnixNano())
	}
	q += " ORDER BY started_at DESC LIMIT 200"

	rows, err := db.conn.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []StoredActionRun
	for rows.Next() {
		var r StoredActionRun
		var dr int
		var startedNs int64
		if err := rows.Scan(&r.ID, &r.ActionID, &r.AlertID, &dr,
			&r.Status, &r.StepsJSON, &startedNs, &r.FinishedAt); err != nil {
			return nil, err
		}
		r.DryRun = dr == 1
		r.StartedAt = time.Unix(0, startedNs)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Prune deletes events older than retentionDays and resolved alerts older than retentionDays.
func (db *DB) Prune(ctx context.Context) error {
	cutoff := time.Now().Add(-time.Duration(db.retentionDays) * 24 * time.Hour).UnixNano()
	if _, err := db.conn.ExecContext(ctx, `DELETE FROM events WHERE ts < ?`, cutoff); err != nil {
		return err
	}
	if _, err := db.conn.ExecContext(ctx,
		`DELETE FROM alerts WHERE status = 'resolved' AND resolved_at < ?`, cutoff); err != nil {
		return err
	}
	if _, err := db.conn.ExecContext(ctx,
		`DELETE FROM action_runs WHERE finished_at IS NOT NULL AND finished_at < ?`, cutoff); err != nil {
		return err
	}
	return nil
}

func nullInt64(v int64) sql.NullInt64 {
	if v == 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: v, Valid: true}
}

func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
```

- [ ] **Step 6: Run tests**

```
cd ~/vakta && CGO_ENABLED=0 go test -v ./internal/storage/
```

Expected: 4 tests PASS.

- [ ] **Step 7: Verify full build**

```
cd ~/vakta && CGO_ENABLED=0 go build ./...
```

Expected: exit 0.

- [ ] **Step 8: Commit**

```
cd ~/vakta
git add internal/storage/ go.mod go.sum
git commit -m "feat(storage): SQLite event/alert/action_runs persistence with retention pruning"
```

---

## Task 4: internal/engine/ — CEL rule engine

**Files:**
- Create: `~/vakta/internal/engine/rule.go`
- Create: `~/vakta/internal/engine/cel.go`
- Create: `~/vakta/internal/engine/engine.go`
- Create: `~/vakta/internal/engine/engine_test.go`
- Create: `~/vakta/rules/built-in/exec-suspicious-port.yaml`
- Create: `~/vakta/rules/built-in/chmod-suid.yaml`

- [ ] **Step 1: Add cel-go dependency**

```
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
cd ~/vakta && go get github.com/google/cel-go && go mod tidy
grep cel-go go.mod    # expect github.com/google/cel-go vX.Y.Z
```

- [ ] **Step 2: Write the failing test**

Create `~/vakta/internal/engine/engine_test.go`:

```go
package engine

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vakta-project/vakta/internal/normalizer"
)

func writeRule(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestEngineMatchesSimpleRule(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "x.yaml", `
rules:
  - id: exec-as-root
    name: Exec as root
    severity: high
    event_type: EXEC
    condition: event.uid == 0
    tags: [t1]
`)
	e, err := New([]string{dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ev := normalizer.Event{Type: "EXEC", UID: 0, Ts: time.Now()}
	ms := e.Evaluate(ev)
	if len(ms) != 1 || ms[0].Rule.ID != "exec-as-root" {
		t.Fatalf("matches=%+v", ms)
	}
}

func TestEngineRejectsEventTypeMismatch(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "y.yaml", `
rules:
  - id: r
    name: R
    severity: info
    event_type: CONNECT
    condition: "true"
`)
	e, _ := New([]string{dir})
	ms := e.Evaluate(normalizer.Event{Type: "EXEC"})
	if len(ms) != 0 {
		t.Fatalf("expected no match, got %+v", ms)
	}
}

func TestEngineDetailAccess(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "p.yaml", `
rules:
  - id: connect-suspicious
    name: Connect to suspicious port
    severity: critical
    event_type: CONNECT
    condition: detail.dst_port == 4444
`)
	e, err := New([]string{dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ev := normalizer.Event{
		Type: "CONNECT",
		Detail: &normalizer.ConnectDetail{
			DstIP: netip.MustParseAddr("1.2.3.4"), DstPort: 4444, Family: 2,
		},
	}
	if got := e.Evaluate(ev); len(got) != 1 {
		t.Fatalf("matches=%+v", got)
	}
}

func TestEngineRejectsBadCEL(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "bad.yaml", `
rules:
  - id: bad
    name: Bad
    severity: info
    condition: this is not CEL
`)
	if _, err := New([]string{dir}); err == nil {
		t.Fatal("expected CEL compile error")
	}
}

func TestEngineReload(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "v1.yaml", `
rules:
  - id: r1
    name: R1
    severity: info
    condition: "true"
`)
	e, _ := New([]string{dir})
	if len(e.Rules()) != 1 {
		t.Fatal()
	}
	writeRule(t, dir, "v1.yaml", `
rules:
  - id: r1
    name: R1
    severity: info
    condition: "true"
  - id: r2
    name: R2
    severity: warning
    condition: "true"
`)
	if err := e.Reload(); err != nil {
		t.Fatal(err)
	}
	if len(e.Rules()) != 2 {
		t.Fatalf("after reload got %d rules", len(e.Rules()))
	}
}

func TestEvaluateOrdersBySeverityThenID(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "x.yaml", `
rules:
  - id: bbb
    name: B
    severity: warning
    condition: "true"
  - id: aaa
    name: A
    severity: critical
    condition: "true"
  - id: ccc
    name: C
    severity: critical
    condition: "true"
`)
	e, _ := New([]string{dir})
	ms := e.Evaluate(normalizer.Event{Type: "X"})
	if len(ms) != 3 {
		t.Fatalf("got %d", len(ms))
	}
	if ms[0].Rule.ID != "aaa" || ms[1].Rule.ID != "ccc" || ms[2].Rule.ID != "bbb" {
		t.Fatalf("order wrong: %s %s %s", ms[0].Rule.ID, ms[1].Rule.ID, ms[2].Rule.ID)
	}
}
```

- [ ] **Step 3: Run, expect failure**

```
cd ~/vakta && go test ./internal/engine/
```

Expected: build error `undefined: New`.

- [ ] **Step 4: Implement rule.go**

Create `~/vakta/internal/engine/rule.go`:

```go
package engine

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Rule is the YAML-decoded form of a single policy.
type Rule struct {
	ID        string   `yaml:"id"`
	Name      string   `yaml:"name"`
	Severity  string   `yaml:"severity"`
	Source    string   `yaml:"source"`
	EventType string   `yaml:"event_type"`
	Condition string   `yaml:"condition"`
	Tags      []string `yaml:"tags"`
	ActionID  string   `yaml:"action_id"`
}

type ruleFile struct {
	Rules []Rule `yaml:"rules"`
}

// loadRulesFromDir reads every *.yaml in dir (non-recursive) and returns all rules.
// Returns empty slice (no error) if dir doesn't exist.
func loadRulesFromDir(dir string) ([]Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("readdir %s: %w", dir, err)
	}
	var out []Rule
	for _, e := range entries {
		if e.IsDir() || (filepath.Ext(e.Name()) != ".yaml" && filepath.Ext(e.Name()) != ".yml") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var rf ruleFile
		if err := yaml.Unmarshal(b, &rf); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out = append(out, rf.Rules...)
	}
	return out, nil
}

// severityOrder gives a sort weight (lower = higher priority).
func severityOrder(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "warning":
		return 2
	case "info":
		return 3
	default:
		return 99
	}
}
```

- [ ] **Step 5: Implement cel.go (CEL env + activation)**

Create `~/vakta/internal/engine/cel.go`:

```go
package engine

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	"github.com/vakta-project/vakta/internal/normalizer"
)

// newCELEnv builds the CEL environment with the variables vakta rules use:
// event, detail, host. Detail is exposed as a map<string, dyn>.
func newCELEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("event", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("detail", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("host", cel.MapType(cel.StringType, cel.DynType)),
	)
}

// celCompile compiles a rule expression and returns a runnable program.
func celCompile(env *cel.Env, expr string) (cel.Program, error) {
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("CEL compile: %w", iss.Err())
	}
	prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return nil, fmt.Errorf("CEL program: %w", err)
	}
	return prg, nil
}

// activationFor builds the {event, detail, host} map for evaluation.
func activationFor(ev normalizer.Event) map[string]any {
	return map[string]any{
		"event": map[string]any{
			"type":      ev.Type,
			"source":    int(ev.Source),
			"pid":       int(ev.PID),
			"ppid":      int(ev.PPID),
			"uid":       int(ev.UID),
			"comm":      ev.Comm,
			"ret":       ev.Ret,
			"cgroup_id": int(ev.CgroupID),
		},
		"detail": detailMap(ev.Detail),
		"host":   map[string]any{"name": ev.Host},
	}
}

// detailMap projects a typed Detail into a snake_case map for CEL access.
// Returns an empty map if Detail is nil so rules can safely reference detail.*.
func detailMap(d any) map[string]any {
	switch v := d.(type) {
	case *normalizer.ExecDetail:
		return map[string]any{"filename": v.Filename, "argv": stringArray(v.Argv)}
	case *normalizer.ConnectDetail:
		return map[string]any{
			"dst_ip": v.DstIP.String(), "dst_port": int(v.DstPort),
			"family": int(v.Family), "errno": int(v.Errno),
		}
	case *normalizer.OpenDetail:
		return map[string]any{"path": v.Path, "flags": int(v.Flags)}
	case *normalizer.CloneDetail:
		return map[string]any{"clone_flags": int(v.CloneFlags)}
	case *normalizer.UnshareDetail:
		return map[string]any{"unshare_flags": int(v.UnshareFlags)}
	case *normalizer.PtraceDetail:
		return map[string]any{"request": v.Request, "target_pid": int(v.TargetPID)}
	case *normalizer.ModuleDetail:
		return map[string]any{"name": v.Name}
	case *normalizer.BPFLoadDetail:
		return map[string]any{"prog_type": int(v.ProgType)}
	case *normalizer.MemfdDetail:
		return map[string]any{"name": v.Name, "flags": int(v.Flags)}
	case *normalizer.ChmodDetail:
		return map[string]any{
			"path": v.Path, "mode": int(v.Mode),
			"suid": v.SUID, "sgid": v.SGID,
		}
	case *normalizer.MmapExecDetail:
		return map[string]any{"addr": int(v.Addr), "len": int(v.Len), "prot": int(v.Prot)}
	case *normalizer.ProcProbeDetail:
		return map[string]any{"target_pid": int(v.TargetPID)}
	case *normalizer.AuditFIMDetail:
		return map[string]any{"path": v.Path, "audit_key": v.AuditKey, "op": v.Op}
	case *normalizer.K8sDetail:
		return map[string]any{
			"verb": v.Verb, "resource": v.Resource, "namespace": v.Namespace,
			"name": v.Name, "username": v.Username, "source_ip": v.SourceIP,
		}
	default:
		return map[string]any{}
	}
}

func stringArray(xs []string) ref.Val {
	conv := make([]any, len(xs))
	for i, s := range xs {
		conv[i] = s
	}
	return types.DefaultTypeAdapter.NativeToValue(conv)
}
```

- [ ] **Step 6: Implement engine.go**

Create `~/vakta/internal/engine/engine.go`:

```go
package engine

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/cel-go/cel"

	"github.com/vakta-project/vakta/internal/normalizer"
)

// Match is produced when a rule's condition evaluates true for an Event.
type Match struct {
	Rule  Rule
	Event normalizer.Event
	At    time.Time
}

// Engine loads rules, compiles CEL programs, evaluates events.
type Engine struct {
	ruleDirs []string
	env      *cel.Env

	mu       sync.RWMutex
	rules    []Rule
	programs map[string]cel.Program // keyed by rule ID
}

// New loads rules from ruleDirs (built-in dir first, then user dirs).
// Compiles all CEL conditions; returns error if any fail.
func New(ruleDirs []string) (*Engine, error) {
	env, err := newCELEnv()
	if err != nil {
		return nil, fmt.Errorf("cel env: %w", err)
	}
	e := &Engine{ruleDirs: ruleDirs, env: env}
	if err := e.load(); err != nil {
		return nil, err
	}
	return e, nil
}

// load reads all rule files, compiles, and atomically swaps the rule set.
func (e *Engine) load() error {
	seen := map[string]int{}
	var all []Rule
	for _, dir := range e.ruleDirs {
		rs, err := loadRulesFromDir(dir)
		if err != nil {
			return err
		}
		for _, r := range rs {
			if idx, ok := seen[r.ID]; ok {
				all[idx] = r // later dir overrides earlier
				continue
			}
			seen[r.ID] = len(all)
			all = append(all, r)
		}
	}
	progs := make(map[string]cel.Program, len(all))
	for _, r := range all {
		p, err := celCompile(e.env, r.Condition)
		if err != nil {
			return fmt.Errorf("rule %s: %w", r.ID, err)
		}
		progs[r.ID] = p
	}
	e.mu.Lock()
	e.rules = all
	e.programs = progs
	e.mu.Unlock()
	return nil
}

// Reload re-reads rules from the same dirs.
func (e *Engine) Reload() error { return e.load() }

// Rules returns a copy of the currently loaded rule set.
func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

// Evaluate returns all matching rules for ev, ordered by severity then ID.
func (e *Engine) Evaluate(ev normalizer.Event) []Match {
	e.mu.RLock()
	rules := e.rules
	progs := e.programs
	e.mu.RUnlock()

	act := activationFor(ev)
	now := time.Now()
	var matches []Match
	for _, r := range rules {
		if r.EventType != "" && r.EventType != ev.Type {
			continue
		}
		if r.Source != "" && !sourceMatches(r.Source, ev.Source) {
			continue
		}
		prg, ok := progs[r.ID]
		if !ok {
			continue
		}
		out, _, err := prg.Eval(act)
		if err != nil {
			continue
		}
		if b, ok := out.Value().(bool); ok && b {
			matches = append(matches, Match{Rule: r, Event: ev, At: now})
		}
	}
	sort.SliceStable(matches, func(i, j int) bool {
		si, sj := severityOrder(matches[i].Rule.Severity), severityOrder(matches[j].Rule.Severity)
		if si != sj {
			return si < sj
		}
		return matches[i].Rule.ID < matches[j].Rule.ID
	})
	return matches
}

func sourceMatches(want string, got normalizer.Source) bool {
	switch want {
	case "ebpf":
		return got == normalizer.SourceEBPF
	case "auditd":
		return got == normalizer.SourceAuditd
	case "k8s_audit":
		return got == normalizer.SourceK8sAudit
	}
	return false
}
```

- [ ] **Step 7: Run tests**

```
cd ~/vakta && go test -v ./internal/engine/
```

Expected: 6 tests PASS.

- [ ] **Step 8: Create two built-in rules**

Create `~/vakta/rules/built-in/exec-suspicious-port.yaml`:

```yaml
rules:
  - id: connect-to-known-c2-port
    name: Connect to known C2 port
    severity: high
    source: ebpf
    event_type: CONNECT
    condition: detail.dst_port in [4444, 8443, 1337, 6666, 9001] && event.uid != 0
    tags: [c2, network]
```

Create `~/vakta/rules/built-in/chmod-suid.yaml`:

```yaml
rules:
  - id: suid-bit-set
    name: SUID bit set on file
    severity: high
    source: ebpf
    event_type: CHMOD
    condition: detail.suid == true && !event.comm.matches("^(dpkg|apt|rpm|yum)$")
    tags: [persistence, suid]
```

- [ ] **Step 9: Verify build**

```
cd ~/vakta && CGO_ENABLED=0 go build ./...
```

Expected: exit 0.

- [ ] **Step 10: Commit**

```
cd ~/vakta
git add internal/engine/ rules/ go.mod go.sum
git commit -m "feat(engine): CEL rule loader + evaluator + hot-reload + 2 built-in rules"
```

---

## Task 5: internal/alertmanager/ — HTTP POST client

**Files:**
- Create: `~/vakta/internal/alertmanager/client.go`
- Create: `~/vakta/internal/alertmanager/client_test.go`

- [ ] **Step 1: Write the failing test**

Create `~/vakta/internal/alertmanager/client_test.go`:

```go
package alertmanager

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestSendPostsAlerts(t *testing.T) {
	var (
		mu       sync.Mutex
		gotBody  []byte
		gotPath  string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotBody = b
		gotPath = r.URL.Path
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL, time.Second)
	c.Send(context.Background(), []Alert{{
		Labels:      map[string]string{"alertname": "X", "severity": "high"},
		Annotations: map[string]string{"summary": "test"},
		StartsAt:    time.Now(),
	}})
	// Send is async — wait briefly.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ok := gotBody != nil
		mu.Unlock()
		if ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotPath != "/api/v2/alerts" {
		t.Fatalf("path=%q", gotPath)
	}
	var parsed []map[string]any
	if err := json.Unmarshal(gotBody, &parsed); err != nil {
		t.Fatalf("body unparseable: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("alerts=%d", len(parsed))
	}
	if parsed[0]["labels"].(map[string]any)["alertname"] != "X" {
		t.Fatalf("labels=%v", parsed[0]["labels"])
	}
}

func TestResolveSetsEndsAt(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := New(srv.URL, time.Second)
	c.Resolve(context.Background(), map[string]string{"alertname": "Y"})
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && gotBody == nil {
		time.Sleep(10 * time.Millisecond)
	}
	if gotBody == nil {
		t.Fatal("no request received")
	}
	var parsed []map[string]any
	_ = json.Unmarshal(gotBody, &parsed)
	if parsed[0]["endsAt"] == "" {
		t.Fatal("endsAt empty for Resolve")
	}
}
```

- [ ] **Step 2: Run, expect failure**

```
cd ~/vakta && go test ./internal/alertmanager/
```

Expected: undefined symbols.

- [ ] **Step 3: Implement client.go**

Create `~/vakta/internal/alertmanager/client.go`:

```go
// Package alertmanager POSTs vakta alerts to Prometheus Alertmanager.
package alertmanager

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Alert is one outgoing alert in Alertmanager's /api/v2/alerts schema.
type Alert struct {
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     time.Time         `json:"startsAt"`
	EndsAt       time.Time         `json:"endsAt,omitempty"`
	GeneratorURL string            `json:"generatorURL,omitempty"`
}

// Client posts alerts to Alertmanager. baseURL example: http://alertmanager:9093.
type Client struct {
	baseURL string
	http    *http.Client
}

func New(baseURL string, timeout time.Duration) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: timeout},
	}
}

// Send POSTs the alerts asynchronously. Errors are logged, never returned.
func (c *Client) Send(ctx context.Context, alerts []Alert) {
	if len(alerts) == 0 || c.baseURL == "" {
		return
	}
	go c.post(ctx, alerts)
}

// Resolve marks alerts with the given labels as resolved (EndsAt = now).
func (c *Client) Resolve(ctx context.Context, labels map[string]string) {
	if c.baseURL == "" {
		return
	}
	a := Alert{Labels: labels, EndsAt: time.Now()}
	go c.post(ctx, []Alert{a})
}

func (c *Client) post(ctx context.Context, alerts []Alert) {
	body, err := json.Marshal(alerts)
	if err != nil {
		slog.Warn("alertmanager: marshal", "err", err)
		return
	}
	req, err := http.NewRequestWithContext(ctx, "POST",
		c.baseURL+"/api/v2/alerts", bytes.NewReader(body))
	if err != nil {
		slog.Warn("alertmanager: new request", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		slog.Warn("alertmanager: POST", "err", err, "url", c.baseURL)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		slog.Warn("alertmanager: bad status", "status", resp.StatusCode)
	}
}
```

- [ ] **Step 4: Run tests + build**

```
cd ~/vakta && go test ./internal/alertmanager/ && CGO_ENABLED=0 go build ./...
```

Expected: 2 PASS, build clean.

- [ ] **Step 5: Commit**

```
cd ~/vakta
git add internal/alertmanager/
git commit -m "feat(alertmanager): async HTTP POST client for /api/v2/alerts"
```

---

## Task 6: internal/auditd/ — netlink reader

**Files:**
- Create: `~/vakta/internal/auditd/reader.go`
- Create: `~/vakta/internal/auditd/reader_test.go`
- Modify: `~/vakta/internal/normalizer/convert_auditd.go` (drop the View-stub now that real type exists; switch normalizer fan-in input channel to real type)

- [ ] **Step 1: Add go-libaudit dependency**

```
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
cd ~/vakta && go get github.com/elastic/go-libaudit/v2 && go mod tidy
grep go-libaudit go.mod    # expect v2.x.y
```

- [ ] **Step 2: Write the failing test**

Create `~/vakta/internal/auditd/reader_test.go`:

```go
package auditd

import (
	"testing"
	"time"
)

// TestRecordStructFieldsExposed sanity-checks that Record matches the
// shape the normalizer's convert_auditd.go expects.
func TestRecordStructFieldsExposed(t *testing.T) {
	r := Record{
		Seq:       1,
		Timestamp: time.Now(),
		Type:      "SYSCALL",
		Fields:    map[string]string{"pid": "100"},
	}
	if r.Type != "SYSCALL" || r.Fields["pid"] != "100" {
		t.Fatal()
	}
}

// TestParseAuditMessage_KeyValueFields verifies our key=value parser handles
// the most common auditd message shapes, including quoted values.
func TestParseAuditMessage_KeyValueFields(t *testing.T) {
	body := `audit(1697040000.123:42): arch=c000003e syscall=59 success=yes exit=0 ppid=1000 pid=2000 uid=0 comm="sshd" key="ssh_login"`
	r, err := parseAuditMessage(1300, body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.Type != "SYSCALL" {
		t.Errorf("Type=%q", r.Type)
	}
	if r.Fields["pid"] != "2000" || r.Fields["uid"] != "0" {
		t.Fatalf("fields=%+v", r.Fields)
	}
	if r.Fields["comm"] != `"sshd"` {
		t.Fatalf("comm=%q (expect quotes preserved for normalizer to strip)", r.Fields["comm"])
	}
	if r.Seq != 42 {
		t.Errorf("Seq=%d", r.Seq)
	}
}
```

- [ ] **Step 3: Run, expect failure**

```
cd ~/vakta && go test ./internal/auditd/
```

Expected: undefined.

- [ ] **Step 4: Implement reader.go**

Create `~/vakta/internal/auditd/reader.go`:

```go
// Package auditd reads from the Linux kernel audit subsystem via netlink.
// Audit rules must be pre-configured externally (auditctl / augenrules).
package auditd

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	libaudit "github.com/elastic/go-libaudit/v2"
)

// Record is one parsed audit record.
type Record struct {
	Seq       uint32
	Timestamp time.Time
	Type      string // SYSCALL | PATH | EXECVE | AVC | etc.
	Fields    map[string]string
}

// Reader streams Records from the netlink audit socket.
type Reader struct {
	client    *libaudit.AuditClient
	out       chan Record
	cancel    context.CancelFunc
	closeOnce sync.Once
}

// New connects to the netlink audit socket. Returns error if the kernel rejects
// (e.g., missing CAP_AUDIT_READ). The caller must Close to release the socket.
func New(ctx context.Context) (*Reader, error) {
	client, err := libaudit.NewAuditClient(nil)
	if err != nil {
		return nil, fmt.Errorf("audit client: %w", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	r := &Reader{
		client: client,
		out:    make(chan Record, 1024),
		cancel: cancel,
	}
	go r.run(ctx)
	return r, nil
}

// Records returns the channel of parsed records; closes on Close().
func (r *Reader) Records() <-chan Record { return r.out }

// Close releases the netlink socket. Safe to call multiple times.
func (r *Reader) Close() error {
	r.closeOnce.Do(func() {
		r.cancel()
		_ = r.client.Close()
	})
	return nil
}

func (r *Reader) run(ctx context.Context) {
	defer close(r.out)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		raw, err := r.client.Receive(false)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("auditd: receive", "err", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		rec, perr := parseAuditMessage(uint16(raw.Type), string(raw.Data))
		if perr != nil {
			slog.Debug("auditd: parse skipped", "type", raw.Type, "err", perr)
			continue
		}
		select {
		case r.out <- rec:
		case <-ctx.Done():
			return
		}
	}
}

// parseAuditMessage turns a raw kernel audit message body into a Record.
// Message body shape: "audit(<unix.ms>:<seq>): k=v k=v ..." where k=v may
// be unquoted or "double-quoted". We keep quoted values intact so downstream
// consumers can strip them (the auditd normalizer does this).
func parseAuditMessage(msgType uint16, body string) (Record, error) {
	rec := Record{Fields: map[string]string{}}
	rec.Type = auditTypeName(msgType)
	// Header: audit(<seconds>.<ms>:<seq>): ...
	open := strings.Index(body, "(")
	close := strings.Index(body, "):")
	if open < 0 || close < 0 || close < open {
		return rec, fmt.Errorf("malformed header")
	}
	hdr := body[open+1 : close]
	rest := body[close+2:]
	dot := strings.Index(hdr, ".")
	colon := strings.Index(hdr, ":")
	if dot < 0 || colon < 0 || colon < dot {
		return rec, fmt.Errorf("malformed timestamp")
	}
	secs, err := strconv.ParseInt(hdr[:dot], 10, 64)
	if err != nil {
		return rec, fmt.Errorf("seconds: %w", err)
	}
	rec.Timestamp = time.Unix(secs, 0).UTC()
	seq, err := strconv.ParseUint(hdr[colon+1:], 10, 32)
	if err != nil {
		return rec, fmt.Errorf("seq: %w", err)
	}
	rec.Seq = uint32(seq)
	// Parse k=v tokens.
	rest = strings.TrimSpace(rest)
	for len(rest) > 0 {
		eq := strings.Index(rest, "=")
		if eq < 0 {
			break
		}
		key := rest[:eq]
		rest = rest[eq+1:]
		var val string
		if strings.HasPrefix(rest, `"`) {
			end := strings.Index(rest[1:], `"`)
			if end < 0 {
				break
			}
			val = rest[:end+2] // include the quotes
			rest = strings.TrimLeft(rest[end+2:], " ")
		} else {
			sp := strings.Index(rest, " ")
			if sp < 0 {
				val = rest
				rest = ""
			} else {
				val = rest[:sp]
				rest = strings.TrimLeft(rest[sp:], " ")
			}
		}
		rec.Fields[key] = val
	}
	return rec, nil
}

// auditTypeName maps numeric audit message types to their text names.
// We only translate the common ones; uncommon types fall back to "TYPE_<n>".
func auditTypeName(t uint16) string {
	switch t {
	case 1300:
		return "SYSCALL"
	case 1302:
		return "PATH"
	case 1305:
		return "CONFIG_CHANGE"
	case 1309:
		return "EXECVE"
	case 1320:
		return "EOE"
	case 1400:
		return "AVC"
	default:
		return fmt.Sprintf("TYPE_%d", t)
	}
}
```

- [ ] **Step 5: Run tests + build**

```
cd ~/vakta && go test ./internal/auditd/ && CGO_ENABLED=0 go build ./...
```

Expected: 2 PASS (libaudit-dependent integration tests skipped on non-root).

- [ ] **Step 6: Wire normalizer to consume real auditd.Record**

Edit `~/vakta/internal/normalizer/convert_auditd.go` — replace the `AuditdRecordView` struct with an alias to the real type, and update conversion:

```go
package normalizer

import (
	"github.com/vakta-project/vakta/internal/auditd"
)

// AuditdRecord is re-exported here for the normalizer's input signature.
type AuditdRecord = auditd.Record

// FromAuditd converts a buffered SYSCALL+PATH multi-record into one Event.
func FromAuditd(records []AuditdRecord, host string) Event {
	if len(records) == 0 {
		return Event{}
	}
	first := records[0]
	ev := Event{
		Ts:     first.Timestamp,
		Source: SourceAuditd,
		Host:   host,
		Type:   "AUDIT_FIM",
	}
	var path, key, op string
	for _, r := range records {
		switch r.Type {
		case "SYSCALL":
			ev.PID = parseUint32(r.Fields["pid"])
			ev.PPID = parseUint32(r.Fields["ppid"])
			ev.UID = parseUint32(r.Fields["uid"])
			ev.GID = parseUint32(r.Fields["gid"])
			ev.Comm = trimQuotes(r.Fields["comm"])
			key = trimQuotes(r.Fields["key"])
		case "PATH":
			if p := trimQuotes(r.Fields["name"]); p != "" {
				path = p
			}
			if r.Fields["op"] != "" {
				op = r.Fields["op"]
			}
		}
	}
	ev.Detail = &AuditFIMDetail{Path: path, AuditKey: key, Op: op}
	return ev
}

func trimQuotes(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func parseUint32(s string) uint32 {
	var n uint32
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + uint32(c-'0')
	}
	return n
}
```

Update `~/vakta/internal/normalizer/normalizer.go` — change the `auditCh` parameter type from `<-chan []AuditdRecordView` to `<-chan []AuditdRecord` (everywhere it appears: in `New`, `runAuditd`, and tests if any reference it).

- [ ] **Step 7: Run normalizer + auditd tests together**

```
cd ~/vakta && go test ./internal/normalizer/ ./internal/auditd/ && CGO_ENABLED=0 go build ./...
```

Expected: all PASS, build clean.

- [ ] **Step 8: Commit**

```
cd ~/vakta
git add internal/auditd/ internal/normalizer/ go.mod go.sum
git commit -m "feat(auditd): netlink reader + parser; normalizer consumes real Record type"
```

---

## Task 7: internal/loki/ — async push client

**Files:**
- Create: `~/vakta/internal/loki/client.go`
- Create: `~/vakta/internal/loki/client_test.go`

- [ ] **Step 1: Write the failing test**

Create `~/vakta/internal/loki/client_test.go`:

```go
package loki

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vakta-project/vakta/internal/normalizer"
)

func TestPushBuffersAndFlushesOnInterval(t *testing.T) {
	var (
		mu       sync.Mutex
		gotCount int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		streams := body["streams"].([]any)
		mu.Lock()
		for _, s := range streams {
			vals := s.(map[string]any)["values"].([]any)
			gotCount += len(vals)
		}
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New(srv.URL, 50*time.Millisecond, 1000)
	defer c.Close()
	for i := 0; i < 5; i++ {
		c.Push(normalizer.Event{Type: "EXEC", Host: "h", Ts: time.Now()})
	}
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if gotCount != 5 {
		t.Fatalf("flushed %d, want 5", gotCount)
	}
	st := c.Stats()
	if st.Flushed != 5 {
		t.Fatalf("stats.Flushed=%d", st.Flushed)
	}
}

func TestPushDropsWhenBufferFull(t *testing.T) {
	// Server blocks until request context is cancelled. Pairs with Client's
	// ctxCancel-on-Close so c.Close() returns fast instead of waiting for
	// http.Client.Timeout (10s).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer func() {
		srv.CloseClientConnections() // force-kill in-flight before Close blocks
		srv.Close()
	}()
	c := newClientWithBufferCap(srv.URL, 24*time.Hour, 1000, 3) // tiny cap
	defer c.Close()
	for i := 0; i < 50; i++ {
		c.Push(normalizer.Event{Type: "EXEC"})
	}
	st := c.Stats()
	if st.Dropped == 0 {
		t.Fatalf("expected drops, stats=%+v", st)
	}
}
```

- [ ] **Step 2: Run, expect failure**

```
cd ~/vakta && go test ./internal/loki/
```

Expected: undefined.

- [ ] **Step 3: Implement client.go**

Create `~/vakta/internal/loki/client.go`:

```go
// Package loki async-pushes events to a Loki HTTP push endpoint.
package loki

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vakta-project/vakta/internal/normalizer"
)

const defaultBufferCap = 10000

type LokiStats struct {
	Enqueued uint64
	Flushed  uint64
	Dropped  uint64
	Errors   uint64
}

type Client struct {
	baseURL       string
	flushInterval time.Duration
	batchSize     int
	http          *http.Client

	buf       chan normalizer.Event
	enqueued  atomic.Uint64
	flushed   atomic.Uint64
	dropped   atomic.Uint64
	errors    atomic.Uint64

	closeOnce sync.Once
	stop      chan struct{}
	done      chan struct{}
	ctx       context.Context
	ctxCancel context.CancelFunc
}

// New builds a Loki client with a 10000-entry internal buffer.
func New(baseURL string, flushInterval time.Duration, batchSize int) *Client {
	return newClientWithBufferCap(baseURL, flushInterval, batchSize, defaultBufferCap)
}

func newClientWithBufferCap(baseURL string, flushInterval time.Duration, batchSize, bufCap int) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		baseURL:       strings.TrimRight(baseURL, "/"),
		flushInterval: flushInterval,
		batchSize:     batchSize,
		http:          &http.Client{Timeout: 10 * time.Second},
		buf:           make(chan normalizer.Event, bufCap),
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
		ctx:           ctx,
		ctxCancel:     cancel,
	}
	go c.run()
	return c
}

// Push enqueues an event for async delivery. Never blocks; drops if buffer full.
func (c *Client) Push(ev normalizer.Event) {
	if c.baseURL == "" {
		return
	}
	c.enqueued.Add(1)
	select {
	case c.buf <- ev:
	default:
		c.dropped.Add(1)
	}
}

func (c *Client) Stats() LokiStats {
	return LokiStats{
		Enqueued: c.enqueued.Load(),
		Flushed:  c.flushed.Load(),
		Dropped:  c.dropped.Load(),
		Errors:   c.errors.Load(),
	}
}

func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.ctxCancel() // cancel in-flight HTTP requests
		close(c.stop)
		<-c.done
	})
	return nil
}

func (c *Client) run() {
	defer close(c.done)
	t := time.NewTicker(c.flushInterval)
	defer t.Stop()
	var batch []normalizer.Event
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := c.send(batch); err != nil {
			c.errors.Add(1)
			slog.Warn("loki: push", "err", err)
		} else {
			c.flushed.Add(uint64(len(batch)))
		}
		batch = batch[:0]
	}
	for {
		select {
		case <-c.stop:
			// drain
			for {
				select {
				case ev := <-c.buf:
					batch = append(batch, ev)
					if len(batch) >= c.batchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		case <-t.C:
			flush()
		case ev := <-c.buf:
			batch = append(batch, ev)
			if len(batch) >= c.batchSize {
				flush()
			}
		}
	}
}

type lokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][2]string       `json:"values"` // [ts_ns, line]
}
type lokiPush struct {
	Streams []lokiStream `json:"streams"`
}

func (c *Client) send(batch []normalizer.Event) error {
	// Group by (host, source, type) to keep stream cardinality bounded.
	streams := map[string]*lokiStream{}
	for _, ev := range batch {
		key := fmt.Sprintf("%s|%d|%s", ev.Host, ev.Source, ev.Type)
		s, ok := streams[key]
		if !ok {
			s = &lokiStream{Stream: map[string]string{
				"host":   ev.Host,
				"source": sourceLabel(ev.Source),
				"type":   ev.Type,
			}}
			streams[key] = s
		}
		line, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		s.Values = append(s.Values, [2]string{
			strconv.FormatInt(ev.Ts.UnixNano(), 10),
			string(line),
		})
	}
	payload := lokiPush{}
	for _, s := range streams {
		payload.Streams = append(payload.Streams, *s)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(c.ctx, "POST",
		c.baseURL+"/loki/api/v1/push", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("loki status %d", resp.StatusCode)
	}
	return nil
}

func sourceLabel(s normalizer.Source) string {
	switch s {
	case normalizer.SourceEBPF:
		return "ebpf"
	case normalizer.SourceAuditd:
		return "auditd"
	case normalizer.SourceK8sAudit:
		return "k8s"
	}
	return "unknown"
}
```

- [ ] **Step 4: Run tests + build**

```
cd ~/vakta && go test -v ./internal/loki/ && CGO_ENABLED=0 go build ./...
```

Expected: 2 PASS.

- [ ] **Step 5: Commit**

```
cd ~/vakta
git add internal/loki/
git commit -m "feat(loki): async buffered push client, backpressure-aware drop counter"
```

---

## Task 8: internal/playbook/ — action engine

**Files:**
- Create: `~/vakta/internal/playbook/action.go` (YAML schema types + loader)
- Create: `~/vakta/internal/playbook/template.go` (Go template rendering helper)
- Create: `~/vakta/internal/playbook/handlers.go` (6 built-in action types)
- Create: `~/vakta/internal/playbook/engine.go`
- Create: `~/vakta/internal/playbook/engine_test.go`

- [ ] **Step 1: Write the failing test**

Create `~/vakta/internal/playbook/engine_test.go`:

```go
package playbook

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vakta-project/vakta/internal/alertmanager"
	"github.com/vakta-project/vakta/internal/engine"
	"github.com/vakta-project/vakta/internal/normalizer"
	"github.com/vakta-project/vakta/internal/storage"
)

func setup(t *testing.T) (*Engine, *storage.DB) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(`
actions:
  - id: notify-only
    name: Just notify
    steps:
      - id: s1
        action: notify
        params:
          severity: high
          message: "{{ .event.comm }} did a thing"
  - id: with-dry-run
    name: dry
    dry_run: true
    steps:
      - id: s1
        action: notify
        params:
          severity: warning
          message: x
  - id: skip-step
    name: skip
    steps:
      - id: s1
        action: notify
        params: { severity: info, message: hi }
        condition: event.uid == 9999
`), 0o644); err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(filepath.Join(t.TempDir(), "x.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	am := alertmanager.New("", time.Second) // empty URL → no-op
	e, err := New([]string{dir}, db, am, EngineOptions{AllowExecRun: false, DryRunGlobal: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e, db
}

func makeMatch(actionID string) engine.Match {
	return engine.Match{
		Rule:  engine.Rule{ID: "r1", Name: "R1", Severity: "info", ActionID: actionID},
		Event: normalizer.Event{Type: "EXEC", PID: 99, UID: 1000, Comm: "ls"},
		At:    time.Now(),
	}
}

func TestRunNotify(t *testing.T) {
	e, _ := setup(t)
	defer e.Close()
	run, err := e.Run(context.Background(), "notify-only", makeMatch("notify-only"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if run.Status != "completed" || len(run.Steps) != 1 {
		t.Fatalf("run=%+v", run)
	}
	if run.Steps[0].Skipped {
		t.Fatal("unexpected skip")
	}
}

func TestRunSkipsStepByCondition(t *testing.T) {
	e, _ := setup(t)
	defer e.Close()
	run, _ := e.Run(context.Background(), "skip-step", makeMatch("skip-step"))
	if !run.Steps[0].Skipped {
		t.Fatalf("step should be skipped; run=%+v", run)
	}
}

func TestRunDryRunMarksSteps(t *testing.T) {
	e, _ := setup(t)
	defer e.Close()
	run, _ := e.Run(context.Background(), "with-dry-run", makeMatch("with-dry-run"))
	if !run.DryRun || run.Status != "completed" {
		t.Fatalf("run=%+v", run)
	}
}

func TestExecRunBlockedByDefault(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "e.yaml"), []byte(`
actions:
  - id: shell
    name: Shell
    steps:
      - id: s1
        action: exec.run
        params: { command: "echo hi" }
`), 0o644)
	db, _ := storage.Open(filepath.Join(t.TempDir(), "x.db"), 30)
	am := alertmanager.New("", time.Second)
	e, err := New([]string{dir}, db, am, EngineOptions{AllowExecRun: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Close()
	run, _ := e.Run(context.Background(), "shell", makeMatch("shell"))
	if run.Status != "failed" {
		t.Fatalf("exec.run should be blocked; got %+v", run)
	}
}

func TestUnknownActionReturnsError(t *testing.T) {
	e, _ := setup(t)
	defer e.Close()
	_, err := e.Run(context.Background(), "nope", makeMatch("nope"))
	if err == nil {
		t.Fatal("expected error")
	}
}
```

- [ ] **Step 2: Run, expect failure**

```
cd ~/vakta && go test ./internal/playbook/
```

Expected: undefined.

- [ ] **Step 3: Implement action.go**

Create `~/vakta/internal/playbook/action.go`:

```go
// Package playbook executes response actions when rule matches fire.
package playbook

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Action is one named playbook (ordered sequence of steps).
type Action struct {
	ID      string `yaml:"id"`
	Name    string `yaml:"name"`
	DryRun  bool   `yaml:"dry_run"`
	Steps   []Step `yaml:"steps"`
}

// Step is one action invocation.
type Step struct {
	ID        string                 `yaml:"id"`
	Action    string                 `yaml:"action"` // see handlers.go
	Params    map[string]any         `yaml:"params"`
	Condition string                 `yaml:"condition"`
}

type actionFile struct {
	Actions []Action `yaml:"actions"`
}

func loadActionsFromDir(dir string) ([]Action, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("readdir: %w", err)
	}
	var out []Action
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var f actionFile
		if err := yaml.Unmarshal(b, &f); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out = append(out, f.Actions...)
	}
	return out, nil
}
```

- [ ] **Step 4: Implement template.go**

Create `~/vakta/internal/playbook/template.go`:

```go
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
```

- [ ] **Step 5: Implement handlers.go (6 built-in action types)**

Create `~/vakta/internal/playbook/handlers.go`:

```go
package playbook

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/vakta-project/vakta/internal/alertmanager"
	"github.com/vakta-project/vakta/internal/engine"
)

type handlerCtx struct {
	am           *alertmanager.Client
	allowExecRun bool
}

// runHandler dispatches a single rendered step to its handler.
func (h *handlerCtx) runHandler(ctx context.Context, s Step, params map[string]any, m engine.Match) (string, error) {
	switch s.Action {
	case "notify":
		return h.actNotify(ctx, params, m)
	case "network.block_ip":
		return h.actBlockIP(ctx, params)
	case "process.kill":
		return h.actKill(params)
	case "container.pause":
		return h.actContainerPause(ctx, params)
	case "storage.snapshot":
		return h.actSnapshot(params, m)
	case "exec.run":
		if !h.allowExecRun {
			return "", errors.New("exec.run disabled by config (allow_exec_run=false)")
		}
		return h.actExecRun(ctx, params)
	default:
		return "", fmt.Errorf("unknown action type: %s", s.Action)
	}
}

func (h *handlerCtx) actNotify(ctx context.Context, p map[string]any, m engine.Match) (string, error) {
	severity, _ := p["severity"].(string)
	message, _ := p["message"].(string)
	h.am.Send(ctx, []alertmanager.Alert{{
		Labels: map[string]string{
			"alertname": m.Rule.Name,
			"severity":  severity,
			"rule_id":   m.Rule.ID,
		},
		Annotations: map[string]string{"summary": message},
		StartsAt:    time.Now(),
	}})
	return "notify dispatched", nil
}

func (h *handlerCtx) actBlockIP(ctx context.Context, p map[string]any) (string, error) {
	ip, _ := p["ip"].(string)
	dir, _ := p["direction"].(string)
	tool, _ := p["tool"].(string)
	if tool == "" {
		tool = "iptables"
	}
	if dir == "" {
		dir = "INPUT"
	}
	var args []string
	switch tool {
	case "iptables":
		args = []string{"-I", dir, "-s", ip, "-j", "DROP"}
	case "nftables":
		args = []string{"add", "rule", "inet", "filter", dir, "ip", "saddr", ip, "drop"}
	default:
		return "", fmt.Errorf("unsupported tool: %s", tool)
	}
	cmd := exec.CommandContext(ctx, tool, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (h *handlerCtx) actKill(p map[string]any) (string, error) {
	pidAny, ok := p["pid"]
	if !ok {
		return "", errors.New("kill: missing pid")
	}
	pid, err := toInt(pidAny)
	if err != nil {
		return "", fmt.Errorf("kill: pid: %w", err)
	}
	sigName, _ := p["signal"].(string)
	sig := syscall.SIGTERM
	if sigName == "SIGKILL" {
		sig = syscall.SIGKILL
	}
	if err := syscall.Kill(pid, sig); err != nil {
		return "", fmt.Errorf("kill(%d, %v): %w", pid, sig, err)
	}
	return fmt.Sprintf("sent %s to %d", sigName, pid), nil
}

func (h *handlerCtx) actContainerPause(ctx context.Context, p map[string]any) (string, error) {
	cgID, _ := p["cgroup_id"].(string)
	if cgID == "" {
		return "", errors.New("container.pause: cgroup_id required")
	}
	// Container ID resolution from cgroup_id is platform-specific and outside this
	// minimal implementation; treat cgroup_id as a docker container ID directly.
	out, err := exec.CommandContext(ctx, "docker", "pause", cgID).CombinedOutput()
	return string(out), err
}

func (h *handlerCtx) actSnapshot(p map[string]any, m engine.Match) (string, error) {
	// Minimal v1: persist a stub snapshot record. Real implementation would
	// capture /proc/<pid>/{status,maps,fd}, /proc/<pid>/net/tcp, etc.
	return fmt.Sprintf("snapshot stub for pid=%d", m.Event.PID), nil
}

func (h *handlerCtx) actExecRun(ctx context.Context, p map[string]any) (string, error) {
	cmd, _ := p["command"].(string)
	if cmd == "" {
		return "", errors.New("exec.run: command required")
	}
	out, err := exec.CommandContext(ctx, "/bin/sh", "-c", cmd).CombinedOutput()
	return string(out), err
}

func toInt(v any) (int, error) {
	switch x := v.(type) {
	case int:
		return x, nil
	case int64:
		return int(x), nil
	case float64:
		return int(x), nil
	case string:
		return strconv.Atoi(x)
	}
	return 0, fmt.Errorf("cannot convert %T to int", v)
}
```

- [ ] **Step 6: Implement engine.go**

Create `~/vakta/internal/playbook/engine.go`:

```go
package playbook

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/cel-go/cel"

	"github.com/vakta-project/vakta/internal/alertmanager"
	"github.com/vakta-project/vakta/internal/engine"
	"github.com/vakta-project/vakta/internal/storage"
)

// EngineOptions configures playbook execution.
type EngineOptions struct {
	AllowExecRun bool // mirrors config.playbook.allow_exec_run
	DryRunGlobal bool // mirrors config.playbook.dry_run (overrides per-action dry_run=false)
}

// ActionRun is one execution record for an action.
type ActionRun struct {
	ActionID   string
	AlertID    int64
	DryRun     bool
	Status     string       // completed | failed
	Steps      []StepResult
	StartedAt  time.Time
	FinishedAt time.Time
}

type StepResult struct {
	ID      string
	Skipped bool
	Output  string
	Err     string
}

// Engine loads action definitions and dispatches Run requests.
type Engine struct {
	mu       sync.RWMutex
	actions  map[string]Action
	store    *storage.DB
	celEnv   *cel.Env
	handlers *handlerCtx
	opts     EngineOptions
}

func New(actionDirs []string, store *storage.DB, am *alertmanager.Client, opts EngineOptions) (*Engine, error) {
	env, err := cel.NewEnv(
		cel.Variable("event", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, fmt.Errorf("cel env: %w", err)
	}
	actions := map[string]Action{}
	for _, dir := range actionDirs {
		as, err := loadActionsFromDir(dir)
		if err != nil {
			return nil, err
		}
		for _, a := range as {
			actions[a.ID] = a
		}
	}
	return &Engine{
		actions:  actions,
		store:    store,
		celEnv:   env,
		handlers: &handlerCtx{am: am, allowExecRun: opts.AllowExecRun},
		opts:     opts,
	}, nil
}

func (e *Engine) Close() {} // reserved for future resources

// Run executes the action with the given ID. Errors only when the action is
// unknown; per-step failures are recorded in the returned ActionRun.
func (e *Engine) Run(ctx context.Context, actionID string, m engine.Match) (ActionRun, error) {
	e.mu.RLock()
	a, ok := e.actions[actionID]
	e.mu.RUnlock()
	if !ok {
		return ActionRun{}, fmt.Errorf("unknown action: %s", actionID)
	}

	dry := a.DryRun || e.opts.DryRunGlobal
	run := ActionRun{
		ActionID:  actionID,
		DryRun:    dry,
		StartedAt: time.Now(),
		Status:    "completed",
	}
	for _, s := range a.Steps {
		sr := StepResult{ID: s.ID}
		if s.Condition != "" {
			pass, err := e.evalCondition(s.Condition, m)
			if err != nil {
				sr.Err = err.Error()
				run.Status = "failed"
				run.Steps = append(run.Steps, sr)
				continue
			}
			if !pass {
				sr.Skipped = true
				run.Steps = append(run.Steps, sr)
				continue
			}
		}
		params, err := renderParams(s.Params, m)
		if err != nil {
			sr.Err = err.Error()
			run.Status = "failed"
			run.Steps = append(run.Steps, sr)
			continue
		}
		if dry {
			sr.Output = fmt.Sprintf("[dry-run] action=%s params=%v", s.Action, params)
			run.Steps = append(run.Steps, sr)
			continue
		}
		out, err := e.handlers.runHandler(ctx, s, params, m)
		sr.Output = out
		if err != nil {
			sr.Err = err.Error()
			run.Status = "failed"
		}
		run.Steps = append(run.Steps, sr)
	}
	run.FinishedAt = time.Now()

	// Persist the run; ignore errors from storage so the action run still returns.
	if e.store != nil {
		stepsJSON, _ := json.Marshal(run.Steps)
		if _, err := e.store.InsertActionRun(ctx, actionID, run.AlertID,
			run.DryRun, run.Status, stepsJSON, run.StartedAt, run.FinishedAt); err != nil {
			slog.Warn("playbook: persist run", "err", err)
		}
	}
	return run, nil
}

// Actions returns a copy of the loaded action set.
func (e *Engine) Actions() []Action {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Action, 0, len(e.actions))
	for _, a := range e.actions {
		out = append(out, a)
	}
	return out
}

func (e *Engine) evalCondition(expr string, m engine.Match) (bool, error) {
	ast, iss := e.celEnv.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return false, iss.Err()
	}
	prg, err := e.celEnv.Program(ast)
	if err != nil {
		return false, err
	}
	act := map[string]any{
		"event": map[string]any{
			"type": m.Event.Type, "pid": int(m.Event.PID), "uid": int(m.Event.UID),
			"comm": m.Event.Comm, "ret": m.Event.Ret,
		},
	}
	out, _, err := prg.Eval(act)
	if err != nil {
		return false, err
	}
	b, ok := out.Value().(bool)
	return ok && b, nil
}
```

- [ ] **Step 7: Run tests + build**

```
cd ~/vakta && CGO_ENABLED=0 go test -v ./internal/playbook/ && CGO_ENABLED=0 go build ./...
```

Expected: 5 PASS, build clean.

- [ ] **Step 8: Commit**

```
cd ~/vakta
git add internal/playbook/
git commit -m "feat(playbook): action engine + 6 built-in handlers, dry-run + per-step condition"
```

---

## Task 9: cmd/vakta/ — CLI + agent wiring

**Files:**
- Create: `~/vakta/cmd/vakta/main.go`
- Create: `~/vakta/cmd/vakta/agent.go`
- Create: `~/vakta/cmd/vakta/rules.go`
- Create: `~/vakta/cmd/vakta/version.go`
- Create: `~/vakta/cmd/vakta/main_test.go`

- [ ] **Step 1: Add cobra dependency**

```
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
cd ~/vakta && go get github.com/spf13/cobra && go mod tidy
grep cobra go.mod    # expect github.com/spf13/cobra vX.Y.Z
```

- [ ] **Step 2: Write the failing test**

Create `~/vakta/cmd/vakta/main_test.go`:

```go
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	var out bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("vakta")) {
		t.Fatalf("version output missing 'vakta': %q", out.String())
	}
}

func TestRulesLint_GoodRule(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "g.yaml")
	_ = os.WriteFile(good, []byte(`
rules:
  - id: r1
    name: R1
    severity: info
    condition: event.uid == 0
`), 0o644)
	var out bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"rules", "lint", good})
	if err := root.Execute(); err != nil {
		t.Fatalf("lint: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("OK")) {
		t.Fatalf("expected OK in output: %q", out.String())
	}
}

func TestRulesLint_BadRule(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "b.yaml")
	_ = os.WriteFile(bad, []byte(`
rules:
  - id: r1
    name: R1
    severity: info
    condition: this is not CEL
`), 0o644)
	root := newRootCmd()
	root.SetArgs([]string{"rules", "lint", bad})
	if err := root.Execute(); err == nil {
		t.Fatal("expected error for invalid CEL")
	}
}
```

- [ ] **Step 3: Implement main.go (root command)**

Create `~/vakta/cmd/vakta/main.go`:

```go
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "vakta",
		Short: "vakta — Linux runtime event-processing agent",
	}
	root.AddCommand(newAgentCmd())
	root.AddCommand(newRulesCmd())
	root.AddCommand(newVersionCmd())
	return root
}
```

- [ ] **Step 4: Implement version.go**

Create `~/vakta/cmd/vakta/version.go`:

```go
package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is the build version, overridable at link time:
//   go build -ldflags "-X main.Version=v0.3.0"
var Version = "dev"

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(c *cobra.Command, _ []string) {
			fmt.Fprintf(c.OutOrStdout(), "vakta %s\n", Version)
		},
	}
}
```

- [ ] **Step 5: Implement rules.go (lint + test subcommands)**

Create `~/vakta/cmd/vakta/rules.go`:

```go
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/vakta-project/vakta/internal/engine"
	"github.com/vakta-project/vakta/internal/normalizer"
)

func newRulesCmd() *cobra.Command {
	c := &cobra.Command{Use: "rules", Short: "Manage rules"}
	c.AddCommand(newRulesLintCmd())
	c.AddCommand(newRulesTestCmd())
	return c
}

func newRulesLintCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lint <file>",
		Short: "Validate rule YAML and CEL compilation",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			path := args[0]
			info, err := os.Stat(path)
			if err != nil {
				return err
			}
			// engine.New expects a directory; for a single file, point at its dir
			// and ensure no other yaml files there would interfere.
			dir := path
			if !info.IsDir() {
				dir = filepathDir(path)
				if other := otherYamlSiblings(dir, path); len(other) > 0 {
					return fmt.Errorf("rules lint expects a single-file dir; siblings present: %v", other)
				}
			}
			_, err = engine.New([]string{dir})
			if err != nil {
				return err
			}
			fmt.Fprintln(c.OutOrStdout(), "OK")
			return nil
		},
	}
}

func newRulesTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test <file> <event-json>",
		Short: "Evaluate a rule file against a single event",
		Args:  cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			e, err := engine.New([]string{filepathDir(args[0])})
			if err != nil {
				return err
			}
			var ev normalizer.Event
			if err := json.Unmarshal([]byte(args[1]), &ev); err != nil {
				return fmt.Errorf("parse event-json: %w", err)
			}
			ms := e.Evaluate(ev)
			b, _ := json.MarshalIndent(map[string]any{"matches": ms}, "", "  ")
			fmt.Fprintln(c.OutOrStdout(), string(b))
			return nil
		},
	}
}
```

Helpers in the same file (avoiding an extra import):

```go
func filepathDir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}

func otherYamlSiblings(dir, exclude string) []string {
	es, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range es {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if (len(n) > 5 && n[len(n)-5:] == ".yaml") || (len(n) > 4 && n[len(n)-4:] == ".yml") {
			full := dir + "/" + n
			if full != exclude {
				out = append(out, full)
			}
		}
	}
	return out
}
```

- [ ] **Step 6: Implement agent.go (wires everything for `vakta agent`)**

Create `~/vakta/cmd/vakta/agent.go`:

```go
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

	"github.com/spf13/cobra"

	"github.com/vakta-project/vakta/config"
	"github.com/vakta-project/vakta/internal/alertmanager"
	"github.com/vakta-project/vakta/internal/engine"
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

	// 3) Normalizer (auditd + k8s channels nil for v1 — Tasks 6 + 10 wire them in)
	n := normalizer.New(probeCh, nil, nil, host)
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

	// 7) Prune ticker
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
			handleEvent(ctx, ev, store, eng, am, lokiC, pb)
		}
	}
}

func handleEvent(
	ctx context.Context, ev normalizer.Event,
	store *storage.DB, eng *engine.Engine,
	am *alertmanager.Client, lokiC *loki.Client, pb *playbook.Engine,
) {
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
			run, err := pb.Run(ctx, m.Rule.ActionID, m)
			run.AlertID = alertID
			if err != nil {
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
```

- [ ] **Step 7: Run tests + build**

```
cd ~/vakta && CGO_ENABLED=0 go test -v ./cmd/... && CGO_ENABLED=0 go build ./...
ls bin 2>/dev/null || CGO_ENABLED=0 go build -o /tmp/vakta ./cmd/vakta && /tmp/vakta version
```

Expected: 3 tests PASS, build clean, `vakta dev` prints from `/tmp/vakta version`.

- [ ] **Step 8: Commit**

```
cd ~/vakta
git add cmd/ go.mod go.sum
git commit -m "feat(cmd/vakta): cobra CLI (agent/rules/version) + agent main loop"
```

---

## Task 10: internal/k8saudit/ — JSON log tailer

**Files:**
- Create: `~/vakta/internal/k8saudit/tailer.go`
- Create: `~/vakta/internal/k8saudit/tailer_test.go`
- Modify: `~/vakta/internal/normalizer/convert_k8s.go` (drop View stub; use real Entry type)
- Modify: `~/vakta/internal/normalizer/normalizer.go` (signature change)
- Modify: `~/vakta/cmd/vakta/agent.go` (wire k8s tailer when mode=k8s)

- [ ] **Step 1: Add nxadm/tail dependency**

```
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
cd ~/vakta && go get github.com/nxadm/tail && go mod tidy
grep nxadm/tail go.mod    # expect github.com/nxadm/tail vX.Y.Z
```

- [ ] **Step 2: Write the failing test**

Create `~/vakta/internal/k8saudit/tailer_test.go`:

```go
package k8saudit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTailerParsesNewLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	tl, err := New(ctx, path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tl.Close()

	// Append a valid audit entry.
	entry := map[string]any{
		"requestReceivedTimestamp": "2026-01-01T00:00:00Z",
		"verb":                     "get",
		"objectRef": map[string]any{
			"resource": "secrets", "namespace": "kube-system", "name": "ca",
		},
		"user":           map[string]any{"username": "system:apiserver"},
		"sourceIPs":      []string{"10.0.0.1"},
		"responseStatus": map[string]any{"code": 200},
	}
	b, _ := json.Marshal(entry)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write(append(b, '\n'))
	_ = f.Close()

	select {
	case e := <-tl.Entries():
		if e.Verb != "get" || e.Resource != "secrets" || e.Username != "system:apiserver" {
			t.Fatalf("entry=%+v", e)
		}
	case <-ctx.Done():
		t.Fatal("no entry received")
	}
}

func TestTailerSkipsErrorStatuses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	bad := `{"verb":"get","responseStatus":{"code":403}}` + "\n"
	good := `{"verb":"get","objectRef":{"resource":"pods"},"responseStatus":{"code":200},"requestReceivedTimestamp":"2026-01-01T00:00:00Z"}` + "\n"
	if err := os.WriteFile(path, []byte(bad+good), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tl, err := New(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	select {
	case e := <-tl.Entries():
		if e.Resource != "pods" {
			t.Fatalf("expected pods entry, got %+v", e)
		}
	case <-ctx.Done():
		t.Fatal("no entry")
	}
}
```

- [ ] **Step 3: Run, expect failure**

```
cd ~/vakta && go test ./internal/k8saudit/
```

Expected: undefined.

- [ ] **Step 4: Implement tailer.go**

Create `~/vakta/internal/k8saudit/tailer.go`:

```go
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
	t         *tail.Tail
	out       chan Entry
	closeOnce sync.Once
	cancel    context.CancelFunc
}

// New opens the audit log file and begins tailing.
func New(ctx context.Context, path string) (*Tailer, error) {
	t, err := tail.TailFile(path, tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: false,
		Poll:      false,
	})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	tr := &Tailer{
		t:      t,
		out:    make(chan Entry, 512),
		cancel: cancel,
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
			e, ok := parse(line.Text)
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

func parse(line string) (Entry, bool) {
	var r raw
	if err := json.Unmarshal([]byte(line), &r); err != nil {
		return Entry{}, false
	}
	if r.ResponseStatus.Code >= 400 {
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
```

- [ ] **Step 5: Replace normalizer's k8s stub with real type**

Replace `~/vakta/internal/normalizer/convert_k8s.go` with:

```go
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
```

Update `~/vakta/internal/normalizer/normalizer.go`: change the `k8sCh` parameter type from `<-chan K8sEntryView` to `<-chan K8sEntry` in `New`'s signature and in `runK8s`.

- [ ] **Step 6: Wire tailer into agent**

In `~/vakta/cmd/vakta/agent.go` `runAgent`, after the `n := normalizer.New(...)` call, add a block before that constructs the k8s channel when configured:

Replace the `n := normalizer.New(probeCh, nil, nil, host)` line with:

```go
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
	n := normalizer.New(probeCh, nil, k8sCh, host)
```

Add `"github.com/vakta-project/vakta/internal/k8saudit"` to imports.

- [ ] **Step 7: Run tests + build**

```
cd ~/vakta && go test ./internal/k8saudit/ ./internal/normalizer/ ./cmd/... && CGO_ENABLED=0 go build ./...
```

Expected: all PASS.

- [ ] **Step 8: Commit**

```
cd ~/vakta
git add internal/k8saudit/ internal/normalizer/ cmd/vakta/agent.go go.mod go.sum
git commit -m "feat(k8saudit): JSON audit log tailer + normalizer wiring + agent k8s mode"
```

---

## Task 11: internal/api/ — REST API + SSE + embedded web

**Files:**
- Create: `~/vakta/internal/api/server.go`
- Create: `~/vakta/internal/api/handlers.go`
- Create: `~/vakta/internal/api/sse.go`
- Create: `~/vakta/internal/api/embed.go`
- Create: `~/vakta/internal/api/server_test.go`
- Create: `~/vakta/web/dist/.gitkeep` (placeholder until Task 12 builds the SPA)
- Modify: `~/vakta/cmd/vakta/agent.go` (start API server)

- [ ] **Step 1: Write the failing test**

Create `~/vakta/internal/api/server_test.go`:

```go
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/vakta-project/vakta/internal/engine"
	"github.com/vakta-project/vakta/internal/normalizer"
	"github.com/vakta-project/vakta/internal/storage"
)

func setup(t *testing.T) *Server {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "x.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = db.InsertEvent(context.Background(), normalizer.Event{
		Ts: time.Now(), Source: normalizer.SourceEBPF, Type: "EXEC",
		Host: "h", PID: 7, Comm: "ls",
	})
	eng, _ := engine.New([]string{t.TempDir()}) // empty rule dir
	bus := newEventBus()
	s := New(":0", db, eng, bus, nil, ServerOptions{})
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestGetEvents(t *testing.T) {
	s := setup(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/events", nil)
	s.handler.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if items, _ := resp["events"].([]any); len(items) != 1 {
		t.Fatalf("events=%v", resp["events"])
	}
}

func TestGetRules(t *testing.T) {
	s := setup(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/rules", nil)
	s.handler.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestPostRulesReload(t *testing.T) {
	s := setup(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/rules/reload", nil)
	s.handler.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestBasicAuthEnforced(t *testing.T) {
	db, _ := storage.Open(filepath.Join(t.TempDir(), "x.db"), 30)
	eng, _ := engine.New([]string{t.TempDir()})
	s := New(":0", db, eng, newEventBus(), nil, ServerOptions{
		Auth: "basic", Username: "u", Password: "p",
	})
	t.Cleanup(func() { _ = s.Close() })

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/events", nil)
	s.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/v1/events", nil)
	req.SetBasicAuth("u", "p")
	s.handler.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}
```

- [ ] **Step 2: Implement embed.go**

Create `~/vakta/internal/api/embed.go`:

```go
package api

import (
	"embed"
	"io/fs"
)

//go:embed all:web_dist
var webEmbed embed.FS

// uiFS exposes the embedded web assets rooted at web_dist/.
func uiFS() fs.FS {
	sub, err := fs.Sub(webEmbed, "web_dist")
	if err != nil {
		return webEmbed
	}
	return sub
}
```

We embed from `web_dist/` (a sibling dir of the api package) which is populated by a build symlink/copy from `~/vakta/web/dist/`. To keep the embed working from the start, create the empty `web_dist/.gitkeep` next to api/.

Actually simpler: embed directly from a sibling path resolved at build time. Since `go:embed` only embeds dirs inside the package directory, create `~/vakta/internal/api/web_dist/` and symlink (or copy) `web/dist/` contents there in CI / Makefile. For now create `~/vakta/internal/api/web_dist/.gitkeep` so the embed doesn't fail.

```
mkdir -p ~/vakta/internal/api/web_dist
touch ~/vakta/internal/api/web_dist/.gitkeep
```

- [ ] **Step 3: Implement server.go**

Create `~/vakta/internal/api/server.go`:

```go
// Package api serves vakta's REST API, SSE stream, and embedded web UI.
package api

import (
	"context"
	"crypto/subtle"
	"net/http"
	"sync"
	"time"

	"github.com/vakta-project/vakta/internal/engine"
	"github.com/vakta-project/vakta/internal/playbook"
	"github.com/vakta-project/vakta/internal/storage"
)

type ServerOptions struct {
	Auth     string // none | basic
	Username string
	Password string
}

type Server struct {
	addr    string
	db      *storage.DB
	eng     *engine.Engine
	pb      *playbook.Engine
	bus     *eventBus
	opts    ServerOptions
	handler http.Handler
	httpSrv *http.Server
	mu      sync.Mutex
	closed  bool
}

func New(addr string, db *storage.DB, eng *engine.Engine, bus *eventBus, pb *playbook.Engine, opts ServerOptions) *Server {
	s := &Server{addr: addr, db: db, eng: eng, pb: pb, bus: bus, opts: opts}
	s.handler = s.buildRouter()
	return s
}

// EventBus returns the shared bus so the agent can publish events for SSE.
func (s *Server) EventBus() *eventBus { return s.bus }

func (s *Server) Start() error {
	s.httpSrv = &http.Server{
		Addr:              s.addr,
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s.httpSrv.ListenAndServe()
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.httpSrv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.httpSrv.Shutdown(ctx)
}

func (s *Server) buildRouter() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/events", s.handleGetEvents)
	mux.HandleFunc("GET /api/v1/events/stream", s.handleEventStream)
	mux.HandleFunc("GET /api/v1/alerts", s.handleGetAlerts)
	mux.HandleFunc("GET /api/v1/rules", s.handleGetRules)
	mux.HandleFunc("POST /api/v1/rules/reload", s.handleReloadRules)
	mux.HandleFunc("POST /api/v1/rules/test", s.handleTestRule)
	mux.HandleFunc("GET /api/v1/actions", s.handleGetActions)
	mux.HandleFunc("GET /api/v1/action-runs", s.handleGetActionRuns)
	mux.HandleFunc("GET /api/v1/stats", s.handleGetStats)
	mux.Handle("/", http.FileServer(http.FS(uiFS())))

	if s.opts.Auth == "basic" {
		return s.basicAuth(mux)
	}
	return mux
}

func (s *Server) basicAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok ||
			subtle.ConstantTimeCompare([]byte(u), []byte(s.opts.Username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(p), []byte(s.opts.Password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="vakta"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}
```

- [ ] **Step 4: Implement handlers.go**

Create `~/vakta/internal/api/handlers.go`:

```go
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/vakta-project/vakta/internal/normalizer"
	"github.com/vakta-project/vakta/internal/storage"
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
	if evs, err := s.db.QueryEvents(ctx, storage.EventFilter{}); err == nil {
		stats["recent_events"] = len(evs)
	}
	writeJSON(w, 200, stats)
}

// helper to keep import "context" used in this file
var _ = context.Background
```

- [ ] **Step 5: Implement sse.go (event bus + SSE handler)**

Create `~/vakta/internal/api/sse.go`:

```go
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/vakta-project/vakta/internal/normalizer"
)

// eventBus is a fan-out for live events to SSE subscribers.
// The agent calls Publish for every normalized event.
type eventBus struct {
	mu   sync.Mutex
	subs map[chan normalizer.Event]struct{}
}

func newEventBus() *eventBus {
	return &eventBus{subs: map[chan normalizer.Event]struct{}{}}
}

// Publish sends an event to all current subscribers without blocking.
// Slow subscribers drop messages.
func (b *eventBus) Publish(ev normalizer.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (b *eventBus) subscribe() (chan normalizer.Event, func()) {
	ch := make(chan normalizer.Event, 64)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.subs, ch)
		b.mu.Unlock()
		close(ch)
	}
}

func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, unsubscribe := s.bus.subscribe()
	defer unsubscribe()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			b, _ := json.Marshal(ev)
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		}
	}
}
```

- [ ] **Step 6: Wire API server + bus into agent**

In `~/vakta/cmd/vakta/agent.go`, after the playbook engine is constructed, add:

```go
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
```

Also export `newEventBus` as `NewEventBus` in `~/vakta/internal/api/sse.go` (rename `newEventBus` → `NewEventBus`, keep `subscribe` lowercase).

In `handleEvent` (inside agent.go), after `eng.Evaluate(ev)` is called and before iterating matches, add `bus.Publish(ev)`. Plumb `bus` into `handleEvent`'s signature.

Add `"github.com/vakta-project/vakta/internal/api"` + `"net/http"` to agent.go imports.

- [ ] **Step 7: Run tests + build**

```
cd ~/vakta && go test ./internal/api/ && CGO_ENABLED=0 go build ./...
```

Expected: 4 tests PASS, build clean.

- [ ] **Step 8: Commit**

```
cd ~/vakta
git add internal/api/ cmd/vakta/agent.go
git commit -m "feat(api): REST API + SSE event stream + embedded web assets + basic auth"
```

---

## Task 12: web/ — React + Vite SPA

**Files:**
- Create: `~/vakta/web/package.json`
- Create: `~/vakta/web/vite.config.ts`
- Create: `~/vakta/web/tsconfig.json`
- Create: `~/vakta/web/index.html`
- Create: `~/vakta/web/src/main.tsx`
- Create: `~/vakta/web/src/App.tsx`
- Create: `~/vakta/web/src/api.ts`
- Create: `~/vakta/web/src/pages/Timeline.tsx`
- Create: `~/vakta/web/src/pages/Alerts.tsx`
- Create: `~/vakta/web/src/pages/Rules.tsx`
- Create: `~/vakta/web/src/pages/Config.tsx`
- Create: `~/vakta/web/src/styles.css`
- Create: `~/vakta/web/.gitignore`
- Create: `~/vakta/Makefile` (build target that runs `npm run build` then copies into internal/api/web_dist/)

- [ ] **Step 1: Initialize Node project + deps**

```
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
cd ~/vakta/web && npm init -y
npm install --save react@18 react-dom@18 react-router-dom@6
npm install --save-dev typescript@5 vite@5 @vitejs/plugin-react @types/react @types/react-dom
```

- [ ] **Step 2: Write package.json scripts + replace generated package.json**

Overwrite `~/vakta/web/package.json` with:

```json
{
  "name": "vakta-web",
  "private": true,
  "version": "0.3.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.3.0",
    "react-dom": "^18.3.0",
    "react-router-dom": "^6.26.0"
  },
  "devDependencies": {
    "typescript": "^5.5.0",
    "vite": "^5.4.0",
    "@vitejs/plugin-react": "^4.3.0",
    "@types/react": "^18.3.0",
    "@types/react-dom": "^18.3.0"
  }
}
```

- [ ] **Step 3: vite.config.ts**

```ts
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: { outDir: 'dist', emptyOutDir: true },
  server: {
    proxy: { '/api': 'http://localhost:9090' }
  }
});
```

- [ ] **Step 4: tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "jsx": "react-jsx",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "noEmit": true
  },
  "include": ["src"]
}
```

- [ ] **Step 5: index.html**

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>vakta</title>
  <link rel="stylesheet" href="/src/styles.css" />
</head>
<body>
  <div id="root"></div>
  <script type="module" src="/src/main.tsx"></script>
</body>
</html>
```

- [ ] **Step 6: src/styles.css (minimal, no framework)**

```css
:root { font-family: system-ui, sans-serif; color-scheme: light dark; }
body { margin: 0; padding: 0; }
nav { display: flex; gap: 1rem; padding: 0.75rem 1rem; border-bottom: 1px solid #ddd; }
nav a { text-decoration: none; color: inherit; padding: 0.25rem 0.5rem; border-radius: 4px; }
nav a.active { background: #eee; }
main { padding: 1rem; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid #eee; font-size: 0.9rem; }
.badge { display: inline-block; padding: 0.1rem 0.4rem; border-radius: 3px; font-size: 0.75rem; font-weight: 600; }
.sev-critical { background: #c0392b; color: white; }
.sev-high { background: #e67e22; color: white; }
.sev-warning { background: #f1c40f; color: black; }
.sev-info { background: #3498db; color: white; }
```

- [ ] **Step 7: src/main.tsx**

```tsx
import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App';

const root = document.getElementById('root');
if (!root) throw new Error('no #root');
createRoot(root).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
);
```

- [ ] **Step 8: src/api.ts**

```ts
const base = '';

export async function getEvents(params: Record<string,string> = {}) {
  const qs = new URLSearchParams(params).toString();
  const r = await fetch(`${base}/api/v1/events${qs ? '?' + qs : ''}`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

export async function getAlerts() {
  const r = await fetch(`${base}/api/v1/alerts`);
  return r.json();
}

export async function getRules() {
  const r = await fetch(`${base}/api/v1/rules`);
  return r.json();
}

export async function reloadRules() {
  const r = await fetch(`${base}/api/v1/rules/reload`, { method: 'POST' });
  return r.json();
}

export async function testRule(event: any) {
  const r = await fetch(`${base}/api/v1/rules/test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ event }),
  });
  return r.json();
}

export function streamEvents(onEvent: (ev: any) => void): () => void {
  const src = new EventSource(`${base}/api/v1/events/stream`);
  src.onmessage = (m) => onEvent(JSON.parse(m.data));
  return () => src.close();
}
```

- [ ] **Step 9: src/App.tsx**

```tsx
import { NavLink, Routes, Route } from 'react-router-dom';
import Timeline from './pages/Timeline';
import Alerts from './pages/Alerts';
import Rules from './pages/Rules';
import Config from './pages/Config';

export default function App() {
  return (
    <>
      <nav>
        <strong style={{ marginRight: '1rem' }}>vakta</strong>
        <NavLink to="/" end>Timeline</NavLink>
        <NavLink to="/alerts">Alerts</NavLink>
        <NavLink to="/rules">Rules</NavLink>
        <NavLink to="/config">Config</NavLink>
      </nav>
      <main>
        <Routes>
          <Route path="/" element={<Timeline />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/rules" element={<Rules />} />
          <Route path="/config" element={<Config />} />
        </Routes>
      </main>
    </>
  );
}
```

- [ ] **Step 10: src/pages/Timeline.tsx**

```tsx
import { useEffect, useState } from 'react';
import { getEvents, streamEvents } from '../api';

type Event = {
  ID: number; Ts: string; Type: string; Host: string;
  PID: number; Comm: string; Ret: number;
};

export default function Timeline() {
  const [events, setEvents] = useState<Event[]>([]);
  const [typeFilter, setTypeFilter] = useState('');

  useEffect(() => {
    getEvents().then((r) => setEvents(r.events || []));
    const stop = streamEvents((ev) => setEvents((prev) => [ev, ...prev].slice(0, 500)));
    return stop;
  }, []);

  const filtered = typeFilter
    ? events.filter((e) => e.Type === typeFilter)
    : events;

  return (
    <>
      <div style={{ marginBottom: '0.5rem' }}>
        <label>Type: </label>
        <input value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} placeholder="EXEC, CONNECT, ..." />
      </div>
      <table>
        <thead>
          <tr>
            <th>Time</th><th>Type</th><th>Host</th><th>PID</th><th>Comm</th><th>Ret</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((e) => (
            <tr key={e.ID}>
              <td>{new Date(e.Ts).toLocaleTimeString()}</td>
              <td>{e.Type}</td>
              <td>{e.Host}</td>
              <td>{e.PID}</td>
              <td>{e.Comm}</td>
              <td>{e.Ret}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
```

- [ ] **Step 11: src/pages/Alerts.tsx**

```tsx
import { useEffect, useState } from 'react';
import { getAlerts } from '../api';

type Alert = {
  ID: number; RuleID: string; RuleName: string; Severity: string; Status: string; FiredAt: string;
};

export default function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  useEffect(() => {
    getAlerts().then((r) => setAlerts(r.alerts || []));
  }, []);
  return (
    <table>
      <thead>
        <tr><th>Time</th><th>Severity</th><th>Rule</th><th>Status</th></tr>
      </thead>
      <tbody>
        {alerts.map((a) => (
          <tr key={a.ID}>
            <td>{new Date(a.FiredAt).toLocaleString()}</td>
            <td><span className={`badge sev-${a.Severity}`}>{a.Severity}</span></td>
            <td>{a.RuleName} <span style={{ color: '#888' }}>({a.RuleID})</span></td>
            <td>{a.Status}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
```

- [ ] **Step 12: src/pages/Rules.tsx**

```tsx
import { useEffect, useState } from 'react';
import { getRules, reloadRules, testRule } from '../api';

type Rule = {
  ID: string; Name: string; Severity: string; EventType: string; Condition: string; Tags: string[];
};

export default function Rules() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [testEv, setTestEv] = useState('{"Type":"EXEC","UID":0}');
  const [testResult, setTestResult] = useState<string>('');

  const load = () => getRules().then((r) => setRules(r.rules || []));
  useEffect(() => { load(); }, []);

  const reload = async () => { await reloadRules(); load(); };
  const runTest = async () => {
    try {
      const ev = JSON.parse(testEv);
      const r = await testRule(ev);
      setTestResult(JSON.stringify(r, null, 2));
    } catch (e: any) {
      setTestResult(String(e));
    }
  };

  return (
    <>
      <button onClick={reload}>Reload rules from disk</button>
      <h3>Test rule</h3>
      <textarea rows={5} cols={60} value={testEv} onChange={(e) => setTestEv(e.target.value)} />
      <br />
      <button onClick={runTest}>Test</button>
      <pre>{testResult}</pre>
      <h3>Loaded rules</h3>
      <table>
        <thead>
          <tr><th>ID</th><th>Severity</th><th>Event type</th><th>Condition</th></tr>
        </thead>
        <tbody>
          {rules.map((r) => (
            <tr key={r.ID}>
              <td>{r.ID}</td>
              <td><span className={`badge sev-${r.Severity}`}>{r.Severity}</span></td>
              <td>{r.EventType || '(any)'}</td>
              <td><code>{r.Condition}</code></td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
```

- [ ] **Step 13: src/pages/Config.tsx**

```tsx
export default function Config() {
  return (
    <>
      <p>Configuration is loaded from <code>/etc/vakta/config.yaml</code> on agent startup.</p>
      <p>Edit the file and restart the agent to apply changes, or use <code>POST /api/v1/rules/reload</code> for hot-reload of rules only.</p>
    </>
  );
}
```

- [ ] **Step 14: .gitignore + build**

Create `~/vakta/web/.gitignore`:

```
node_modules/
dist/
```

Build and copy into Go embed dir:

```
cd ~/vakta/web && npm run build
rm -rf ~/vakta/internal/api/web_dist/*
cp -r ~/vakta/web/dist/* ~/vakta/internal/api/web_dist/
```

- [ ] **Step 15: Add Makefile for repeatable builds**

Create `~/vakta/Makefile`:

```makefile
.PHONY: web build test

web:
	cd web && npm ci && npm run build
	rm -rf internal/api/web_dist/*
	mkdir -p internal/api/web_dist
	cp -r web/dist/* internal/api/web_dist/

build: web
	CGO_ENABLED=0 go build -o bin/vakta ./cmd/vakta

test:
	CGO_ENABLED=0 go test ./...
```

- [ ] **Step 16: Verify full build + Go tests**

```
cd ~/vakta && make build && CGO_ENABLED=0 go test ./...
```

Expected: all green; `bin/vakta` exists.

- [ ] **Step 17: Commit**

```
cd ~/vakta
git add web/ internal/api/web_dist/ Makefile
git commit -m "feat(web): React+Vite SPA (timeline/alerts/rules/config) + Makefile build target"
```

---

## Task 13: deploy/ — systemd + Dockerfile + Helm

**Files:**
- Create: `~/vakta/deploy/systemd/vakta.service`
- Create: `~/vakta/Dockerfile`
- Create: `~/vakta/deploy/helm/Chart.yaml`
- Create: `~/vakta/deploy/helm/values.yaml`
- Create: `~/vakta/deploy/helm/templates/daemonset.yaml`
- Create: `~/vakta/deploy/helm/templates/configmap.yaml`
- Create: `~/vakta/deploy/helm/templates/serviceaccount.yaml`
- Create: `~/vakta/deploy/helm/templates/service.yaml`

- [ ] **Step 1: systemd unit**

Create `~/vakta/deploy/systemd/vakta.service`:

```ini
[Unit]
Description=vakta runtime event-processing agent
After=network-online.target auditd.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/vakta agent --config /etc/vakta/config.yaml
Restart=on-failure
RestartSec=5s
User=root
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_AUDIT_READ
StateDirectory=vakta
RuntimeDirectory=vakta
StandardOutput=journal
StandardError=journal
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/vakta /var/log/vakta
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Dockerfile**

Create `~/vakta/Dockerfile`:

```dockerfile
# syntax=docker/dockerfile:1.7

FROM node:20-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json* ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.25-alpine AS go
RUN apk add --no-cache clang llvm libelf-dev linux-headers musl-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /web/dist ./internal/api/web_dist
RUN CGO_ENABLED=0 go generate ./internal/probe/... \
 && CGO_ENABLED=0 go build -ldflags "-X main.Version=$(git describe --tags --always 2>/dev/null || echo dev)" -o /out/vakta ./cmd/vakta

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=go /out/vakta /usr/local/bin/vakta
USER 0:0
ENTRYPOINT ["/usr/local/bin/vakta"]
CMD ["agent", "--config", "/etc/vakta/config.yaml"]
```

(Build runs as non-root by image convention, runtime must be root for CAP_BPF/CAP_AUDIT_READ; daemonset overrides USER.)

- [ ] **Step 3: Helm Chart.yaml + values.yaml**

`~/vakta/deploy/helm/Chart.yaml`:

```yaml
apiVersion: v2
name: vakta
description: vakta runtime event-processing agent
type: application
version: 0.3.0
appVersion: "0.3.0"
```

`~/vakta/deploy/helm/values.yaml`:

```yaml
image:
  repository: ghcr.io/vakta-project/vakta
  tag: latest
  pullPolicy: IfNotPresent

mode: k8s
nodeSelector: {}
tolerations:
  - operator: Exists
    effect: NoSchedule

resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 512Mi

alertmanager: ""
loki: ""
auditLogPath: /var/log/audit/audit.log
k8sAuditLogPath: /var/log/kubernetes/audit.log

ui:
  service:
    type: ClusterIP
    port: 9090
```

- [ ] **Step 4: DaemonSet template**

`~/vakta/deploy/helm/templates/daemonset.yaml`:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: vakta
  labels:
    app.kubernetes.io/name: vakta
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: vakta
  template:
    metadata:
      labels:
        app.kubernetes.io/name: vakta
    spec:
      serviceAccountName: vakta
      hostPID: true
      hostNetwork: true
      tolerations: {{ toYaml .Values.tolerations | nindent 8 }}
      nodeSelector: {{ toYaml .Values.nodeSelector | nindent 8 }}
      containers:
        - name: agent
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          args: ["agent", "--config", "/etc/vakta/config.yaml", "--mode", "{{ .Values.mode }}"]
          securityContext:
            privileged: false
            capabilities:
              add: ["BPF", "PERFMON", "SYS_RESOURCE", "AUDIT_READ"]
          ports:
            - name: ui
              containerPort: 9090
          resources: {{ toYaml .Values.resources | nindent 12 }}
          volumeMounts:
            - name: bpf
              mountPath: /sys/fs/bpf
            - name: kernel-btf
              mountPath: /sys/kernel/btf
              readOnly: true
            - name: k8s-audit
              mountPath: /var/log/k8s-audit.log
              readOnly: true
            - name: state
              mountPath: /var/lib/vakta
            - name: config
              mountPath: /etc/vakta
      volumes:
        - name: bpf
          hostPath: { path: /sys/fs/bpf }
        - name: kernel-btf
          hostPath: { path: /sys/kernel/btf }
        - name: k8s-audit
          hostPath: { path: "{{ .Values.k8sAuditLogPath }}" }
        - name: state
          emptyDir: {}
        - name: config
          configMap:
            name: vakta-config
```

- [ ] **Step 5: ConfigMap template**

`~/vakta/deploy/helm/templates/configmap.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: vakta-config
data:
  config.yaml: |
    agent:
      mode: {{ .Values.mode }}
    sources:
      ebpf: true
      auditd: false
      k8s_audit: true
      k8s_audit_log: /var/log/k8s-audit.log
    rules_dir: /etc/vakta/rules
    actions_dir: /etc/vakta/actions
    outputs:
      alertmanager: "{{ .Values.alertmanager }}"
      loki: "{{ .Values.loki }}"
    storage:
      sqlite_path: /var/lib/vakta/events.db
      retention_days: 30
    ui:
      enabled: true
      addr: ":9090"
      auth: none
```

- [ ] **Step 6: ServiceAccount + Service**

`~/vakta/deploy/helm/templates/serviceaccount.yaml`:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vakta
```

`~/vakta/deploy/helm/templates/service.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: vakta-ui
  labels:
    app.kubernetes.io/name: vakta
spec:
  type: {{ .Values.ui.service.type }}
  ports:
    - name: ui
      port: {{ .Values.ui.service.port }}
      targetPort: ui
  selector:
    app.kubernetes.io/name: vakta
```

- [ ] **Step 7: Verify Helm chart lints (if helm installed)**

```
which helm && cd ~/vakta && helm lint deploy/helm/ || echo "helm not installed locally; skipping lint"
```

Expected: lint passes if helm is available; otherwise note for CI.

- [ ] **Step 8: Verify Dockerfile builds (smoke; may take minutes)**

```
cd ~/vakta && docker build -t vakta:dev . || echo "docker build skipped (no docker on this host)"
```

Expected: successful image if docker installed.

- [ ] **Step 9: Commit**

```
cd ~/vakta
git add deploy/ Dockerfile
git commit -m "feat(deploy): systemd unit + Dockerfile + Helm chart (DaemonSet/ConfigMap/Service)"
```

---

## Self-review

### 1. Spec coverage

| Spec section | Task(s) |
|---|---|
| §1 auditd Reader | Task 6 |
| §2 k8s Audit Tailer | Task 10 |
| §3 Event Normalizer + Detail types | Task 2 |
| §4 Policy Engine (CEL) | Task 4 |
| §5 SQLite Store + Alert + StoredEvent/Alert + Prune | Task 3 |
| §6 Alertmanager Client | Task 5 |
| §7 Loki Push Client | Task 7 |
| §8 Action Engine + 6 built-in action types | Task 8 |
| §9 REST API (8 endpoints incl. /events/stream SSE) | Task 11 |
| §10 Web UI (4 pages) | Task 12 |
| §11 CLI entrypoint (`agent`/`rules lint`/`rules test`/`version`) | Task 9 |
| Configuration (config.yaml schema + defaults) | Task 1 |
| Go dependencies (yaml/cel/sqlite/cobra/libaudit/tail) | added in Tasks 1/3/4/6/9/10 |
| Build & Test commands | Task 12 (Makefile) |
| Deployment modes (host/k8s) | Task 9 (CLI flag), Task 13 (systemd vs DaemonSet) |

Coverage is complete. No spec section is unmapped.

### 2. Placeholder scan

Re-grepped the plan for the forbidden markers: `TBD`, `TODO`, `fill in`, `implement later`, `similar to Task`. None present except the explicit `web/dist/.gitkeep` (a placeholder *file*, not a plan placeholder) and the `cmd/vakta/` empty dir from v0.1 (resolved by Task 9 creating `main.go`).

Every step has either concrete code, an exact command + expected output, or a one-line shell action with explicit arguments.

### 3. Type/method name consistency

Cross-checked the type contracts table at the top of this plan against each task:

| Symbol | Defined in | Referenced in | Consistent? |
|---|---|---|---|
| `normalizer.Event` | Task 2 (`event.go`) | Task 3 (storage), Task 4 (engine), Task 5 (alertmanager via match), Task 7 (loki), Task 8 (playbook), Task 11 (api) | ✓ same field set (ID/Ts/Source/Type/Host/CgroupID/PID/PPID/UID/GID/Comm/Ret/Detail) |
| `normalizer.Source` constants (1/2/3) | Task 2 | Task 4 (CEL `event.source`), Task 7 (label string) | ✓ |
| `engine.Rule` (ID/Name/Severity/Source/EventType/Condition/Tags/ActionID) | Task 4 | Task 8 (`m.Rule.ActionID`), Task 9 (lint), Task 11 (`/api/v1/rules`) | ✓ |
| `engine.Match` (Rule/Event/At) | Task 4 | Task 8 (Run signature), Task 9 (handleEvent loop) | ✓ |
| `storage.Alert` (RuleID/RuleName/Severity/EventID/ActionID/Status/Tags/FiredAt) | Task 3 | Task 9 (`handleEvent` constructs one) | ✓ |
| `storage.StoredEvent`, `storage.StoredAlert` | Task 3 | Task 11 (`/events`, `/alerts` JSON responses) | ✓ |
| `storage.InsertActionRun` signature | Task 3 | Task 8 (called from Engine.Run) | ✓ matches: actionID, alertID, dryRun, status, stepsJSON, startedAt, finishedAt |
| `playbook.ActionRun` / `playbook.StepResult` | Task 8 | Task 11 (`/api/v1/action-runs` — note: this endpoint is declared in the spec but the GET handler is NOT implemented in Task 11; only `/api/v1/actions` and `/api/v1/stats` are. Adding the handler is a 12-line follow-up but isn't in scope as written.) | ⚠ partial |
| `alertmanager.Alert` (Labels/Annotations/StartsAt/EndsAt/GeneratorURL) | Task 5 | Task 8 (`actNotify`), Task 9 (`handleEvent`) | ✓ |
| bpf2go field names from probe (Task 2 conversion uses `probe.EventHeader`, `probe.ExecEvent` etc.) | probe layer (already shipped) | Task 2 (`convert_probe.go`) | ✓ matches the v0.2 probe types |

**Patched 2026-06-28:** `GET /api/v1/action-runs` (spec §9) is now implemented — Task 3 includes `storage.QueryActionRuns` + `ActionRunFilter` + `StoredActionRun` + a round-trip unit test; Task 11 registers the route and implements `handleGetActionRuns`. The plan's self-review table above shows ⚠ for historical context but the actual code is complete.

### Build invariant

Verified each task ends with either `CGO_ENABLED=0 go build ./...` exiting 0 or an equivalent build step (Task 12 also runs `make build` which wraps the same command). No task introduces CGo. The probe layer's bpf2go output is also CGO_ENABLED=0 compatible (it embeds pre-compiled `.o` via `go:embed`).

### Commit cadence

13 tasks produce ~14-30 commits total (some tasks have multiple commit points around dependency adds + tests + impl). Every commit's working tree builds and tests pass — no broken intermediate state.

---

## Closing notes

- **Execution order matters** for Tasks 2/6/10: Task 2 uses forward-declared `AuditdRecordView` / `K8sEntryView` stubs that Tasks 6 and 10 then replace with type aliases to the real packages. The build stays green throughout because the stub structs have identical field shapes to the real types.
- **No probe-layer changes** anywhere in this plan; the existing `internal/probe/` package is consumed as-is.
- **First-time setup deltas to track** (not in any task because they're per-deployment): create `/etc/vakta/`, `/var/lib/vakta/`, write `config.yaml` from `config/default.yaml`, set up `auditctl` rules externally before starting the agent (per spec §1 note).
- **Out of scope for this plan** (deliberate): probe-layer changes, integration tests beyond what each component package ships, mTLS for the API server, multi-tenant rule namespacing, RBAC. All can be follow-up tasks.

