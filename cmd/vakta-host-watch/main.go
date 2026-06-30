// Package main implements vakta-host-watch, a host overload early-warning
// daemon. See docs/superpowers/specs/2026-06-30-vakta-host-watch-design.md
// in the Taberna repo for the design.
package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("vakta-host-watch starting (scaffold)")
	os.Exit(0)
}

type Config struct {
	SampleInterval time.Duration `yaml:"sample_interval"`
	RetentionDays  int           `yaml:"retention_days"`
	Cooldown       time.Duration `yaml:"cooldown"`
	DBPath         string        `yaml:"db_path"`

	Telegram struct {
		BotToken string `yaml:"bot_token"`
		ChatID   string `yaml:"chat_id"`
	} `yaml:"telegram"`

	Thresholds struct {
		Load1              float64 `yaml:"load1"`
		SwapSiMinKBPerSec  int64   `yaml:"swap_si_min_kb_s"`
		VmstatBMin         int64   `yaml:"vmstat_b_min"`
		WindowSamples      int     `yaml:"window_samples"`
	} `yaml:"thresholds"`
}

func defaultConfig() Config {
	var c Config
	c.SampleInterval = 60 * time.Second
	c.RetentionDays = 30
	c.Cooldown = 3 * time.Minute
	c.DBPath = expandHome("~/.vakta/host-watch.db")
	c.Thresholds.Load1 = 20
	c.Thresholds.SwapSiMinKBPerSec = 1
	c.Thresholds.VmstatBMin = 10
	c.Thresholds.WindowSamples = 3
	return c
}

func loadConfig(path string) (Config, error) {
	cfg := defaultConfig()
	body, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return applyEnvOverrides(cfg), nil
		}
		return cfg, err
	}
	if err := yaml.Unmarshal(body, &cfg); err != nil {
		return cfg, err
	}
	return applyEnvOverrides(cfg), nil
}

func applyEnvOverrides(cfg Config) Config {
	if v := os.Getenv("TG_BOT_TOKEN"); v != "" {
		cfg.Telegram.BotToken = v
	}
	if v := os.Getenv("TG_CHAT_ID"); v != "" {
		cfg.Telegram.ChatID = v
	}
	return cfg
}

func expandHome(p string) string {
	if len(p) > 1 && p[:2] == "~/" {
		if h, err := os.UserHomeDir(); err == nil {
			return h + p[1:]
		}
	}
	return p
}

// --- Sample types ---

type Sample struct {
	Ts             int64     `json:"ts"`
	Load1          float64   `json:"load1"`
	Load5          float64   `json:"load5"`
	Load15         float64   `json:"load15"`
	MemUsedMB      int64     `json:"mem_used_mb"`
	SwapUsedMB     int64     `json:"swap_used_mb"`
	SwapSiKBPerSec int64     `json:"swap_si_kb_s"`
	VmstatB        int64     `json:"vmstat_b"`
	VmstatWA       int64     `json:"vmstat_wa"`
	TopProcs       []TopProc `json:"top_procs"`
}

type TopProc struct {
	PID    int    `json:"pid"`
	Name   string `json:"name"`
	RSSKB  int64  `json:"rss_kb"`
	SwapKB int64  `json:"swap_kb"`
}

type vmstatSnapshot struct {
	Time       time.Time
	PswpIn     int64
	PgmajFault int64
}

type meminfo struct {
	UsedMB     int64
	SwapUsedMB int64
}

// --- /proc parsers ---

func parseLoadavg(s string) (l1, l5, l15 float64, err error) {
	parts := strings.Fields(s)
	if len(parts) < 3 {
		return 0, 0, 0, fmt.Errorf("loadavg: expected ≥3 fields, got %d", len(parts))
	}
	if l1, err = strconv.ParseFloat(parts[0], 64); err != nil {
		return
	}
	if l5, err = strconv.ParseFloat(parts[1], 64); err != nil {
		return
	}
	if l15, err = strconv.ParseFloat(parts[2], 64); err != nil {
		return
	}
	return
}

func parseVmstat(s string) (vmstatSnapshot, error) {
	var v vmstatSnapshot
	v.Time = time.Now()
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		n, _ := strconv.ParseInt(f[1], 10, 64)
		switch f[0] {
		case "pswpin":
			v.PswpIn = n
		case "pgmajfault":
			v.PgmajFault = n
		}
	}
	return v, sc.Err()
}

// swapInKBPerSec converts pswpin delta over interval into KB/s.
// pageSize is the kernel page size in bytes (4096 on x86_64).
func swapInKBPerSec(prev, cur vmstatSnapshot, interval time.Duration, pageSize int64) int64 {
	if interval <= 0 {
		return 0
	}
	pages := cur.PswpIn - prev.PswpIn
	if pages < 0 {
		return 0
	}
	bytesPerSec := pages * pageSize * int64(time.Second) / int64(interval)
	return bytesPerSec / 1024
}

func parseMeminfo(s string) (meminfo, error) {
	var m meminfo
	var total, avail, swapTotal, swapFree int64
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		n, _ := strconv.ParseInt(f[1], 10, 64)
		switch strings.TrimSuffix(f[0], ":") {
		case "MemTotal":
			total = n
		case "MemAvailable":
			avail = n
		case "SwapTotal":
			swapTotal = n
		case "SwapFree":
			swapFree = n
		}
	}
	m.UsedMB = (total - avail) / 1024
	m.SwapUsedMB = (swapTotal - swapFree) / 1024
	return m, nil
}

// readTopProcs walks /proc/<pid>/status for memory size and returns the top N
// by RSS+swap. /proc/<pid>/comm gives a short name.
func readTopProcs(n int) ([]TopProc, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	all := make([]TopProc, 0, 256)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		rss, swap, ok := readProcStatusRssSwap(pid)
		if !ok {
			continue
		}
		name, _ := readProcComm(pid)
		all = append(all, TopProc{PID: pid, Name: name, RSSKB: rss, SwapKB: swap})
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].RSSKB+all[i].SwapKB > all[j].RSSKB+all[j].SwapKB
	})
	if len(all) > n {
		all = all[:n]
	}
	return all, nil
}

func readProcStatusRssSwap(pid int) (rss, swap int64, ok bool) {
	body, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0, false
	}
	var foundRSS, foundSwap bool
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			fmt.Sscanf(line, "VmRSS: %d kB", &rss)
			foundRSS = true
		} else if strings.HasPrefix(line, "VmSwap:") {
			fmt.Sscanf(line, "VmSwap: %d kB", &swap)
			foundSwap = true
		}
	}
	return rss, swap, foundRSS || foundSwap
}

func readProcComm(pid int) (string, error) {
	body, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// --- Sampler ---

type Sampler struct {
	pageSize int64
	prev     vmstatSnapshot
}

func NewSampler() *Sampler {
	return &Sampler{pageSize: int64(os.Getpagesize())}
}

func (s *Sampler) Read() (Sample, error) {
	loadBody, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return Sample{}, err
	}
	l1, l5, l15, err := parseLoadavg(string(loadBody))
	if err != nil {
		return Sample{}, err
	}

	vmBody, err := os.ReadFile("/proc/vmstat")
	if err != nil {
		return Sample{}, err
	}
	cur, err := parseVmstat(string(vmBody))
	if err != nil {
		return Sample{}, err
	}
	var siKBPerSec int64
	if !s.prev.Time.IsZero() {
		siKBPerSec = swapInKBPerSec(s.prev, cur, cur.Time.Sub(s.prev.Time), s.pageSize)
	}
	s.prev = cur

	// procs_blocked from /proc/stat
	statBody, err := os.ReadFile("/proc/stat")
	if err != nil {
		return Sample{}, err
	}
	var procsBlocked int64
	sc := bufio.NewScanner(strings.NewReader(string(statBody)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == "procs_blocked" {
			procsBlocked, _ = strconv.ParseInt(f[1], 10, 64)
			break
		}
	}

	// CPU iowait% from the "cpu" aggregate line in /proc/stat
	var wa int64
	for sc2 := bufio.NewScanner(strings.NewReader(string(statBody))); sc2.Scan(); {
		f := strings.Fields(sc2.Text())
		if len(f) >= 6 && f[0] == "cpu" {
			user, _ := strconv.ParseInt(f[1], 10, 64)
			nice, _ := strconv.ParseInt(f[2], 10, 64)
			system, _ := strconv.ParseInt(f[3], 10, 64)
			idle, _ := strconv.ParseInt(f[4], 10, 64)
			iowait, _ := strconv.ParseInt(f[5], 10, 64)
			total := user + nice + system + idle + iowait
			if total > 0 {
				wa = iowait * 100 / total
			}
			break
		}
	}

	memBody, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return Sample{}, err
	}
	mem, err := parseMeminfo(string(memBody))
	if err != nil {
		return Sample{}, err
	}

	procs, err := readTopProcs(10)
	if err != nil {
		return Sample{}, err
	}

	return Sample{
		Ts:             time.Now().Unix(),
		Load1:          l1,
		Load5:          l5,
		Load15:         l15,
		MemUsedMB:      mem.UsedMB,
		SwapUsedMB:     mem.SwapUsedMB,
		SwapSiKBPerSec: siKBPerSec,
		VmstatB:        procsBlocked,
		VmstatWA:       wa,
		TopProcs:       procs,
	}, nil
}

func (s Sample) TopProcsJSON() string {
	b, _ := json.Marshal(s.TopProcs)
	return string(b)
}

// --- Store (SQLite) ---

type Store struct {
	db *sql.DB
}

const sqlSchema = `
CREATE TABLE IF NOT EXISTS samples (
    ts            INTEGER PRIMARY KEY,
    load1         REAL    NOT NULL,
    load5         REAL    NOT NULL,
    load15        REAL    NOT NULL,
    mem_used_mb   INTEGER NOT NULL,
    swap_used_mb  INTEGER NOT NULL,
    swap_si_kb_s  INTEGER NOT NULL,
    vmstat_b      INTEGER NOT NULL,
    vmstat_wa     INTEGER NOT NULL,
    top_procs     TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);
`

func openStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// SQLite serializes writes through a single OS connection. database/sql's default
	// pool of unlimited connections lets the runtime open multiple parallel SQLite
	// handles, which race for the file lock and produce "database is locked" errors
	// under contention. Pin to 1 connection so the database/sql layer queues writers
	// for us, matching the pattern in vakta's internal/storage/storage.go.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(sqlSchema); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Insert(sm Sample) error {
	procsJSON := sm.TopProcsJSON()
	if procsJSON == "" {
		procsJSON = "[]"
	}
	_, err := s.db.Exec(`
INSERT INTO samples (ts, load1, load5, load15, mem_used_mb, swap_used_mb, swap_si_kb_s, vmstat_b, vmstat_wa, top_procs)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(ts) DO NOTHING`,
		sm.Ts, sm.Load1, sm.Load5, sm.Load15, sm.MemUsedMB, sm.SwapUsedMB,
		sm.SwapSiKBPerSec, sm.VmstatB, sm.VmstatWA, procsJSON,
	)
	return err
}

func (s *Store) QueryRecent(n int) ([]Sample, error) {
	rows, err := s.db.Query(`
SELECT ts, load1, load5, load15, mem_used_mb, swap_used_mb, swap_si_kb_s, vmstat_b, vmstat_wa, top_procs
FROM samples
ORDER BY ts DESC
LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Sample
	for rows.Next() {
		var sm Sample
		var procsJSON string
		if err := rows.Scan(&sm.Ts, &sm.Load1, &sm.Load5, &sm.Load15,
			&sm.MemUsedMB, &sm.SwapUsedMB, &sm.SwapSiKBPerSec,
			&sm.VmstatB, &sm.VmstatWA, &procsJSON); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(procsJSON), &sm.TopProcs)
		out = append(out, sm)
	}
	return out, rows.Err()
}

func (s *Store) Prune(beforeTs int64) error {
	_, err := s.db.Exec(`DELETE FROM samples WHERE ts < ?`, beforeTs)
	return err
}
