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
