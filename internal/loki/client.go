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

	buf      chan normalizer.Event
	enqueued atomic.Uint64
	flushed  atomic.Uint64
	dropped  atomic.Uint64
	errors   atomic.Uint64

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
		c.ctxCancel() // cancel any in-flight HTTP requests
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
