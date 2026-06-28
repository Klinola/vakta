import { useEffect, useMemo, useRef, useState } from 'react';
import { getEvents, streamEvents, relativeTime, type VaktaEvent } from '../api';

const HIGH_IMPACT = new Set(['PTRACE', 'MODULE_LOAD', 'BPF_LOAD', 'MEMFD', 'MMAP_EXEC']);
const WARN_IMPACT = new Set(['CHMOD', 'PROC_PROBE', 'AUDIT_CRED_ACCESS', 'CREDENTIAL_ACCESS']);

function impactClass(type: string): string {
  if (HIGH_IMPACT.has(type)) return 'tint-high';
  if (WARN_IMPACT.has(type)) return 'tint-warn';
  return '';
}

function parseDetail(ev: VaktaEvent): unknown {
  if (ev.Detail !== undefined && ev.Detail !== null) return ev.Detail;
  if (typeof ev.DetailJSON === 'string' && ev.DetailJSON.length > 0) {
    try { return JSON.parse(ev.DetailJSON); } catch { return ev.DetailJSON; }
  }
  return null;
}

const PAGE_SIZE = 100;

export default function Timeline() {
  const [events, setEvents] = useState<VaktaEvent[]>([]);
  const [typeFilter, setTypeFilter] = useState('');
  const [manualType, setManualType] = useState('');
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const [streamState, setStreamState] = useState<'connecting' | 'open' | 'error'>('connecting');
  const [autoScroll, setAutoScroll] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [, forceRender] = useState(0);
  const topRef = useRef<HTMLTableSectionElement | null>(null);

  // Initial fetch
  useEffect(() => {
    getEvents({ limit: String(PAGE_SIZE) })
      .then((r) => setEvents(r.events ?? []))
      .catch(() => {/* swallow; UI shows empty */});
  }, []);

  // SSE feed
  useEffect(() => {
    const h = streamEvents(
      (ev) => {
        setEvents((prev) => {
          if (prev.some((p) => p.ID === ev.ID)) return prev;
          return [ev, ...prev].slice(0, 1000);
        });
      },
      (s) => setStreamState(s),
    );
    return h.close;
  }, []);

  // Auto-scroll when new events land
  useEffect(() => {
    if (autoScroll && events.length > 0) {
      topRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }, [events.length, autoScroll]);

  // Tick relative times every 5s so "2s ago" stays fresh
  useEffect(() => {
    const id = setInterval(() => forceRender((n) => n + 1), 5_000);
    return () => clearInterval(id);
  }, []);

  const observedTypes = useMemo(() => {
    const s = new Set<string>();
    for (const e of events) s.add(e.Type);
    return Array.from(s).sort();
  }, [events]);

  const effectiveFilter = manualType.trim() || typeFilter;
  const filtered = effectiveFilter
    ? events.filter((e) => e.Type === effectiveFilter)
    : events;

  const toggle = (id: number) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });

  const loadMore = async () => {
    if (events.length === 0 || loadingMore) return;
    setLoadingMore(true);
    try {
      const oldest = events[events.length - 1];
      const r = await getEvents({ limit: String(PAGE_SIZE), cursor: String(oldest.ID) });
      const more = r.events ?? [];
      setEvents((prev) => {
        const seen = new Set(prev.map((p) => p.ID));
        return [...prev, ...more.filter((m) => !seen.has(m.ID))];
      });
    } finally {
      setLoadingMore(false);
    }
  };

  const dotClass =
    streamState === 'open' ? 'live-dot live' : streamState === 'error' ? 'live-dot error' : 'live-dot';
  const dotLabel =
    streamState === 'open' ? 'Streaming' : streamState === 'error' ? 'Stream error' : 'Connecting…';

  return (
    <>
      <div className="card-header">
        <h2>Event timeline</h2>
        <span className="live-indicator">
          <span className={dotClass} />
          {dotLabel}
        </span>
      </div>

      <div className="filter-bar">
        <label>
          Type
          <select value={typeFilter} onChange={(e) => { setTypeFilter(e.target.value); setManualType(''); }}>
            <option value="">All ({events.length})</option>
            {observedTypes.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </label>
        <label>
          or
          <input
            type="text"
            value={manualType}
            onChange={(e) => setManualType(e.target.value)}
            placeholder="Type name…"
            style={{ width: '11rem' }}
          />
        </label>
        <div className="spacer" />
        <label>
          <input type="checkbox" checked={autoScroll} onChange={(e) => setAutoScroll(e.target.checked)} />
          Auto-scroll
        </label>
        <span className="muted" style={{ fontSize: '0.8rem' }}>
          showing {filtered.length} of {events.length}
        </span>
      </div>

      <div className="table-wrap">
        <table>
          <thead ref={topRef}>
            <tr>
              <th style={{ width: '8.5rem' }}>Time</th>
              <th>Type</th>
              <th>Host</th>
              <th>PID</th>
              <th>Comm</th>
              <th>UID</th>
              <th>Ret</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={7}><div className="empty">No events match the current filter.</div></td></tr>
            ) : (
              filtered.flatMap((e) => {
                const isOpen = expanded.has(e.ID);
                const tint = impactClass(e.Type);
                const rows = [
                  <tr
                    key={e.ID}
                    className={`expandable ${tint} ${isOpen ? 'expanded' : ''}`}
                    onClick={() => toggle(e.ID)}
                  >
                    <td title={new Date(e.Ts).toLocaleString()}>{relativeTime(e.Ts)}</td>
                    <td>{e.Type}</td>
                    <td className="text-mono">{e.Host}</td>
                    <td className="text-mono">{e.PID}</td>
                    <td className="text-mono">{e.Comm}</td>
                    <td className="text-mono">{e.UID}</td>
                    <td className="text-mono">{e.Ret}</td>
                  </tr>,
                ];
                if (isOpen) {
                  rows.push(
                    <tr key={`d-${e.ID}`} className="detail-row">
                      <td colSpan={7}>
                        <div className="detail-grid">
                          <div className="k">Event ID</div><div className="v">{e.ID}</div>
                          <div className="k">Timestamp</div><div className="v">{new Date(e.Ts).toLocaleString()}</div>
                          <div className="k">Source</div><div className="v">{e.Source}</div>
                          <div className="k">PPID</div><div className="v">{e.PPID}</div>
                          <div className="k">CgroupID</div><div className="v">{e.CgroupID}</div>
                        </div>
                        <pre className="detail-json">{JSON.stringify(parseDetail(e), null, 2) || '(no detail)'}</pre>
                      </td>
                    </tr>,
                  );
                }
                return rows;
              })
            )}
          </tbody>
        </table>
      </div>

      <div style={{ marginTop: '0.85rem', textAlign: 'center' }}>
        <button className="ghost" onClick={loadMore} disabled={loadingMore || events.length === 0}>
          {loadingMore ? <><span className="spinner" /> Loading…</> : 'Load older events'}
        </button>
      </div>
    </>
  );
}
