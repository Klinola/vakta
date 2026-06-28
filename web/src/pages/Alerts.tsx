import { useEffect, useMemo, useState } from 'react';
import { getAlerts, nullableNum, nullableStr, relativeTime, type VaktaAlert } from '../api';

const SEVERITIES = ['', 'critical', 'high', 'warning', 'info'];
const STATUSES = ['', 'firing', 'resolved', 'suppressed'];

function tintFor(sev: string): string {
  if (sev === 'critical') return 'tint-crit';
  if (sev === 'high') return 'tint-high';
  if (sev === 'warning') return 'tint-warn';
  return '';
}

export default function Alerts() {
  const [alerts, setAlerts] = useState<VaktaAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [sev, setSev] = useState('');
  const [status, setStatus] = useState('');
  const [expanded, setExpanded] = useState<Set<number>>(new Set());

  useEffect(() => {
    setLoading(true);
    getAlerts({ limit: '200' })
      .then((r) => { setAlerts(r.alerts ?? []); setErr(null); })
      .catch((e) => setErr(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const filtered = useMemo(() => {
    return alerts.filter((a) =>
      (!sev || a.Severity === sev) &&
      (!status || a.Status === status)
    );
  }, [alerts, sev, status]);

  const toggle = (id: number) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });

  return (
    <>
      <div className="card-header">
        <h2>Alerts</h2>
        <span className="muted" style={{ fontSize: '0.82rem' }}>
          {filtered.length} of {alerts.length} shown
        </span>
      </div>

      <div className="filter-bar">
        <label>
          Severity
          <select value={sev} onChange={(e) => setSev(e.target.value)}>
            {SEVERITIES.map((s) => <option key={s || 'any'} value={s}>{s || 'All'}</option>)}
          </select>
        </label>
        <label>
          Status
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            {STATUSES.map((s) => <option key={s || 'any'} value={s}>{s || 'All'}</option>)}
          </select>
        </label>
        {(sev || status) && (
          <button className="ghost small" onClick={() => { setSev(''); setStatus(''); }}>
            Clear filters
          </button>
        )}
      </div>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th style={{ width: '9rem' }}>Fired</th>
              <th>Severity</th>
              <th>Rule</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={5}><div className="loading"><span className="spinner" /> Loading…</div></td></tr>
            ) : err ? (
              <tr><td colSpan={5}><div className="empty">Failed to load: {err}</div></td></tr>
            ) : filtered.length === 0 ? (
              <tr><td colSpan={5}><div className="empty">No alerts match the current filter.</div></td></tr>
            ) : (
              filtered.flatMap((a) => {
                const isOpen = expanded.has(a.ID);
                const eventId = nullableNum(a.EventID);
                const actionId = nullableStr(a.ActionID);
                const rows = [
                  <tr
                    key={a.ID}
                    className={`expandable ${tintFor(a.Severity)} ${isOpen ? 'expanded' : ''}`}
                    onClick={() => toggle(a.ID)}
                  >
                    <td title={new Date(a.FiredAt).toLocaleString()}>{relativeTime(a.FiredAt)}</td>
                    <td><span className={`badge sev-${a.Severity}`}>{a.Severity}</span></td>
                    <td>
                      {a.RuleName}{' '}
                      <span className="muted text-mono" style={{ fontSize: '0.78rem' }}>({a.RuleID})</span>
                    </td>
                    <td><span className={`badge status-${a.Status}`}>{a.Status}</span></td>
                    <td className="text-mono muted">{actionId ?? '—'}</td>
                  </tr>,
                ];
                if (isOpen) {
                  rows.push(
                    <tr key={`d-${a.ID}`} className="detail-row">
                      <td colSpan={5}>
                        <div className="detail-grid">
                          <div className="k">Alert ID</div><div className="v">{a.ID}</div>
                          <div className="k">Rule ID</div><div className="v">{a.RuleID}</div>
                          <div className="k">Event ID</div><div className="v">{eventId ?? '(none)'}</div>
                          <div className="k">Action ID</div><div className="v">{actionId ?? '(none)'}</div>
                          <div className="k">Fired at</div><div className="v">{new Date(a.FiredAt).toLocaleString()}</div>
                          {a.Tags && a.Tags.length > 0 && (
                            <>
                              <div className="k">Tags</div>
                              <div className="v">
                                {a.Tags.map((t) => <span key={t} className="pill">{t}</span>)}
                              </div>
                            </>
                          )}
                        </div>
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
    </>
  );
}
