import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { getStats, getAlerts, relativeTime, type VaktaStats, type VaktaAlert } from '../api';

function pickStat(s: VaktaStats | null, primary: keyof VaktaStats, fallback: keyof VaktaStats): string {
  if (!s) return '—';
  const v = s[primary] ?? s[fallback];
  return v == null ? '—' : String(v);
}

export default function Dashboard() {
  const [stats, setStats] = useState<VaktaStats | null>(null);
  const [alerts, setAlerts] = useState<VaktaAlert[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    const refresh = () => {
      Promise.all([getStats(), getAlerts({ limit: '10' })])
        .then(([s, a]) => {
          if (!alive) return;
          setStats(s);
          setAlerts((a.alerts ?? []).slice(0, 10));
          setErr(null);
          setLoading(false);
        })
        .catch((e) => {
          if (!alive) return;
          setErr(String(e));
          setLoading(false);
        });
    };
    refresh();
    const id = setInterval(refresh, 30_000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  return (
    <>
      <div className="card-header">
        <h2>Overview</h2>
        <span className="muted" style={{ fontSize: '0.78rem' }}>auto-refreshing every 30s</span>
      </div>

      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-label">Total events</div>
          <div className="stat-value">{pickStat(stats, 'events_total', 'events')}</div>
          <div className="stat-sub">stored in SQLite</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Alerts</div>
          <div className="stat-value">{pickStat(stats, 'alerts_total', 'alerts')}</div>
          <div className="stat-sub">all-time fired</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Rules loaded</div>
          <div className="stat-value">{stats?.rules ?? '—'}</div>
          <div className="stat-sub">policy engine</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Action runs</div>
          <div className="stat-value">{pickStat(stats, 'action_runs_total', 'action_runs')}</div>
          <div className="stat-sub">{stats?.actions != null ? `${stats.actions} actions defined` : 'playbook'}</div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>Recent alerts</h3>
          <Link to="/alerts" className="muted" style={{ fontSize: '0.82rem' }}>View all →</Link>
        </div>
        {loading ? (
          <div className="loading"><span className="spinner" /> Loading…</div>
        ) : err ? (
          <div className="empty">Failed to load: {err}</div>
        ) : alerts.length === 0 ? (
          <div className="empty">No alerts yet.</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>When</th>
                  <th>Severity</th>
                  <th>Rule</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((a) => (
                  <tr key={a.ID}>
                    <td title={new Date(a.FiredAt).toLocaleString()}>{relativeTime(a.FiredAt)}</td>
                    <td><span className={`badge sev-${a.Severity}`}>{a.Severity}</span></td>
                    <td>
                      {a.RuleName}{' '}
                      <span className="muted text-mono" style={{ fontSize: '0.78rem' }}>({a.RuleID})</span>
                    </td>
                    <td><span className={`badge status-${a.Status}`}>{a.Status}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}
