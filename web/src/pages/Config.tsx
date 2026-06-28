import { useEffect, useState } from 'react';
import { getStats, reloadRules, type VaktaStats } from '../api';

function row(label: string, value: string | number | null | undefined) {
  return (
    <>
      <div className="k">{label}</div>
      <div className="v">{value == null ? '—' : value}</div>
    </>
  );
}

export default function Config() {
  const [stats, setStats] = useState<VaktaStats | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [reloading, setReloading] = useState(false);
  const [reloadMsg, setReloadMsg] = useState<string | null>(null);

  const refresh = () => {
    getStats()
      .then((s) => { setStats(s); setErr(null); })
      .catch((e) => setErr(String(e)));
  };

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 30_000);
    return () => clearInterval(id);
  }, []);

  const onReload = async () => {
    setReloading(true);
    setReloadMsg(null);
    try {
      const r = await reloadRules();
      const count = r.rules ?? r.count;
      setReloadMsg(count != null ? `Reloaded — ${count} rules.` : 'Reloaded successfully.');
      refresh();
    } catch (e) {
      setReloadMsg(`Reload failed: ${e}`);
    } finally {
      setReloading(false);
    }
  };

  return (
    <>
      <div className="card">
        <h3 style={{ marginTop: 0 }}>System status</h3>
        {err ? (
          <p className="empty">Failed to load stats: {err}</p>
        ) : !stats ? (
          <div className="loading"><span className="spinner" /> Loading…</div>
        ) : (
          <div className="detail-grid">
            {row('Rules loaded', stats.rules)}
            {row('Events stored', stats.events_total ?? stats.events)}
            {row('Alerts fired', stats.alerts_total ?? stats.alerts)}
            {row('Action runs', stats.action_runs_total ?? stats.action_runs)}
            {row('Actions defined', stats.actions)}
          </div>
        )}
      </div>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>Configuration</h3>
        <p>
          Configuration is loaded from <code>/etc/vakta/config.yaml</code> on agent startup. Edit the file and
          restart the agent to apply changes, or hot-reload rules below.
        </p>
        <div style={{ marginTop: '0.5rem' }}>
          <button onClick={onReload} disabled={reloading}>
            {reloading ? <><span className="spinner" /> Reloading…</> : 'Reload rules'}
          </button>
          {reloadMsg && <span className="muted" style={{ marginLeft: '0.75rem' }}>{reloadMsg}</span>}
        </div>
      </div>
    </>
  );
}
