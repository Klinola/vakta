import { useEffect, useState } from 'react';
import { getRules, reloadRules, testRule, type VaktaRule } from '../api';

const SAMPLE_EVENT = `{
  "Type": "EXEC",
  "UID": 0,
  "Comm": "bash",
  "PID": 1234,
  "Detail": {}
}`;

export default function Rules() {
  const [rules, setRules] = useState<VaktaRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [reloadMsg, setReloadMsg] = useState<string | null>(null);
  const [reloading, setReloading] = useState(false);

  const [testEv, setTestEv] = useState(SAMPLE_EVENT);
  const [testResult, setTestResult] = useState<string>('');
  const [testing, setTesting] = useState(false);

  const load = () => {
    setLoading(true);
    return getRules()
      .then((r) => { setRules(r.rules ?? []); setErr(null); })
      .catch((e) => setErr(String(e)))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const onReload = async () => {
    setReloading(true);
    setReloadMsg(null);
    try {
      const r = await reloadRules();
      await load();
      const count = r.rules ?? r.count;
      setReloadMsg(count != null ? `Reloaded — ${count} rules now loaded.` : 'Reloaded successfully.');
    } catch (e) {
      setReloadMsg(`Reload failed: ${e}`);
    } finally {
      setReloading(false);
    }
  };

  const runTest = async () => {
    setTesting(true);
    try {
      const ev = JSON.parse(testEv);
      const r = await testRule(ev);
      setTestResult(JSON.stringify(r, null, 2));
    } catch (e) {
      setTestResult(String(e));
    } finally {
      setTesting(false);
    }
  };

  return (
    <>
      <div className="card">
        <div className="card-header">
          <h3>Policy engine</h3>
          <div className="toolbar" style={{ margin: 0 }}>
            <button onClick={onReload} disabled={reloading}>
              {reloading ? <><span className="spinner" /> Reloading…</> : 'Reload from disk'}
            </button>
          </div>
        </div>
        {reloadMsg && <p style={{ margin: '0.4rem 0 0', color: 'var(--text2)' }}>{reloadMsg}</p>}
      </div>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>Test a synthetic event</h3>
        <p className="muted" style={{ fontSize: '0.82rem', marginTop: 0 }}>
          JSON shape mirrors a normalized event. Result lists any rules that would fire.
        </p>
        <textarea rows={8} value={testEv} onChange={(e) => setTestEv(e.target.value)} />
        <div style={{ marginTop: '0.5rem' }}>
          <button onClick={runTest} disabled={testing}>
            {testing ? <><span className="spinner" /> Testing…</> : 'Test'}
          </button>
        </div>
        {testResult && <pre className="detail-json" style={{ marginTop: '0.6rem', maxHeight: '320px' }}>{testResult}</pre>}
      </div>

      <div className="card-header">
        <h3 style={{ margin: 0 }}>Loaded rules</h3>
        <span className="muted" style={{ fontSize: '0.82rem' }}>{rules.length} total</span>
      </div>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Severity</th>
              <th>Event type</th>
              <th>Source</th>
              <th>Condition</th>
              <th>Tags</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={8}><div className="loading"><span className="spinner" /> Loading…</div></td></tr>
            ) : err ? (
              <tr><td colSpan={8}><div className="empty">Failed to load: {err}</div></td></tr>
            ) : rules.length === 0 ? (
              <tr><td colSpan={8}><div className="empty">No rules loaded.</div></td></tr>
            ) : (
              rules.map((r) => {
                const tags = r.Tags ?? [];
                const cond = r.Condition || '';
                const truncated = cond.length > 60 ? cond.slice(0, 60) + '…' : cond;
                return (
                  <tr key={r.ID}>
                    <td className="text-mono">{r.ID}</td>
                    <td>{r.Name || <span className="muted">—</span>}</td>
                    <td><span className={`badge sev-${r.Severity}`}>{r.Severity}</span></td>
                    <td className="text-mono">{r.EventType || <span className="muted">(any)</span>}</td>
                    <td className="text-mono muted">{r.Source || '(any)'}</td>
                    <td>
                      {cond
                        ? <code className="condition-cell" title={cond}>{truncated}</code>
                        : <span className="muted">—</span>}
                    </td>
                    <td>
                      {tags.length === 0
                        ? <span className="muted">—</span>
                        : tags.map((t) => <span key={t} className="pill">{t}</span>)}
                    </td>
                    <td className="text-mono muted">{r.ActionID || '—'}</td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}
