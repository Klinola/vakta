import { useEffect, useState } from 'react';
import {
  getActions,
  getActionRuns,
  nullableNum,
  relativeTime,
  type VaktaAction,
  type VaktaActionRun,
} from '../api';

function durationMs(startISO: string, finished: VaktaActionRun['FinishedAt']): string {
  const start = new Date(startISO).getTime();
  if (!Number.isFinite(start)) return '—';
  const finishedNs = nullableNum(finished);
  if (finishedNs == null) return 'running';
  const end = finishedNs / 1_000_000; // ns → ms
  const ms = end - start;
  if (ms < 0) return '—';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60_000).toFixed(1)}m`;
}

function summarizeSteps(stepsJSON: string): string {
  if (!stepsJSON) return '';
  try {
    const arr = JSON.parse(stepsJSON) as Array<{ Output?: string; Err?: string; Skipped?: boolean; ID?: string }>;
    if (!Array.isArray(arr) || arr.length === 0) return '';
    const errored = arr.filter((s) => s.Err);
    if (errored.length > 0) return `${errored.length} step error(s): ${errored[0].Err}`;
    const lastWithOutput = [...arr].reverse().find((s) => s.Output);
    if (lastWithOutput?.Output) return lastWithOutput.Output;
    return `${arr.length} step(s) ok`;
  } catch {
    return stepsJSON.slice(0, 80);
  }
}

export default function Actions() {
  const [actions, setActions] = useState<VaktaAction[]>([]);
  const [runs, setRuns] = useState<VaktaActionRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    Promise.all([getActions(), getActionRuns()])
      .then(([a, r]) => {
        setActions(a.actions ?? []);
        setRuns(r.action_runs ?? []);
        setErr(null);
      })
      .catch((e) => setErr(String(e)))
      .finally(() => setLoading(false));
  }, []);

  return (
    <>
      <div className="card-header">
        <h2>Actions</h2>
        <span className="muted" style={{ fontSize: '0.82rem' }}>
          {actions.length} defined · {runs.length} recent runs
        </span>
      </div>

      <h3>Loaded playbooks</h3>
      {loading ? (
        <div className="loading"><span className="spinner" /> Loading…</div>
      ) : err ? (
        <div className="empty">Failed to load: {err}</div>
      ) : actions.length === 0 ? (
        <div className="empty">No actions defined.</div>
      ) : (
        <div className="action-card-list">
          {actions.map((a) => (
            <div key={a.ID} className="action-card">
              <div className="title">{a.Name || a.ID}</div>
              <div className="muted text-mono" style={{ fontSize: '0.78rem' }}>{a.ID}</div>
              <div className="meta">
                <span className="pill">{a.Steps?.length ?? 0} steps</span>
                {a.DryRun && <span className="pill dryrun">dry-run</span>}
              </div>
              {a.Steps && a.Steps.length > 0 && (
                <div className="step-list">
                  {a.Steps.slice(0, 5).map((s, i) => (
                    <div key={s.ID || i}>{i + 1}. {s.Action}{s.ID ? ` (${s.ID})` : ''}</div>
                  ))}
                  {a.Steps.length > 5 && <div className="muted">…+{a.Steps.length - 5} more</div>}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      <h3 style={{ marginTop: '1.5rem' }}>Recent action runs</h3>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Started</th>
              <th>Action</th>
              <th>Status</th>
              <th>Duration</th>
              <th>Alert</th>
              <th>Output</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6}><div className="loading"><span className="spinner" /> Loading…</div></td></tr>
            ) : runs.length === 0 ? (
              <tr><td colSpan={6}><div className="empty">No action runs recorded yet.</div></td></tr>
            ) : (
              runs.map((r) => {
                const alertId = nullableNum(r.AlertID);
                const summary = summarizeSteps(r.StepsJSON);
                const truncated = summary.length > 80 ? summary.slice(0, 80) + '…' : summary;
                return (
                  <tr key={r.ID}>
                    <td title={new Date(r.StartedAt).toLocaleString()}>{relativeTime(r.StartedAt)}</td>
                    <td>
                      <span className="text-mono">{r.ActionID}</span>
                      {r.DryRun && <> <span className="pill dryrun">dry-run</span></>}
                    </td>
                    <td><span className={`badge status-${r.Status || 'running'}`}>{r.Status || 'running'}</span></td>
                    <td className="text-mono">{durationMs(r.StartedAt, r.FinishedAt)}</td>
                    <td className="text-mono muted">{alertId ?? '—'}</td>
                    <td title={summary} className="muted" style={{ fontSize: '0.82rem' }}>{truncated || '—'}</td>
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
