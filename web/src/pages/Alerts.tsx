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
