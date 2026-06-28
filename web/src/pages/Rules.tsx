import { useEffect, useState } from 'react';
import { getRules, reloadRules, testRule } from '../api';

type Rule = {
  ID: string; Name: string; Severity: string; EventType: string; Condition: string; Tags: string[];
};

export default function Rules() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [testEv, setTestEv] = useState('{"Type":"EXEC","UID":0}');
  const [testResult, setTestResult] = useState<string>('');

  const load = () => getRules().then((r) => setRules(r.rules || []));
  useEffect(() => { load(); }, []);

  const reload = async () => { await reloadRules(); load(); };
  const runTest = async () => {
    try {
      const ev = JSON.parse(testEv);
      const r = await testRule(ev);
      setTestResult(JSON.stringify(r, null, 2));
    } catch (e: any) {
      setTestResult(String(e));
    }
  };

  return (
    <>
      <button onClick={reload}>Reload rules from disk</button>
      <h3>Test rule</h3>
      <textarea rows={5} cols={60} value={testEv} onChange={(e) => setTestEv(e.target.value)} />
      <br />
      <button onClick={runTest}>Test</button>
      <pre>{testResult}</pre>
      <h3>Loaded rules</h3>
      <table>
        <thead>
          <tr><th>ID</th><th>Severity</th><th>Event type</th><th>Condition</th></tr>
        </thead>
        <tbody>
          {rules.map((r) => (
            <tr key={r.ID}>
              <td>{r.ID}</td>
              <td><span className={`badge sev-${r.Severity}`}>{r.Severity}</span></td>
              <td>{r.EventType || '(any)'}</td>
              <td><code>{r.Condition}</code></td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
