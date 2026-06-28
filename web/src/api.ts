const base = '';

export async function getEvents(params: Record<string,string> = {}) {
  const qs = new URLSearchParams(params).toString();
  const r = await fetch(`${base}/api/v1/events${qs ? '?' + qs : ''}`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

export async function getAlerts() {
  const r = await fetch(`${base}/api/v1/alerts`);
  return r.json();
}

export async function getRules() {
  const r = await fetch(`${base}/api/v1/rules`);
  return r.json();
}

export async function reloadRules() {
  const r = await fetch(`${base}/api/v1/rules/reload`, { method: 'POST' });
  return r.json();
}

export async function testRule(event: any) {
  const r = await fetch(`${base}/api/v1/rules/test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ event }),
  });
  return r.json();
}

export function streamEvents(onEvent: (ev: any) => void): () => void {
  const src = new EventSource(`${base}/api/v1/events/stream`);
  src.onmessage = (m) => onEvent(JSON.parse(m.data));
  return () => src.close();
}
