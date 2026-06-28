const base = '';

export type VaktaEvent = {
  ID: number;
  Ts: string;
  Source: number;
  Type: string;
  Host: string;
  PID: number;
  PPID: number;
  UID: number;
  Comm: string;
  Ret: number;
  CgroupID: number;
  Detail?: unknown;
  DetailJSON?: string;
};

export type NullableInt = number | { Int64: number; Valid: boolean } | null;
export type NullableString = string | { String: string; Valid: boolean } | null;

export type VaktaAlert = {
  ID: number;
  RuleID: string;
  RuleName: string;
  Severity: string;
  EventID?: NullableInt;
  ActionID?: NullableString;
  Status: string;
  Tags?: string[] | null;
  FiredAt: string;
};

export type VaktaRule = {
  ID: string;
  Name: string;
  Severity: string;
  Source: string;
  EventType: string;
  Condition: string;
  Tags?: string[] | null;
  ActionID: string;
};

export type VaktaStep = {
  ID: string;
  Action: string;
  Params: Record<string, unknown>;
  Condition: string;
};

export type VaktaAction = {
  ID: string;
  Name: string;
  DryRun: boolean;
  Steps: VaktaStep[];
};

export type VaktaActionRun = {
  ID: number;
  ActionID: string;
  AlertID?: NullableInt;
  DryRun: boolean;
  Status: string;
  StepsJSON: string;
  StartedAt: string;
  FinishedAt?: NullableInt;
};

export type VaktaStats = {
  rules?: number;
  events?: number;
  alerts?: number;
  action_runs?: number;
  events_total?: number;
  alerts_total?: number;
  action_runs_total?: number;
  actions?: number;
};

async function fetchJSON<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`${base}${path}`, init);
  if (!r.ok) throw new Error(`HTTP ${r.status} on ${path}`);
  return r.json() as Promise<T>;
}

export function getEvents(params: Record<string, string> = {}) {
  const qs = new URLSearchParams(params).toString();
  return fetchJSON<{ events: VaktaEvent[] | null }>(`/api/v1/events${qs ? '?' + qs : ''}`);
}

export function getAlerts(params: Record<string, string> = {}) {
  const qs = new URLSearchParams(params).toString();
  return fetchJSON<{ alerts: VaktaAlert[] | null; total?: number }>(`/api/v1/alerts${qs ? '?' + qs : ''}`);
}

export function getRules() {
  return fetchJSON<{ rules: VaktaRule[] | null }>('/api/v1/rules');
}

export function reloadRules() {
  return fetchJSON<{ ok?: boolean; rules?: number; count?: number }>('/api/v1/rules/reload', { method: 'POST' });
}

export function testRule(event: unknown) {
  return fetchJSON<{ matches?: unknown[] | null }>('/api/v1/rules/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ event }),
  });
}

export function getStats() {
  return fetchJSON<VaktaStats>('/api/v1/stats');
}

export function getActions() {
  return fetchJSON<{ actions: VaktaAction[] | null }>('/api/v1/actions');
}

export function getActionRuns(params: Record<string, string> = {}) {
  const qs = new URLSearchParams(params).toString();
  return fetchJSON<{ action_runs: VaktaActionRun[] | null }>(`/api/v1/action-runs${qs ? '?' + qs : ''}`);
}

export type StreamHandle = {
  close: () => void;
  source: EventSource;
};

export function streamEvents(
  onEvent: (ev: VaktaEvent) => void,
  onStatus?: (state: 'open' | 'error') => void,
): StreamHandle {
  const src = new EventSource(`${base}/api/v1/events/stream`);
  src.onopen = () => onStatus?.('open');
  src.onerror = () => onStatus?.('error');
  src.onmessage = (m) => {
    try {
      onEvent(JSON.parse(m.data) as VaktaEvent);
    } catch {
      /* ignore malformed frame */
    }
  };
  return { close: () => src.close(), source: src };
}

/* ── helpers ────────────────────────────────────────── */

export function nullableNum(v: NullableInt | undefined): number | null {
  if (v == null) return null;
  if (typeof v === 'number') return v;
  return v.Valid ? v.Int64 : null;
}

export function nullableStr(v: NullableString | undefined): string | null {
  if (v == null) return null;
  if (typeof v === 'string') return v || null;
  return v.Valid ? v.String : null;
}

export function relativeTime(iso: string): string {
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return iso;
  const diff = Date.now() - t;
  const s = Math.floor(diff / 1000);
  if (s < 5) return 'just now';
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}
