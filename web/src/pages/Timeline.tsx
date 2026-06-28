import { useEffect, useState } from 'react';
import { getEvents, streamEvents } from '../api';

type Event = {
  ID: number; Ts: string; Type: string; Host: string;
  PID: number; Comm: string; Ret: number;
};

export default function Timeline() {
  const [events, setEvents] = useState<Event[]>([]);
  const [typeFilter, setTypeFilter] = useState('');

  useEffect(() => {
    getEvents().then((r) => setEvents(r.events || []));
    const stop = streamEvents((ev) => setEvents((prev) => [ev, ...prev].slice(0, 500)));
    return stop;
  }, []);

  const filtered = typeFilter
    ? events.filter((e) => e.Type === typeFilter)
    : events;

  return (
    <>
      <div style={{ marginBottom: '0.5rem' }}>
        <label>Type: </label>
        <input value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} placeholder="EXEC, CONNECT, ..." />
      </div>
      <table>
        <thead>
          <tr>
            <th>Time</th><th>Type</th><th>Host</th><th>PID</th><th>Comm</th><th>Ret</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((e) => (
            <tr key={e.ID}>
              <td>{new Date(e.Ts).toLocaleTimeString()}</td>
              <td>{e.Type}</td>
              <td>{e.Host}</td>
              <td>{e.PID}</td>
              <td>{e.Comm}</td>
              <td>{e.Ret}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
