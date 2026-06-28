import { useEffect, useState } from 'react';
import { NavLink, Routes, Route } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import Timeline from './pages/Timeline';
import Alerts from './pages/Alerts';
import Rules from './pages/Rules';
import Actions from './pages/Actions';
import Config from './pages/Config';
import { streamEvents } from './api';

export default function App() {
  // Global SSE health indicator — keeps the nav "Live" dot meaningful
  // regardless of which page is mounted.
  const [streamState, setStreamState] = useState<'connecting' | 'open' | 'error'>('connecting');

  useEffect(() => {
    const h = streamEvents(
      () => {
        /* discard — Timeline owns the real feed */
      },
      (s) => setStreamState(s),
    );
    return h.close;
  }, []);

  const dotClass =
    streamState === 'open' ? 'live-dot live' : streamState === 'error' ? 'live-dot error' : 'live-dot';
  const label =
    streamState === 'open' ? 'Live' : streamState === 'error' ? 'Disconnected' : 'Connecting…';

  return (
    <>
      <nav>
        <span className="brand">vakta</span>
        <NavLink to="/" end>Dashboard</NavLink>
        <NavLink to="/events">Events</NavLink>
        <NavLink to="/alerts">Alerts</NavLink>
        <NavLink to="/rules">Rules</NavLink>
        <NavLink to="/actions">Actions</NavLink>
        <NavLink to="/config">Config</NavLink>
        <div className="nav-right">
          <span className="live-indicator">
            <span className={dotClass} />
            {label}
          </span>
        </div>
      </nav>
      <main>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/events" element={<Timeline />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/rules" element={<Rules />} />
          <Route path="/actions" element={<Actions />} />
          <Route path="/config" element={<Config />} />
        </Routes>
      </main>
    </>
  );
}
