import { NavLink, Routes, Route } from 'react-router-dom';
import Timeline from './pages/Timeline';
import Alerts from './pages/Alerts';
import Rules from './pages/Rules';
import Config from './pages/Config';

export default function App() {
  return (
    <>
      <nav>
        <strong style={{ marginRight: '1rem' }}>vakta</strong>
        <NavLink to="/" end>Timeline</NavLink>
        <NavLink to="/alerts">Alerts</NavLink>
        <NavLink to="/rules">Rules</NavLink>
        <NavLink to="/config">Config</NavLink>
      </nav>
      <main>
        <Routes>
          <Route path="/" element={<Timeline />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/rules" element={<Rules />} />
          <Route path="/config" element={<Config />} />
        </Routes>
      </main>
    </>
  );
}
