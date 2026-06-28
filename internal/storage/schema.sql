CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    host        TEXT    NOT NULL,
    source      INTEGER NOT NULL,
    type        TEXT    NOT NULL,
    cgroup_id   INTEGER NOT NULL DEFAULT 0,
    pid         INTEGER,
    ppid        INTEGER,
    uid         INTEGER,
    comm        TEXT,
    ret         INTEGER NOT NULL DEFAULT 0,
    detail_json TEXT    NOT NULL DEFAULT '{}',
    created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(type, ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_pid  ON events(pid, ts DESC);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY,
    rule_id     TEXT    NOT NULL,
    rule_name   TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    event_id    INTEGER REFERENCES events(id),
    action_id   TEXT,
    status      TEXT    NOT NULL DEFAULT 'firing',
    tags_json   TEXT    NOT NULL DEFAULT '[]',
    fired_at    INTEGER NOT NULL,
    resolved_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_alerts_fired  ON alerts(fired_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_rule   ON alerts(rule_id, fired_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, fired_at DESC);

CREATE TABLE IF NOT EXISTS action_runs (
    id          INTEGER PRIMARY KEY,
    action_id   TEXT    NOT NULL,
    alert_id    INTEGER REFERENCES alerts(id),
    dry_run     INTEGER NOT NULL DEFAULT 0,
    status      TEXT    NOT NULL,
    steps_json  TEXT    NOT NULL DEFAULT '[]',
    started_at  INTEGER NOT NULL,
    finished_at INTEGER
);
