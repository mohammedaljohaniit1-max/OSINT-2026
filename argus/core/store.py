"""
SQLite persistence + monitor-mode diffing.

Each scan is stored so `monitor` profile can diff runs and alert on NEW
findings (new subdomain, new breach, new exposed secret).
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from .models import IntelGraph


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY, target TEXT, type TEXT, ts REAL, json TEXT);
CREATE TABLE IF NOT EXISTS entities(
  scan_id INTEGER, eid TEXT, etype TEXT, value TEXT, risk TEXT, conf REAL);
"""


class Store:
    def __init__(self, path="reports/argus.db"):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.executescript(SCHEMA)

    def save(self, graph: IntelGraph) -> int:
        meta = graph.run_meta
        cur = self.conn.execute(
            "INSERT INTO scans(target,type,ts,json) VALUES(?,?,?,?)",
            (meta.get("target"), meta.get("target_type"), time.time(),
             json.dumps(graph.to_dict())),
        )
        sid = cur.lastrowid
        for e in graph.entities.values():
            self.conn.execute(
                "INSERT INTO entities VALUES(?,?,?,?,?,?)",
                (sid, e.id, e.type.value, e.value, e.risk.value, e.confidence),
            )
        self.conn.commit()
        return sid

    def previous_entities(self, target: str) -> set[str]:
        row = self.conn.execute(
            "SELECT id FROM scans WHERE target=? ORDER BY ts DESC LIMIT 1 OFFSET 1",
            (target,),
        ).fetchone()
        if not row:
            return set()
        return {r[0] for r in self.conn.execute(
            "SELECT eid FROM entities WHERE scan_id=?", (row[0],))}

    def close(self):
        self.conn.close()
