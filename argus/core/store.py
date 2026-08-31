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

    # ---------------- management helpers (used by CLI mgmt commands) -------- #
    def list_scans(self, limit: int = 50, target: str | None = None) -> list[dict]:
        """Return scan history: id, target, type, timestamp, entity count."""
        if target:
            rows = self.conn.execute(
                "SELECT id,target,type,ts FROM scans WHERE target=? "
                "ORDER BY ts DESC LIMIT ?", (target, limit)).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT id,target,type,ts FROM scans ORDER BY ts DESC LIMIT ?",
                (limit,)).fetchall()
        out = []
        for sid, tgt, typ, ts in rows:
            n = self.conn.execute(
                "SELECT COUNT(*) FROM entities WHERE scan_id=?", (sid,)).fetchone()[0]
            out.append({"id": sid, "target": tgt, "type": typ, "ts": ts,
                        "entities": n})
        return out

    def get_scan(self, scan_id: int) -> dict | None:
        """Return the full stored graph dict for a scan id (latest if None)."""
        row = self.conn.execute(
            "SELECT json FROM scans WHERE id=?", (scan_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def latest_scan_id(self, target: str | None = None) -> int | None:
        if target:
            row = self.conn.execute(
                "SELECT id FROM scans WHERE target=? ORDER BY ts DESC LIMIT 1",
                (target,)).fetchone()
        else:
            row = self.conn.execute(
                "SELECT id FROM scans ORDER BY ts DESC LIMIT 1").fetchone()
        return row[0] if row else None

    def entities_of(self, scan_id: int) -> dict[str, dict]:
        """eid -> {etype,value,risk,conf} for diffing."""
        rows = self.conn.execute(
            "SELECT eid,etype,value,risk,conf FROM entities WHERE scan_id=?",
            (scan_id,)).fetchall()
        return {r[0]: {"etype": r[1], "value": r[2], "risk": r[3], "conf": r[4]}
                for r in rows}

    def diff(self, target: str) -> dict:
        """Diff the two most recent scans of a target -> added/removed entities."""
        rows = self.conn.execute(
            "SELECT id FROM scans WHERE target=? ORDER BY ts DESC LIMIT 2",
            (target,)).fetchall()
        if len(rows) < 2:
            return {"error": "need at least 2 scans of this target to diff"}
        new_id, old_id = rows[0][0], rows[1][0]
        new_e, old_e = self.entities_of(new_id), self.entities_of(old_id)
        added = [new_e[k] for k in new_e.keys() - old_e.keys()]
        removed = [old_e[k] for k in old_e.keys() - new_e.keys()]
        return {"new_scan": new_id, "old_scan": old_id,
                "added": added, "removed": removed}

    def delete_scan(self, scan_id: int) -> bool:
        cur = self.conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        self.conn.execute("DELETE FROM entities WHERE scan_id=?", (scan_id,))
        self.conn.commit()
        return cur.rowcount > 0

    def clean(self, keep: int = 0, target: str | None = None) -> int:
        """Delete old scans. keep=N keeps the N most recent (per target if given).
        Returns number of scans deleted."""
        if target:
            ids = [r[0] for r in self.conn.execute(
                "SELECT id FROM scans WHERE target=? ORDER BY ts DESC",
                (target,)).fetchall()]
        else:
            ids = [r[0] for r in self.conn.execute(
                "SELECT id FROM scans ORDER BY ts DESC").fetchall()]
        victims = ids[keep:] if keep > 0 else ids
        for sid in victims:
            self.delete_scan(sid)
        return len(victims)

    def stats(self) -> dict:
        total = self.conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        ents = self.conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0]
        targets = self.conn.execute(
            "SELECT COUNT(DISTINCT target) FROM scans").fetchone()[0]
        return {"scans": total, "entities": ents, "distinct_targets": targets}

    def close(self):
        self.conn.close()
