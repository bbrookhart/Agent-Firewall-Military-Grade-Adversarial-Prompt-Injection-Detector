"""
SOC metrics engine — tracks detection quality KPIs over time.
"""

from __future__ import annotations

import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Generator, Optional

from core.models import FirewallDecision, ScanResult


class MetricsEngine:
    _lock = threading.Lock()

    def __init__(self, db_path: str = "data/metrics.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _get_conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_metrics (
                    run_id            TEXT PRIMARY KEY,
                    request_id        TEXT NOT NULL,
                    session_id        TEXT,
                    timestamp         TEXT NOT NULL,
                    decision          TEXT NOT NULL,
                    threat_level      TEXT NOT NULL,
                    composite_score   REAL NOT NULL,
                    primary_category  TEXT NOT NULL,
                    total_time_ms     REAL,
                    layers_count      INTEGER,
                    tokens_used       INTEGER,
                    canary_triggered  INTEGER DEFAULT 0,
                    ensemble_disagreement REAL,
                    analyst_verified  INTEGER,
                    false_positive    INTEGER,
                    atlas_techniques  TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON scan_metrics(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_dec ON scan_metrics(decision)")
            conn.commit()

    def record(self, result: ScanResult, session_id: Optional[str] = None) -> None:
        with self._lock:
            with self._get_conn() as conn:
                tokens = sum(
                    lr.metadata.get("tokens_used", 0)
                    for lr in result.layer_results if lr.metadata
                )
                conn.execute(
                    "INSERT OR REPLACE INTO scan_metrics VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        result.scan_id, result.request_id, session_id,
                        result.timestamp.isoformat(),
                        result.decision.value, result.threat_level.value,
                        result.composite_score, result.primary_category.value,
                        result.total_processing_time_ms,
                        len(result.layers_executed),
                        tokens or None,
                        int(result.canary_result.triggered if result.canary_result else False),
                        result.ensemble.disagreement_score if result.ensemble else None,
                        None, None,
                        ",".join(result.atlas_annotation.technique_ids) if result.atlas_annotation else "",
                    ),
                )
                conn.commit()

    def get_stats(self, since_hours: int = 24) -> dict[str, Any]:
        since = (datetime.utcnow() - timedelta(hours=since_hours)).isoformat()
        with self._get_conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM scan_metrics WHERE timestamp>=?", (since,)
            ).fetchone()[0]
            if not total:
                return {"total": 0, "period_hours": since_hours}

            blocked = conn.execute("SELECT COUNT(*) FROM scan_metrics WHERE decision='BLOCK' AND timestamp>=?", (since,)).fetchone()[0]
            warned = conn.execute("SELECT COUNT(*) FROM scan_metrics WHERE decision='WARN' AND timestamp>=?", (since,)).fetchone()[0]
            allowed = conn.execute("SELECT COUNT(*) FROM scan_metrics WHERE decision='ALLOW' AND timestamp>=?", (since,)).fetchone()[0]
            human = conn.execute("SELECT COUNT(*) FROM scan_metrics WHERE decision='HUMAN_REVIEW' AND timestamp>=?", (since,)).fetchone()[0]
            canary = conn.execute("SELECT COUNT(*) FROM scan_metrics WHERE canary_triggered=1 AND timestamp>=?", (since,)).fetchone()[0]
            avg_score = conn.execute("SELECT AVG(composite_score) FROM scan_metrics WHERE timestamp>=?", (since,)).fetchone()[0]
            avg_time = conn.execute("SELECT AVG(total_time_ms) FROM scan_metrics WHERE timestamp>=?", (since,)).fetchone()[0]
            p95_time = conn.execute(
                "SELECT composite_score FROM scan_metrics WHERE timestamp>=? ORDER BY total_time_ms",
                (since,)
            ).fetchall()
            p95 = sorted([r[0] for r in p95_time])[int(len(p95_time) * 0.95)] if p95_time else 0

            by_cat = {}
            for row in conn.execute(
                "SELECT primary_category, COUNT(*) FROM scan_metrics WHERE timestamp>=? GROUP BY primary_category",
                (since,),
            ).fetchall():
                by_cat[row[0]] = row[1]

            fp = conn.execute("SELECT COUNT(*) FROM scan_metrics WHERE false_positive=1", ).fetchone()[0]
            verified = conn.execute("SELECT COUNT(*) FROM scan_metrics WHERE analyst_verified=1").fetchone()[0]

            return {
                "total": total, "blocked": blocked, "warned": warned,
                "allowed": allowed, "human_review": human,
                "block_rate": blocked / total,
                "canary_triggers": canary,
                "avg_composite_score": round(avg_score or 0, 2),
                "avg_processing_ms": round(avg_time or 0, 2),
                "p95_processing_ms": round(p95, 2),
                "false_positives_confirmed": fp,
                "analyst_verified": verified,
                "by_category": by_cat,
                "period_hours": since_hours,
            }


_instance: Optional[MetricsEngine] = None

def get_metrics_engine() -> MetricsEngine:
    global _instance
    if _instance is None:
        from config.settings import settings
        _instance = MetricsEngine(db_path=settings.metrics_db_path)
    return _instance
