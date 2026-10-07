"""
Adaptive Systems Optimization Engine (ASOE)
===========================================

A conservative, executable foundation for continuously:
  1. collecting system telemetry,
  2. detecting abnormalities and inefficiencies,
  3. correlating observations into incidents/relationships,
  4. selecting reversible corrective actions,
  5. executing only policy-approved interventions,
  6. verifying post-change state,
  7. rolling back changes when verification fails.

Supported out of the box:
  - CPU, memory, disk, network and process telemetry via psutil
  - persistent SQLite telemetry/event/evidence history
  - rolling statistical baselines
  - anomaly detection using robust z-scores + threshold rules
  - process parent/child and resource relationships
  - conservative local interventions:
        * lower CPU scheduling priority
        * restore scheduling priority
        * stop/isolate a process temporarily
        * resume an isolated process
        * terminate a process only when explicitly allowed
        * reclaim old files only inside configured safe roots
  - action verification and automatic rollback
  - extension interfaces for hardware/cloud adapters
  - dry-run mode by default

IMPORTANT:
This is an adaptive systems-control framework, not a universal autonomous
administrator. Hardware/cloud vendors expose different control planes, so
those controls are represented by adapters rather than pretending there is
one universal API.

Install:
    python -m pip install psutil

Examples:
    python asoe.py
    python asoe.py --interval 5 --execute
    python asoe.py --interval 5 --execute --config asoe.json
    python asoe.py --once --execute

The default policy is intentionally conservative. Start with dry-run, inspect
the SQLite database/logs, then enable individual actions.
"""


from __future__ import annotations

import argparse
import collections
import dataclasses
import datetime as dt
import json
import math
import os
import pathlib
import platform
import re
import signal
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import psutil
except ImportError:
    print("Missing dependency: psutil", file=sys.stderr)
    print("Install with: python -m pip install psutil", file=sys.stderr)
    raise


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "interval_seconds": 5.0,
    "history_seconds": 900,
    "database": "asoe.db",
    "log_file": "asoe.log",
    "dry_run": True,
    "auto_execute": False,

    # Detection thresholds. These are deliberately configurable rather than
    # hard-coded into the decision engine.
    "thresholds": {
        "cpu_percent": 90.0,
        "memory_percent": 90.0,
        "disk_percent": 90.0,
        "load_per_cpu": 1.50,
        "process_cpu_percent": 85.0,
        "process_memory_percent": 25.0,
        "network_bytes_per_sec": 100_000_000.0,
        "anomaly_z": 3.5,
        "persistence_samples": 3,
        "verification_timeout": 20.0,
        "verification_poll": 1.0,
    },

    # Safety policy. "allow_actions" is the only list of action classes the
    # executor can perform automatically.
    "safety": {
        "allow_actions": [
            "lower_priority",
            "isolate_process",
            "reclaim_temp_files",
        ],
        "allow_terminate": False,
        "allow_process_names": [],
        "deny_process_names": [
            "init",
            "systemd",
            "launchd",
            "kernel_task",
            "sshd",
            "loginwindow",
            "explorer.exe",
            "csrss.exe",
            "wininit.exe",
            "services.exe",
            "lsass.exe",
            "system",
        ],
        "max_reclaim_bytes_per_cycle": 100_000_000,
        "temp_roots": [],
        "min_file_age_seconds": 86_400,
        "isolation_seconds": 15.0,
    },

    # Retention controls. Abnormal windows are preserved longer than ordinary
    # telemetry so that future versions can learn from interventions.
    "retention": {
        "telemetry_days": 7,
        "events_days": 30,
        "evidence_days": 90,
        "interventions_days": 365,
    },
}


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = json.loads(json.dumps(base))
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return DEFAULT_CONFIG
    with open(path, "r", encoding="utf-8") as f:
        user_cfg = json.load(f)
    return deep_merge(DEFAULT_CONFIG, user_cfg)


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def safe_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def normalized_name(name: str) -> str:
    return re.sub(r"[^a-z0-9_.-]+", "_", name.lower())


def percentile(values: Sequence[float], p: float) -> float:
    if not values:
        return 0.0
    xs = sorted(values)
    if len(xs) == 1:
        return xs[0]
    rank = (len(xs) - 1) * p
    lo = math.floor(rank)
    hi = math.ceil(rank)
    if lo == hi:
        return xs[lo]
    return xs[lo] + (xs[hi] - xs[lo]) * (rank - lo)


def robust_z(value: float, history: Sequence[float]) -> float:
    """Robust z score using median absolute deviation."""
    if len(history) < 8:
        return 0.0
    med = statistics.median(history)
    deviations = [abs(x - med) for x in history]
    mad = statistics.median(deviations)
    if mad < 1e-12:
        stdev = statistics.pstdev(history)
        if stdev < 1e-12:
            return 0.0
        return (value - med) / stdev
    return 0.6745 * (value - med) / mad


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Telemetry:
    timestamp: str
    observation_id: str
    host_id: str
    source: str
    component: str
    metric: str
    value: float
    unit: str
    interval: float
    confidence: float = 1.0
    tags: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    finding_id: str
    timestamp: str
    host_id: str
    component: str
    metric: str
    value: float
    baseline: float
    deviation: float
    severity: float
    detection_method: str
    evidence: Dict[str, Any]
    relationship_keys: List[str] = field(default_factory=list)


@dataclass
class Relationship:
    relationship_id: str
    timestamp: str
    left: str
    right: str
    relation: str
    strength: float
    evidence: Dict[str, Any]


@dataclass
class ActionPlan:
    action_id: str
    created_at: str
    action_type: str
    target: str
    reason: str
    expected_effect: Dict[str, Any]
    rollback: Dict[str, Any]
    risk: float
    confidence: float
    finding_ids: List[str]
    dry_run: bool = True


@dataclass
class ActionResult:
    action_id: str
    started_at: str
    completed_at: str
    success: bool
    changed: bool
    message: str
    before: Dict[str, Any]
    after: Dict[str, Any]
    verification: Dict[str, Any]
    rolled_back: bool = False


# ---------------------------------------------------------------------------
# SQLite event/evidence store
# ---------------------------------------------------------------------------

class Store:
    def __init__(self, path: str):
        self.path = path
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init()

    def _init(self) -> None:
        with self.lock, self.conn:
            self.conn.executescript("""
            PRAGMA journal_mode=WAL;

            CREATE TABLE IF NOT EXISTS telemetry (
                timestamp TEXT NOT NULL,
                observation_id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL,
                source TEXT NOT NULL,
                component TEXT NOT NULL,
                metric TEXT NOT NULL,
                value REAL NOT NULL,
                unit TEXT NOT NULL,
                interval REAL NOT NULL,
                confidence REAL NOT NULL,
                tags_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_telemetry_metric_time
                ON telemetry(host_id, component, metric, timestamp);

            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                host_id TEXT NOT NULL,
                component TEXT NOT NULL,
                metric TEXT NOT NULL,
                value REAL NOT NULL,
                baseline REAL NOT NULL,
                deviation REAL NOT NULL,
                severity REAL NOT NULL,
                detection_method TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                relationship_keys_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_findings_time
                ON findings(host_id, timestamp);

            CREATE TABLE IF NOT EXISTS relationships (
                relationship_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                left_key TEXT NOT NULL,
                right_key TEXT NOT NULL,
                relation TEXT NOT NULL,
                strength REAL NOT NULL,
                evidence_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS interventions (
                action_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                action_type TEXT NOT NULL,
                target TEXT NOT NULL,
                reason TEXT NOT NULL,
                plan_json TEXT NOT NULL,
                result_json TEXT,
                status TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS system_state (
                timestamp TEXT NOT NULL,
                state_json TEXT NOT NULL
            );
            """)

    def add_telemetry(self, rows: Iterable[Telemetry]) -> None:
        data = [
            (
                x.timestamp, x.observation_id, x.host_id, x.source,
                x.component, x.metric, x.value, x.unit, x.interval,
                x.confidence, json.dumps(x.tags, sort_keys=True)
            )
            for x in rows
        ]
        if not data:
            return
        with self.lock, self.conn:
            self.conn.executemany("""
                INSERT OR REPLACE INTO telemetry
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, data)

    def add_finding(self, x: Finding) -> None:
        with self.lock, self.conn:
            self.conn.execute("""
                INSERT OR REPLACE INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                x.finding_id, x.timestamp, x.host_id, x.component, x.metric,
                x.value, x.baseline, x.deviation, x.severity,
                x.detection_method, json.dumps(x.evidence, sort_keys=True),
                json.dumps(x.relationship_keys, sort_keys=True)
            ))

    def add_relationship(self, x: Relationship) -> None:
        with self.lock, self.conn:
            self.conn.execute("""
                INSERT OR REPLACE INTO relationships
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                x.relationship_id, x.timestamp, x.left, x.right,
                x.relation, x.strength, json.dumps(x.evidence, sort_keys=True)
            ))

    def add_intervention(self, plan: ActionPlan,
                         result: Optional[ActionResult] = None,
                         status: str = "planned") -> None:
        with self.lock, self.conn:
            self.conn.execute("""
                INSERT OR REPLACE INTO interventions
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                plan.action_id, plan.created_at, plan.action_type, plan.target,
                plan.reason, json.dumps(dataclasses.asdict(plan), sort_keys=True),
                json.dumps(dataclasses.asdict(result), sort_keys=True) if result else None,
                status
            ))

    def add_state(self, state: Dict[str, Any]) -> None:
        with self.lock, self.conn:
            self.conn.execute(
                "INSERT INTO system_state VALUES (?, ?)",
                (utc_now(), json.dumps(state, sort_keys=True))
            )

    def history(self, host_id: str, component: str,
                metric: str, limit: int = 180) -> List[float]:
        with self.lock:
            rows = self.conn.execute("""
                SELECT value FROM telemetry
                WHERE host_id=? AND component=? AND metric=?
                ORDER BY timestamp DESC LIMIT ?
            """, (host_id, component, metric, limit)).fetchall()
        return [float(r["value"]) for r in reversed(rows)]

    def recent_findings(self, host_id: str, seconds: float = 60) -> List[sqlite3.Row]:
        cutoff = (dt.datetime.now(dt.timezone.utc) -
                  dt.timedelta(seconds=seconds)).isoformat()
        with self.lock:
            return self.conn.execute("""
                SELECT * FROM findings
                WHERE host_id=? AND timestamp>=?
                ORDER BY timestamp ASC
            """, (host_id, cutoff)).fetchall()

    def purge(self, cfg: Dict[str, Any]) -> None:
        now = dt.datetime.now(dt.timezone.utc)
        retention = cfg["retention"]

        def cutoff(days: int) -> str:
            return (now - dt.timedelta(days=days)).isoformat()

        with self.lock, self.conn:
            self.conn.execute(
                "DELETE FROM telemetry WHERE timestamp < ?",
                (cutoff(retention["telemetry_days"]),)
            )
            self.conn.execute(
                "DELETE FROM findings WHERE timestamp < ?",
                (cutoff(retention["events_days"]),)
            )
            self.conn.execute(
                "DELETE FROM relationships WHERE timestamp < ?",
                (cutoff(retention["events_days"]),)
            )
            self.conn.execute(
                "DELETE FROM interventions WHERE created_at < ?",
                (cutoff(retention["interventions_days"]),)
            )


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

class Logger:
    def __init__(self, path: str):
        self.path = path
        self.lock = threading.Lock()

    def write(self, level: str, message: str, **fields: Any) -> None:
        record = {
            "timestamp": utc_now(),
            "level": level,
            "message": message,
            **fields,
        }
        line = json.dumps(record, sort_keys=True, default=str)
        with self.lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        print(line, flush=True)


# ---------------------------------------------------------------------------
# Telemetry collection
# ---------------------------------------------------------------------------

class LocalCollector:
    """
    Produces normalized telemetry. Process identities include PID + create
    time so a recycled PID is not treated as the same process.
    """

    def __init__(self, interval: float):
        self.interval = interval
        self.host_id = f"{platform.node()}:{platform.system()}:{platform.machine()}"
        self._last_net = None
        self._last_net_time = None
        self._disk_last = None
        self._prime_process_cpu()

    def _prime_process_cpu(self) -> None:
        for proc in psutil.process_iter(["pid"]):
            try:
                proc.cpu_percent(None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    def _process_identity(self, proc: psutil.Process) -> str:
        try:
            create = proc.create_time()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            create = 0
        return f"{proc.pid}:{create:.3f}"

    def collect(self) -> Tuple[List[Telemetry], Dict[str, Any]]:
        now = utc_now()
        rows: List[Telemetry] = []

        # CPU
        cpu = psutil.cpu_percent(interval=None)
        rows.append(Telemetry(
            now, str(uuid.uuid4()), self.host_id, "local",
            "host", "cpu_percent", float(cpu), "percent", self.interval
        ))

        load = os.getloadavg()[0] if hasattr(os, "getloadavg") else cpu / 100.0
        logical = psutil.cpu_count() or 1
        load_per_cpu = load / logical
        rows.append(Telemetry(
            now, str(uuid.uuid4()), self.host_id, "local",
            "host", "load_per_cpu", float(load_per_cpu), "ratio", self.interval
        ))

        # Memory
        vm = psutil.virtual_memory()
        rows.append(Telemetry(
            now, str(uuid.uuid4()), self.host_id, "local",
            "host", "memory_percent", float(vm.percent), "percent", self.interval
        ))
        rows.append(Telemetry(
            now, str(uuid.uuid4()), self.host_id, "local",
            "host", "memory_available_bytes", float(vm.available),
            "bytes", self.interval
        ))

        # Root disk
        try:
            du = psutil.disk_usage(os.path.abspath(os.sep))
            rows.append(Telemetry(
                now, str(uuid.uuid4()), self.host_id, "local",
                "disk", "disk_percent", float(du.percent), "percent", self.interval
            ))
        except Exception:
            pass

        # Network throughput
        try:
            net = psutil.net_io_counters()
            current_total = net.bytes_sent + net.bytes_recv
            current_time = time.monotonic()
            if self._last_net is not None and self._last_net_time is not None:
                elapsed = max(0.001, current_time - self._last_net_time)
                bps = max(0.0, (current_total - self._last_net) / elapsed)
                rows.append(Telemetry(
                    now, str(uuid.uuid4()), self.host_id, "local",
                    "network", "bytes_per_sec", float(bps), "bytes/s", elapsed
                ))
            self._last_net = current_total
            self._last_net_time = current_time
        except Exception:
            pass

        # Processes. Limit to processes visible to the current user where
        # possible; AccessDenied is simply recorded as unavailable.
        process_snapshot = []
        for proc in psutil.process_iter(
            ["pid", "name", "username", "ppid", "status", "memory_info"]
        ):
            try:
                with proc.oneshot():
                    pid = proc.pid
                    name = proc.info.get("name") or "unknown"
                    identity = self._process_identity(proc)
                    cpu_p = proc.cpu_percent(None)
                    rss = proc.memory_info().rss
                    host_mem = max(vm.total, 1)
                    mem_p = 100.0 * rss / host_mem
                    ppid = proc.info.get("ppid") or 0
                    status = proc.info.get("status") or "unknown"

                process_snapshot.append({
                    "identity": identity,
                    "pid": pid,
                    "name": name,
                    "ppid": ppid,
                    "status": status,
                    "cpu_percent": float(cpu_p),
                    "rss_bytes": int(rss),
                    "memory_percent": float(mem_p),
                })

                component = f"process:{identity}:{normalized_name(name)}"
                tags = {
                    "pid": pid,
                    "name": name,
                    "ppid": ppid,
                    "status": status,
                    "identity": identity,
                }

                rows.append(Telemetry(
                    now, str(uuid.uuid4()), self.host_id, "local",
                    component, "cpu_percent", float(cpu_p), "percent",
                    self.interval, tags=tags
                ))
                rows.append(Telemetry(
                    now, str(uuid.uuid4()), self.host_id, "local",
                    component, "memory_percent", float(mem_p), "percent",
                    self.interval, tags=tags
                ))
                rows.append(Telemetry(
                    now, str(uuid.uuid4()), self.host_id, "local",
                    component, "rss_bytes", float(rss), "bytes",
                    self.interval, tags=tags
                ))
            except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
                continue
            except Exception:
                continue

        state = {
            "host_id": self.host_id,
            "timestamp": now,
            "host": {
                "cpu_percent": cpu,
                "load_per_cpu": load_per_cpu,
                "memory_percent": vm.percent,
                "memory_available_bytes": vm.available,
            },
            "processes": process_snapshot,
        }
        return rows, state


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

class Detector:
    def __init__(self, store: Store, cfg: Dict[str, Any]):
        self.store = store
        self.cfg = cfg

    def _threshold_finding(self, t: Telemetry,
                           baseline: float,
                           deviation: float,
                           severity: float,
                           method: str,
                           evidence: Dict[str, Any]) -> Finding:
        return Finding(
            finding_id=str(uuid.uuid4()),
            timestamp=t.timestamp,
            host_id=t.host_id,
            component=t.component,
            metric=t.metric,
            value=t.value,
            baseline=baseline,
            deviation=deviation,
            severity=clamp(severity, 0.0, 1.0),
            detection_method=method,
            evidence=evidence,
            relationship_keys=[t.component, f"{t.component}:{t.metric}"],
        )

    def detect(self, rows: Sequence[Telemetry]) -> List[Finding]:
        findings: List[Finding] = []
        th = self.cfg["thresholds"]

        for t in rows:
            history = self.store.history(
                t.host_id, t.component, t.metric, limit=180
            )
            baseline = statistics.median(history) if history else t.value
            z = robust_z(t.value, history)
            deviation = t.value - baseline

            threshold = None
            if t.metric == "cpu_percent" and t.component == "host":
                threshold = th["cpu_percent"]
            elif t.metric == "memory_percent" and t.component == "host":
                threshold = th["memory_percent"]
            elif t.metric == "disk_percent":
                threshold = th["disk_percent"]
            elif t.metric == "load_per_cpu":
                threshold = th["load_per_cpu"]
            elif t.metric == "bytes_per_sec":
                threshold = th["network_bytes_per_sec"]
            elif t.metric == "cpu_percent" and t.component.startswith("process:"):
                threshold = th["process_cpu_percent"]
            elif t.metric == "memory_percent" and t.component.startswith("process:"):
                threshold = th["process_memory_percent"]

            threshold_hit = threshold is not None and t.value >= threshold
            anomaly_hit = abs(z) >= th["anomaly_z"]

            if not threshold_hit and not anomaly_hit:
                continue

            threshold_score = 0.0
            if threshold is not None and threshold > 0:
                threshold_score = clamp(t.value / threshold - 1.0, 0.0, 1.0)

            z_score = clamp(abs(z) / (th["anomaly_z"] * 2.0), 0.0, 1.0)
            persistence = min(
                len(history) / max(1, th["persistence_samples"]), 1.0
            )

            severity = 0.45 * threshold_score + 0.40 * z_score + 0.15 * persistence

            method = []
            if threshold_hit:
                method.append("threshold")
            if anomaly_hit:
                method.append("robust_z")

            findings.append(self._threshold_finding(
                t=t,
                baseline=baseline,
                deviation=deviation,
                severity=severity,
                method="+".join(method),
                evidence={
                    "history_count": len(history),
                    "robust_z": z,
                    "threshold": threshold,
                    "persistence_proxy": persistence,
                    "tags": t.tags,
                },
            ))

        # Write after detection so current values become history for the next
        # cycle rather than contaminating their own baseline.
        for finding in findings:
            self.store.add_finding(finding)

        return findings


# ---------------------------------------------------------------------------
# Relationship / root-cause analysis
# ---------------------------------------------------------------------------

class RelationshipEngine:
    """
    This is intentionally an evidence-weighting engine, not a claim of formal
    causality. It builds useful candidate relationships from:
      - parent -> child process structure
      - simultaneous host/process anomalies
      - shared resource pressure
      - temporal ordering
    """

    def __init__(self, store: Store):
        self.store = store

    def analyze(self, state: Dict[str, Any],
                findings: Sequence[Finding]) -> List[Relationship]:
        relationships: List[Relationship] = []
        by_component: Dict[str, List[Finding]] = collections.defaultdict(list)
        for f in findings:
            by_component[f.component].append(f)

        processes = {p["pid"]: p for p in state.get("processes", [])}

        # Parent-child relationships.
        for p in state.get("processes", []):
            parent = processes.get(p.get("ppid"))
            if not parent:
                continue

            child_key = f"process:{p['identity']}:{normalized_name(p['name'])}"
            parent_key = f"process:{parent['identity']}:{normalized_name(parent['name'])}"

            child_findings = by_component.get(child_key, [])
            parent_findings = by_component.get(parent_key, [])

            if child_findings and parent_findings:
                strength = clamp(
                    (max(f.severity for f in child_findings) +
                     max(f.severity for f in parent_findings)) / 2.0,
                    0.0, 1.0
                )
                relationships.append(Relationship(
                    relationship_id=str(uuid.uuid4()),
                    timestamp=utc_now(),
                    left=parent_key,
                    right=child_key,
                    relation="parent_child_anomaly",
                    strength=strength,
                    evidence={
                        "parent_pid": parent["pid"],
                        "child_pid": p["pid"],
                    }
                ))

        # Shared-resource relationships: multiple process anomalies occurring
        # in the same cycle under host pressure.
        host_findings = by_component.get("host", [])
        if host_findings:
            host_severity = max(f.severity for f in host_findings)
            process_findings = [
                f for f in findings if f.component.startswith("process:")
            ]
            for pf in process_findings:
                strength = clamp(0.55 * pf.severity + 0.45 * host_severity, 0, 1)
                relationships.append(Relationship(
                    relationship_id=str(uuid.uuid4()),
                    timestamp=utc_now(),
                    left=pf.component,
                    right="host",
                    relation="shared_resource_pressure",
                    strength=strength,
                    evidence={
                        "process_severity": pf.severity,
                        "host_severity": host_severity,
                    }
                ))

        for r in relationships:
            self.store.add_relationship(r)

        return relationships


# ---------------------------------------------------------------------------
# Policy / action selection
# ---------------------------------------------------------------------------

class PolicyEngine:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg

    def _process_name_from_finding(self, f: Finding) -> str:
        return str(f.evidence.get("tags", {}).get("name", ""))

    def _pid_from_finding(self, f: Finding) -> Optional[int]:
        value = f.evidence.get("tags", {}).get("pid")
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _allowed_process(self, name: str) -> bool:
        safety = self.cfg["safety"]
        normalized = normalized_name(name)
        denied = {normalized_name(x) for x in safety["deny_process_names"]}
        allowed = {normalized_name(x) for x in safety["allow_process_names"]}

        if normalized in denied:
            return False
        if allowed and normalized not in allowed:
            return False
        return True

    def choose(self, findings: Sequence[Finding],
               relationships: Sequence[Relationship]) -> List[ActionPlan]:
        plans: List[ActionPlan] = []
        safety = self.cfg["safety"]
        allowed_actions = set(safety["allow_actions"])

        # Group process findings so several metrics on one process produce one
        # intervention rather than competing actions.
        grouped: Dict[str, List[Finding]] = collections.defaultdict(list)
        for f in findings:
            if f.component.startswith("process:"):
                grouped[f.component].append(f)

        for component, fs in grouped.items():
            f = max(fs, key=lambda x: x.severity)
            name = self._process_name_from_finding(f)
            pid = self._pid_from_finding(f)
            if pid is None or not self._allowed_process(name):
                continue

            severe = f.severity >= 0.60
            action_type = None
            expected = {}
            rollback = {}
            risk = 0.0
            confidence = clamp(0.55 + 0.35 * f.severity, 0, 1)

            if f.metric == "cpu_percent" and "lower_priority" in allowed_actions:
                action_type = "lower_priority"
                expected = {"cpu_percent": "decrease"}
                rollback = {"action_type": "restore_priority", "pid": pid}
                risk = 0.15

            elif (
                f.metric == "memory_percent"
                and severe
                and "isolate_process" in allowed_actions
            ):
                action_type = "isolate_process"
                expected = {"memory_pressure": "decrease_or_stabilize"}
                rollback = {
                    "action_type": "resume_process",
                    "pid": pid,
                }
                risk = 0.35

            elif (
                f.metric == "cpu_percent"
                and severe
                and safety.get("allow_terminate", False)
                and "terminate_process" in allowed_actions
            ):
                action_type = "terminate_process"
                expected = {"process_state": "terminated"}
                rollback = {"action_type": "none"}
                risk = 0.90

            if action_type:
                plans.append(ActionPlan(
                    action_id=str(uuid.uuid4()),
                    created_at=utc_now(),
                    action_type=action_type,
                    target=f"pid:{pid}",
                    reason=(
                        f"{f.metric} abnormal for {name} "
                        f"(value={f.value:.2f}, baseline={f.baseline:.2f}, "
                        f"severity={f.severity:.2f})"
                    ),
                    expected_effect=expected,
                    rollback=rollback,
                    risk=risk,
                    confidence=confidence,
                    finding_ids=[x.finding_id for x in fs],
                ))

        # Host-level disk pressure can safely trigger bounded reclamation if
        # the operator explicitly configured safe roots.
        for f in findings:
            if (
                f.metric == "disk_percent"
                and f.component == "disk"
                and f.severity >= 0.40
                and "reclaim_temp_files" in allowed_actions
                and safety.get("temp_roots")
            ):
                plans.append(ActionPlan(
                    action_id=str(uuid.uuid4()),
                    created_at=utc_now(),
                    action_type="reclaim_temp_files",
                    target="configured_temp_roots",
                    reason=(
                        f"disk utilization abnormal "
                        f"(value={f.value:.2f}%, baseline={f.baseline:.2f}%)"
                    ),
                    expected_effect={"disk_percent": "decrease"},
                    rollback={"action_type": "restore_deleted_files"},
                    risk=0.25,
                    confidence=0.75,
                    finding_ids=[f.finding_id],
                ))

        # Deduplicate by action type + target.
        unique = {}
        for p in plans:
            unique[(p.action_type, p.target)] = p
        return list(unique.values())


# ---------------------------------------------------------------------------
# Intervention adapters
# ---------------------------------------------------------------------------

class LocalActionAdapter:
    """
    Local reversible controls.

    The executor uses psutil rather than arbitrary shell commands. This avoids
    turning the optimizer into an unrestricted command-execution engine.
    """

    def __init__(self, cfg: Dict[str, Any], logger: Logger):
        self.cfg = cfg
        self.logger = logger
        self._deleted_files: Dict[str, List[Tuple[str, str]]] = {}

    def _pid(self, target: str) -> int:
        if not target.startswith("pid:"):
            raise ValueError(f"Invalid process target: {target}")
        return int(target.split(":", 1)[1])

    def snapshot_process(self, pid: int) -> Dict[str, Any]:
        p = psutil.Process(pid)
        with p.oneshot():
            return {
                "pid": pid,
                "name": p.name(),
                "status": p.status(),
                "nice": p.nice(),
                "cpu_percent": p.cpu_percent(None),
                "rss_bytes": p.memory_info().rss,
                "create_time": p.create_time(),
            }

    def lower_priority(self, target: str) -> Dict[str, Any]:
        pid = self._pid(target)
        p = psutil.Process(pid)
        before = p.nice()

        # Cross-platform best effort: Windows accepts integer priority classes
        # but not Unix nice values. psutil abstracts most of this; if the
        # platform rejects it, verification will fail and no lasting state
        # should be assumed.
        if os.name == "nt":
            new_value = psutil.BELOW_NORMAL_PRIORITY_CLASS
        else:
            new_value = min(19, int(before) + 5)

        p.nice(new_value)
        return {"pid": pid, "old_priority": before, "new_priority": p.nice()}

    def restore_priority(self, pid: int, old_priority: Any = None) -> Dict[str, Any]:
        p = psutil.Process(pid)
        current = p.nice()

        if old_priority is not None:
            p.nice(old_priority)
        else:
            # Conservative default: return toward normal priority.
            p.nice(0 if os.name != "nt" else psutil.NORMAL_PRIORITY_CLASS)

        return {
            "pid": pid,
            "old_priority": current,
            "new_priority": p.nice(),
        }

    def isolate_process(self, target: str) -> Dict[str, Any]:
        pid = self._pid(target)
        p = psutil.Process(pid)

        if os.name == "nt":
            # Windows has no portable psutil STOP/CONT equivalent.
            # Refuse rather than silently using a non-equivalent operation.
            raise RuntimeError(
                "Portable process isolation is not implemented on Windows"
            )

        before = self.snapshot_process(pid)
        os.kill(pid, signal.SIGSTOP)
        return {"before": before, "pid": pid, "isolated": True}

    def resume_process(self, pid: int) -> Dict[str, Any]:
        if os.name == "nt":
            raise RuntimeError(
                "Portable process resume is not implemented on Windows"
            )
        os.kill(pid, signal.SIGCONT)
        return {"pid": pid, "isolated": False}

    def terminate_process(self, target: str) -> Dict[str, Any]:
        pid = self._pid(target)
        p = psutil.Process(pid)
        before = self.snapshot_process(pid)
        p.terminate()
        return {"before": before, "pid": pid, "terminated_requested": True}

    def reclaim_temp_files(self) -> Dict[str, Any]:
        safety = self.cfg["safety"]
        roots = safety.get("temp_roots", [])
        age = float(safety.get("min_file_age_seconds", 86_400))
        cap = int(safety.get("max_reclaim_bytes_per_cycle", 100_000_000))

        deleted: List[Tuple[str, str]] = []
        reclaimed = 0
        cutoff = time.time() - age

        for root in roots:
            root_path = pathlib.Path(root).expanduser().resolve()
            if not root_path.exists() or not root_path.is_dir():
                continue

            for path in root_path.rglob("*"):
                if reclaimed >= cap:
                    break
                try:
                    if not path.is_file() or path.is_symlink():
                        continue
                    stat = path.stat()
                    if stat.st_mtime > cutoff:
                        continue

                    size = stat.st_size
                    # Rename before deletion. If the operation fails, no
                    # deletion is recorded. This creates a more auditable
                    # transaction boundary.
                    quarantine = path.with_name(
                        f".asoe_quarantine_{uuid.uuid4().hex}_{path.name}"
                    )
                    path.rename(quarantine)
                    deleted.append((str(quarantine), str(path)))
                    reclaimed += size
                except (OSError, PermissionError):
                    continue

        token = str(uuid.uuid4())
        self._deleted_files[token] = deleted

        # The result contains a rollback token. The files remain in the same
        # filesystem under quarantine until rollback or operator cleanup.
        return {
            "rollback_token": token,
            "reclaimed_bytes": reclaimed,
            "quarantined_files": len(deleted),
        }

    def restore_deleted_files(self, token: str) -> Dict[str, Any]:
        entries = self._deleted_files.get(token, [])
        restored = 0
        for quarantine, original in entries:
            try:
                q = pathlib.Path(quarantine)
                o = pathlib.Path(original)
                if q.exists() and not o.exists():
                    q.rename(o)
                    restored += 1
            except OSError:
                continue
        return {"rollback_token": token, "restored_files": restored}


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

class Verifier:
    def __init__(self, collector: LocalCollector, cfg: Dict[str, Any]):
        self.collector = collector
        self.cfg = cfg

    def _sample(self) -> Dict[str, Any]:
        _, state = self.collector.collect()
        return state

    def _find_process(self, state: Dict[str, Any], pid: int) -> Optional[Dict[str, Any]]:
        for p in state.get("processes", []):
            if int(p["pid"]) == pid:
                return p
        return None

    def verify(self, plan: ActionPlan,
               before_state: Dict[str, Any]) -> Dict[str, Any]:
        timeout = float(self.cfg["thresholds"]["verification_timeout"])
        poll = float(self.cfg["thresholds"]["verification_poll"])
        deadline = time.monotonic() + timeout

        pid = None
        if plan.target.startswith("pid:"):
            pid = int(plan.target.split(":", 1)[1])

        samples = []

        while time.monotonic() < deadline:
            state = self._sample()
            samples.append(state)

            if plan.action_type == "lower_priority" and pid is not None:
                proc = self._find_process(state, pid)
                if proc:
                    before_proc = self._find_process(before_state, pid)
                    if before_proc:
                        priority_ok = True
                        # Priority is not included in collector state, so the
                        # direct process snapshot is used below.
                        try:
                            priority = psutil.Process(pid).nice()
                            if os.name == "nt":
                                priority_ok = priority != psutil.NORMAL_PRIORITY_CLASS
                            else:
                                priority_ok = priority >= before_proc.get("nice", 0)
                        except Exception:
                            priority_ok = False

                        if priority_ok:
                            return {
                                "verified": True,
                                "criterion": "priority_changed",
                                "samples": len(samples),
                            }

            elif plan.action_type == "isolate_process" and pid is not None:
                # SIGSTOP should make the process report stopped.
                proc = self._find_process(state, pid)
                if proc and proc.get("status") == psutil.STATUS_STOPPED:
                    return {
                        "verified": True,
                        "criterion": "process_stopped",
                        "samples": len(samples),
                    }

            elif plan.action_type == "terminate_process" and pid is not None:
                proc = self._find_process(state, pid)
                if proc is None:
                    return {
                        "verified": True,
                        "criterion": "process_absent",
                        "samples": len(samples),
                    }

            elif plan.action_type == "reclaim_temp_files":
                # The action's own result verifies that quarantine occurred.
                return {
                    "verified": True,
                    "criterion": "files_quarantined",
                    "samples": len(samples),
                }

            time.sleep(poll)

        return {
            "verified": False,
            "criterion": "verification_timeout",
            "samples": len(samples),
        }


# ---------------------------------------------------------------------------
# Transactional executor
# ---------------------------------------------------------------------------

class Executor:
    def __init__(self, cfg: Dict[str, Any], logger: Logger,
                 adapter: LocalActionAdapter, verifier: Verifier):
        self.cfg = cfg
        self.logger = logger
        self.adapter = adapter
        self.verifier = verifier

    def execute(self, plan: ActionPlan,
                current_state: Dict[str, Any]) -> ActionResult:
        started = utc_now()
        before: Dict[str, Any] = {}
        after: Dict[str, Any] = {}
        verification: Dict[str, Any] = {}
        rolled_back = False

        # Dry-run is explicit and remains the default.
        if self.cfg["dry_run"] or not self.cfg["auto_execute"]:
            return ActionResult(
                action_id=plan.action_id,
                started_at=started,
                completed_at=utc_now(),
                success=True,
                changed=False,
                message="DRY RUN: intervention planned but not executed",
                before={},
                after={},
                verification={"verified": False, "dry_run": True},
                rolled_back=False,
            )

        try:
            if plan.target.startswith("pid:"):
                pid = int(plan.target.split(":", 1)[1])
                before = self.adapter.snapshot_process(pid)

            if plan.action_type == "lower_priority":
                after = self.adapter.lower_priority(plan.target)

            elif plan.action_type == "isolate_process":
                after = self.adapter.isolate_process(plan.target)

            elif plan.action_type == "terminate_process":
                if not self.cfg["safety"].get("allow_terminate", False):
                    raise PermissionError("Termination is disabled by safety policy")
                after = self.adapter.terminate_process(plan.target)

            elif plan.action_type == "reclaim_temp_files":
                after = self.adapter.reclaim_temp_files()

            else:
                raise ValueError(f"Unsupported action: {plan.action_type}")

            verification = self.verifier.verify(plan, current_state)

            if verification.get("verified"):
                return ActionResult(
                    action_id=plan.action_id,
                    started_at=started,
                    completed_at=utc_now(),
                    success=True,
                    changed=True,
                    message="Intervention executed and verified",
                    before=before,
                    after=after,
                    verification=verification,
                    rolled_back=False,
                )

            # Verification failed: rollback whenever a reversible operation
            # has a known rollback path.
            rollback = plan.rollback.get("action_type")
            if rollback == "restore_priority":
                pid = int(plan.rollback["pid"])
                old_priority = before.get("nice")
                try:
                    self.adapter.restore_priority(pid, old_priority)
                    rolled_back = True
                except Exception as e:
                    self.logger.write(
                        "ERROR", "Priority rollback failed",
                        action_id=plan.action_id, error=str(e)
                    )

            elif rollback == "resume_process":
                pid = int(plan.rollback["pid"])
                try:
                    self.adapter.resume_process(pid)
                    rolled_back = True
                except Exception as e:
                    self.logger.write(
                        "ERROR", "Process resume rollback failed",
                        action_id=plan.action_id, error=str(e)
                    )

            elif rollback == "restore_deleted_files":
                token = after.get("rollback_token")
                if token:
                    restored = self.adapter.restore_deleted_files(token)
                    rolled_back = restored.get("restored_files", 0) > 0

            return ActionResult(
                action_id=plan.action_id,
                started_at=started,
                completed_at=utc_now(),
                success=False,
                changed=True,
                message="Verification failed; rollback attempted",
                before=before,
                after=after,
                verification=verification,
                rolled_back=rolled_back,
            )

        except Exception as exc:
            # If execution itself failed before a known mutation completed,
            # report the failure. The caller does not treat it as successful.
            return ActionResult(
                action_id=plan.action_id,
                started_at=started,
                completed_at=utc_now(),
                success=False,
                changed=bool(after),
                message=f"Intervention failed: {exc}",
                before=before,
                after=after,
                verification=verification,
                rolled_back=rolled_back,
            )


# ---------------------------------------------------------------------------
# Adaptive feedback
# ---------------------------------------------------------------------------

class LearningPolicy:
    """
    Lightweight online policy adaptation.

    It does NOT blindly learn to execute arbitrary actions. It only modifies
    confidence for action classes based on verified success/failure history.
    This is intentionally bounded and explainable.
    """

    def __init__(self):
        self.stats = collections.defaultdict(lambda: {"success": 0, "failure": 0})

    def observe(self, plan: ActionPlan, result: ActionResult) -> None:
        if result.success and result.changed:
            self.stats[plan.action_type]["success"] += 1
        elif result.changed:
            self.stats[plan.action_type]["failure"] += 1

    def confidence_multiplier(self, action_type: str) -> float:
        s = self.stats[action_type]
        total = s["success"] + s["failure"]
        if total == 0:
            return 1.0
        empirical = (s["success"] + 1) / (total + 2)  # Laplace smoothing
        return clamp(0.75 + 0.5 * empirical, 0.75, 1.25)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class AdaptiveOptimizer:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.store = Store(cfg["database"])
        self.logger = Logger(cfg["log_file"])
        self.collector = LocalCollector(cfg["interval_seconds"])
        self.detector = Detector(self.store, cfg)
        self.relationships = RelationshipEngine(self.store)
        self.policy = PolicyEngine(cfg)
        self.adapter = LocalActionAdapter(cfg, self.logger)
        self.verifier = Verifier(self.collector, cfg)
        self.executor = Executor(cfg, self.logger, self.adapter, self.verifier)
        self.learning = LearningPolicy()
        self.cycle = 0

    def cycle_once(self) -> Dict[str, Any]:
        self.cycle += 1

        rows, state = self.collector.collect()
        self.store.add_telemetry(rows)
        self.store.add_state(state)

        findings = self.detector.detect(rows)
        relationships = self.relationships.analyze(state, findings)
        plans = self.policy.choose(findings, relationships)

        executed = []
        for plan in plans:
            plan.confidence *= self.learning.confidence_multiplier(plan.action_type)
            self.store.add_intervention(plan, status="planned")

            # Safety gate: risk/confidence threshold prevents marginal actions.
            if plan.risk > 0.70 or plan.confidence < 0.55:
                self.store.add_intervention(plan, status="blocked_by_safety_gate")
                self.logger.write(
                    "WARNING", "Action blocked by safety gate",
                    action_id=plan.action_id,
                    action_type=plan.action_type,
                    target=plan.target,
                    risk=plan.risk,
                    confidence=plan.confidence,
                )
                continue

            result = self.executor.execute(plan, state)
            self.learning.observe(plan, result)
            status = (
                "verified"
                if result.success and result.changed
                else "dry_run"
                if not result.changed
                else "failed_or_rolled_back"
            )
            self.store.add_intervention(plan, result, status=status)
            executed.append(result)

            self.logger.write(
                "INFO" if result.success else "ERROR",
                "Intervention result",
                action_id=plan.action_id,
                action_type=plan.action_type,
                target=plan.target,
                success=result.success,
                changed=result.changed,
                rolled_back=result.rolled_back,
                result_message=result.message,
            )

        if self.cycle % 100 == 0:
            self.store.purge(self.cfg)

        summary = {
            "cycle": self.cycle,
            "timestamp": utc_now(),
            "telemetry_count": len(rows),
            "finding_count": len(findings),
            "relationship_count": len(relationships),
            "plan_count": len(plans),
            "interventions": [dataclasses.asdict(x) for x in executed],
        }

        self.logger.write(
            "INFO",
            "Cycle complete",
            cycle=self.cycle,
            telemetry=len(rows),
            findings=len(findings),
            relationships=len(relationships),
            plans=len(plans),
        )
        return summary

    def run(self, once: bool = False) -> None:
        self.logger.write(
            "INFO",
            "Adaptive optimizer started",
            dry_run=self.cfg["dry_run"],
            auto_execute=self.cfg["auto_execute"],
            interval=self.cfg["interval_seconds"],
            database=self.cfg["database"],
        )

        if once:
            self.cycle_once()
            return

        while True:
            started = time.monotonic()
            try:
                self.cycle_once()
            except KeyboardInterrupt:
                self.logger.write("INFO", "Shutdown requested")
                break
            except Exception as exc:
                self.logger.write(
                    "ERROR",
                    "Optimizer cycle crashed; continuing",
                    error=str(exc),
                    traceback=traceback.format_exc(),
                )

            elapsed = time.monotonic() - started
            sleep_for = max(0.1, self.cfg["interval_seconds"] - elapsed)
            try:
                time.sleep(sleep_for)
            except KeyboardInterrupt:
                self.logger.write("INFO", "Shutdown requested")
                break


# ---------------------------------------------------------------------------
# Optional extension interfaces for future hardware/cloud adapters
# ---------------------------------------------------------------------------

class InfrastructureAdapter:
    """
    Extension contract.

    Implementations can normalize vendor-specific telemetry and interventions
    into the same model used by the local engine. Examples:
      - Kubernetes
      - AWS/Azure/GCP APIs
      - BMC/IPMI/Redfish
      - network switches
      - storage arrays
      - hypervisors
    """

    name = "abstract"

    def collect(self) -> Tuple[List[Telemetry], Dict[str, Any]]:
        raise NotImplementedError

    def plan_actions(self, findings: Sequence[Finding]) -> List[ActionPlan]:
        return []

    def execute(self, plan: ActionPlan) -> ActionResult:
        raise NotImplementedError


class CloudAdapter(InfrastructureAdapter):
    """
    Safe base class for cloud control-plane implementations.

    No cloud mutation is performed here. A vendor adapter must explicitly
    implement the API operations and its own authentication/least-privilege
    policy.
    """

    name = "cloud"

    def collect(self):
        return [], {"adapter": self.name, "status": "not_configured"}

    def execute(self, plan: ActionPlan) -> ActionResult:
        raise NotImplementedError(
            "Implement a vendor-specific cloud adapter before enabling cloud actions"
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Adaptive Systems Optimization Engine"
    )
    parser.add_argument(
        "--config", default=None,
        help="Path to JSON configuration file"
    )
    parser.add_argument(
        "--interval", type=float, default=None,
        help="Override telemetry/control interval in seconds"
    )
    parser.add_argument(
        "--execute", action="store_true",
        help="Enable policy-approved interventions (default is dry-run)"
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Run exactly one observation/detection/control cycle"
    )
    parser.add_argument(
        "--db", default=None,
        help="Override SQLite database path"
    )
    parser.add_argument(
        "--log", default=None,
        help="Override JSONL log path"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    cfg = load_config(args.config)

    if args.interval is not None:
        cfg["interval_seconds"] = max(0.25, args.interval)
    if args.db:
        cfg["database"] = args.db
    if args.log:
        cfg["log_file"] = args.log

    # --execute changes both gates deliberately; the config file still
    # controls which action classes are permitted.
    if args.execute:
        cfg["dry_run"] = False
        cfg["auto_execute"] = True

    optimizer = AdaptiveOptimizer(cfg)
    optimizer.run(once=args.once)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
