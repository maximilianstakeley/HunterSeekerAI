"""
ADAPTIVE SYSTEMS OPTIMIZER
==========================

Architecture:

V0 - Observation
V1 - Anomaly Detection
V2 - Investigation
V3 - Root-Cause Analysis
V4 - Decision / Optimization
V5 - Intervention / Verification / Rollback

This prototype is intentionally safety constrained.

It can:
    - Observe system resources
    - Detect abnormal behavior
    - Investigate processes
    - Correlate system abnormalities
    - Generate root-cause hypotheses
    - Select interventions
    - Execute reversible low-risk interventions
    - Verify results
    - Roll back failed reversible interventions
    - Maintain an audit trail

It does NOT blindly:
    - delete files
    - kill arbitrary system processes
    - modify operating-system configuration
    - modify cloud infrastructure
    - modify user data

Those capabilities should only be added after the
decision/verification architecture has been validated.
"""

import csv
import json
import os
import platform
import statistics
import subprocess
import sys
import time
import traceback
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Optional, Any

import psutil


# ============================================================
# CONFIGURATION
# ============================================================

SAMPLE_INTERVAL = 3.0

HISTORY_LENGTH = 60

CPU_WARNING = 75.0
CPU_CRITICAL = 90.0

MEMORY_WARNING = 80.0
MEMORY_CRITICAL = 92.0

DISK_IO_WARNING_MB = 100.0
NETWORK_WARNING_MB = 100.0

MIN_SAMPLES_FOR_BASELINE = 10

# ------------------------------------------------------------
# SAFETY
# ------------------------------------------------------------

# Start here.
#
# False = optimizer can analyze and recommend interventions,
#         but will not modify processes.
#
# True = reversible low-risk interventions may execute.
#
ENABLE_AUTOMATIC_ACTIONS = False

# Destructive actions remain disabled in this prototype.
ENABLE_DESTRUCTIVE_ACTIONS = False

# Maximum number of interventions during one execution.
MAX_INTERVENTIONS_PER_SESSION = 5

# Minimum seconds between interventions.
ACTION_COOLDOWN = 30

# Never modify these processes.
PROTECTED_PROCESS_NAMES = {
    "system",
    "systemd",
    "launchd",
    "kernel_task",
    "init",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "smss.exe",
    "winlogon.exe",
    "explorer.exe",
}

# Never automatically intervene in PID 1.
PROTECTED_PIDS = {1}


# ============================================================
# DIRECTORIES
# ============================================================

DATA_DIR = "optimizer_data"

os.makedirs(DATA_DIR, exist_ok=True)

METRICS_FILE = os.path.join(DATA_DIR, "metrics.csv")
ANOMALIES_FILE = os.path.join(DATA_DIR, "anomalies.csv")
ROOT_CAUSES_FILE = os.path.join(DATA_DIR, "root_causes.csv")
ACTIONS_FILE = os.path.join(DATA_DIR, "actions.csv")
VERIFICATION_FILE = os.path.join(DATA_DIR, "verification.csv")
SYSTEM_STATE_FILE = os.path.join(DATA_DIR, "system_state.json")


# ============================================================
# DATA STRUCTURES
# ============================================================

@dataclass
class SystemState:
    timestamp: str

    cpu_percent: float
    memory_percent: float

    memory_available_mb: float
    memory_used_mb: float

    process_count: int

    disk_read_mb_s: float
    disk_write_mb_s: float

    network_sent_mb_s: float
    network_recv_mb_s: float

    load_average: float


@dataclass
class Anomaly:
    timestamp: str
    category: str
    severity: str
    value: float
    threshold: float
    description: str


@dataclass
class RootCause:
    timestamp: str
    cause: str
    confidence: float
    evidence: str
    affected_processes: str


@dataclass
class Action:
    timestamp: str
    action_type: str
    target_pid: Optional[int]
    target_name: Optional[str]

    reason: str
    risk: float

    executed: bool
    result: str


@dataclass
class Verification:
    timestamp: str
    action_type: str

    metric_before: float
    metric_after: float

    improved: bool
    rollback_required: bool

    result: str


# ============================================================
# GLOBAL STATE
# ============================================================

state_history = deque(maxlen=HISTORY_LENGTH)

process_cpu_history = defaultdict(
    lambda: deque(maxlen=HISTORY_LENGTH)
)

process_memory_history = defaultdict(
    lambda: deque(maxlen=HISTORY_LENGTH)
)

last_disk_io = None
last_network_io = None
last_sample_time = None

intervention_history = []

last_intervention_time = 0


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def timestamp():
    return datetime.now().isoformat(timespec="seconds")


def mb(value):
    return value / (1024 * 1024)


def safe_process_name(process):
    try:
        return process.name()
    except Exception:
        return "unknown"


def is_protected_process(process):
    try:
        pid = process.pid
        name = safe_process_name(process).lower()

        if pid in PROTECTED_PIDS:
            return True

        if name in PROTECTED_PROCESS_NAMES:
            return True

        return False

    except Exception:
        return True


# ============================================================
# CSV STORAGE
# ============================================================

def append_csv(filename, data):
    if not data:
        return

    file_exists = os.path.exists(filename)

    with open(
        filename,
        "a",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=data.keys()
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow(data)


# ============================================================
# V0 — OBSERVATION
# ============================================================

def collect_system_state():
    global last_disk_io
    global last_network_io
    global last_sample_time

    now = time.time()

    cpu = psutil.cpu_percent(interval=0.2)

    memory = psutil.virtual_memory()

    process_count = len(
        list(
            psutil.process_iter(
                attrs=["pid"]
            )
        )
    )

    # -------------------------
    # Disk
    # -------------------------

    disk = psutil.disk_io_counters()

    disk_read_rate = 0.0
    disk_write_rate = 0.0

    if last_disk_io is not None and last_sample_time is not None:

        elapsed = max(
            now - last_sample_time,
            0.001
        )

        disk_read_rate = (
            disk.read_bytes -
            last_disk_io.read_bytes
        ) / elapsed

        disk_write_rate = (
            disk.write_bytes -
            last_disk_io.write_bytes
        ) / elapsed

    last_disk_io = disk

    # -------------------------
    # Network
    # -------------------------

    network = psutil.net_io_counters()

    network_sent_rate = 0.0
    network_recv_rate = 0.0

    if last_network_io is not None and last_sample_time is not None:

        elapsed = max(
            now - last_sample_time,
            0.001
        )

        network_sent_rate = (
            network.bytes_sent -
            last_network_io.bytes_sent
        ) / elapsed

        network_recv_rate = (
            network.bytes_recv -
            last_network_io.bytes_recv
        ) / elapsed

    last_network_io = network

    # -------------------------
    # Load
    # -------------------------

    try:
        load_average = os.getloadavg()[0]

    except Exception:
        load_average = 0.0

    state = SystemState(

        timestamp=timestamp(),

        cpu_percent=cpu,

        memory_percent=memory.percent,

        memory_available_mb=mb(
            memory.available
        ),

        memory_used_mb=mb(
            memory.used
        ),

        process_count=process_count,

        disk_read_mb_s=mb(
            disk_read_rate
        ),

        disk_write_mb_s=mb(
            disk_write_rate
        ),

        network_sent_mb_s=mb(
            network_sent_rate
        ),

        network_recv_mb_s=mb(
            network_recv_rate
        ),

        load_average=load_average
    )

    last_sample_time = now

    state_history.append(state)

    append_csv(
        METRICS_FILE,
        asdict(state)
    )

    return state


# ============================================================
# PROCESS OBSERVATION
# ============================================================

def collect_process_information():

    processes = []

    for process in psutil.process_iter(
        [
            "pid",
            "name",
            "status",
            "memory_info",
            "cpu_percent",
            "ppid",
        ]
    ):

        try:

            info = process.info

            pid = info["pid"]

            name = info["name"] or "unknown"

            memory_info = info.get(
                "memory_info"
            )

            rss = (
                memory_info.rss
                if memory_info
                else 0
            )

            cpu = info.get(
                "cpu_percent"
            ) or 0.0

            processes.append(
                {
                    "pid": pid,
                    "name": name,
                    "cpu": cpu,
                    "rss_mb": mb(rss),
                    "status": info.get(
                        "status"
                    ),
                    "ppid": info.get(
                        "ppid"
                    ),
                }
            )

            process_cpu_history[
                pid
            ].append(cpu)

            process_memory_history[
                pid
            ].append(mb(rss))

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):

            continue

    return processes


# ============================================================
# V1 — ANOMALY DETECTION
# ============================================================

def detect_anomalies(state):

    anomalies = []

    # -------------------------
    # CPU
    # -------------------------

    if state.cpu_percent >= CPU_CRITICAL:

        anomalies.append(
            Anomaly(
                timestamp=state.timestamp,
                category="SYSTEM_CPU",
                severity="CRITICAL",
                value=state.cpu_percent,
                threshold=CPU_CRITICAL,
                description=(
                    "System CPU utilization "
                    "is critically high."
                )
            )
        )

    elif state.cpu_percent >= CPU_WARNING:

        anomalies.append(
            Anomaly(
                timestamp=state.timestamp,
                category="SYSTEM_CPU",
                severity="WARNING",
                value=state.cpu_percent,
                threshold=CPU_WARNING,
                description=(
                    "System CPU utilization "
                    "is elevated."
                )
            )
        )

    # -------------------------
    # Memory
    # -------------------------

    if state.memory_percent >= MEMORY_CRITICAL:

        anomalies.append(
            Anomaly(
                timestamp=state.timestamp,
                category="SYSTEM_MEMORY",
                severity="CRITICAL",
                value=state.memory_percent,
                threshold=MEMORY_CRITICAL,
                description=(
                    "System memory pressure "
                    "is critically high."
                )
            )
        )

    elif state.memory_percent >= MEMORY_WARNING:

        anomalies.append(
            Anomaly(
                timestamp=state.timestamp,
                category="SYSTEM_MEMORY",
                severity="WARNING",
                value=state.memory_percent,
                threshold=MEMORY_WARNING,
                description=(
                    "System memory utilization "
                    "is elevated."
                )
            )
        )

    # -------------------------
    # Disk
    # -------------------------

    disk_total = (
        state.disk_read_mb_s +
        state.disk_write_mb_s
    )

    if disk_total >= DISK_IO_WARNING_MB:

        anomalies.append(
            Anomaly(
                timestamp=state.timestamp,
                category="DISK_IO",
                severity="WARNING",
                value=disk_total,
                threshold=DISK_IO_WARNING_MB,
                description=(
                    "Disk I/O rate is elevated."
                )
            )
        )

    # -------------------------
    # Network
    # -------------------------

    network_total = (
        state.network_sent_mb_s +
        state.network_recv_mb_s
    )

    if network_total >= NETWORK_WARNING_MB:

        anomalies.append(
            Anomaly(
                timestamp=state.timestamp,
                category="NETWORK",
                severity="WARNING",
                value=network_total,
                threshold=NETWORK_WARNING_MB,
                description=(
                    "Network traffic rate "
                    "is elevated."
                )
            )
        )

    for anomaly in anomalies:

        append_csv(
            ANOMALIES_FILE,
            asdict(anomaly)
        )

    return anomalies


# ============================================================
# V2 — INVESTIGATION
# ============================================================

def investigate_processes(processes):

    findings = []

    # -------------------------
    # CPU
    # -------------------------

    high_cpu = sorted(
        processes,
        key=lambda x: x["cpu"],
        reverse=True
    )[:10]

    for process in high_cpu:

        if process["cpu"] >= CPU_WARNING:

            findings.append(
                {
                    "type": "HIGH_CPU_PROCESS",
                    "pid": process["pid"],
                    "name": process["name"],
                    "value": process["cpu"]
                }
            )

    # -------------------------
    # Memory
    # -------------------------

    high_memory = sorted(
        processes,
        key=lambda x: x["rss_mb"],
        reverse=True
    )[:10]

    for process in high_memory:

        if process["rss_mb"] > 500:

            findings.append(
                {
                    "type": "HIGH_MEMORY_PROCESS",
                    "pid": process["pid"],
                    "name": process["name"],
                    "value": process["rss_mb"]
                }
            )

    # -------------------------
    # Memory growth
    # -------------------------

    for process in processes:

        pid = process["pid"]

        history = process_memory_history[pid]

        if len(history) < 5:
            continue

        recent = list(history)[-5:]

        growth = (
            recent[-1] -
            recent[0]
        )

        if growth >= 100:

            findings.append(
                {
                    "type": "MEMORY_GROWTH",
                    "pid": pid,
                    "name": process["name"],
                    "value": growth
                }
            )

    return findings


# ============================================================
# V3 — ROOT-CAUSE ENGINE
# ============================================================

def root_cause_analysis(
    state,
    anomalies,
    process_findings
):

    causes = []

    cpu_anomaly = any(
        a.category == "SYSTEM_CPU"
        for a in anomalies
    )

    memory_anomaly = any(
        a.category == "SYSTEM_MEMORY"
        for a in anomalies
    )

    disk_anomaly = any(
        a.category == "DISK_IO"
        for a in anomalies
    )

    network_anomaly = any(
        a.category == "NETWORK"
        for a in anomalies
    )

    # --------------------------------------------------------
    # CPU root cause
    # --------------------------------------------------------

    if cpu_anomaly:

        cpu_processes = [
            x for x in process_findings
            if x["type"] == "HIGH_CPU_PROCESS"
        ]

        if cpu_processes:

            target = cpu_processes[0]

            causes.append(
                RootCause(
                    timestamp=timestamp(),
                    cause="PROCESS_CPU_CONTENTION",
                    confidence=0.85,
                    evidence=(
                        "System CPU utilization is elevated "
                        "and a specific process is consuming "
                        "a large proportion of CPU."
                    ),
                    affected_processes=(
                        f'{target["name"]} '
                        f'(PID {target["pid"]})'
                    )
                )
            )

        else:

            causes.append(
                RootCause(
                    timestamp=timestamp(),
                    cause="SYSTEM_WIDE_CPU_PRESSURE",
                    confidence=0.55,
                    evidence=(
                        "CPU utilization is elevated, "
                        "but no single dominant process "
                        "has been identified."
                    ),
                    affected_processes=""
                )
            )

    # --------------------------------------------------------
    # Memory root cause
    # --------------------------------------------------------

    if memory_anomaly:

        memory_processes = [
            x for x in process_findings
            if x["type"] in (
                "HIGH_MEMORY_PROCESS",
                "MEMORY_GROWTH"
            )
        ]

        if memory_processes:

            target = memory_processes[0]

            causes.append(
                RootCause(
                    timestamp=timestamp(),
                    cause="PROCESS_MEMORY_PRESSURE",
                    confidence=0.80,
                    evidence=(
                        "System memory pressure coincides "
                        "with unusually high or increasing "
                        "memory usage by a process."
                    ),
                    affected_processes=(
                        f'{target["name"]} '
                        f'(PID {target["pid"]})'
                    )
                )
            )

        else:

            causes.append(
                RootCause(
                    timestamp=timestamp(),
                    cause="SYSTEM_WIDE_MEMORY_PRESSURE",
                    confidence=0.50,
                    evidence=(
                        "System memory utilization is high, "
                        "but a dominant process has not "
                        "been established."
                    ),
                    affected_processes=""
                )
            )

    # --------------------------------------------------------
    # CPU + Memory relationship
    # --------------------------------------------------------

    if cpu_anomaly and memory_anomaly:

        causes.append(
            RootCause(
                timestamp=timestamp(),
                cause="COMPUTATION_MEMORY_INTERACTION",
                confidence=0.65,
                evidence=(
                    "CPU and memory pressure are occurring "
                    "simultaneously. This may indicate a "
                    "computation-intensive workload with "
                    "substantial memory allocation."
                ),
                affected_processes=""
            )
        )

    # --------------------------------------------------------
    # Disk + CPU relationship
    # --------------------------------------------------------

    if disk_anomaly and cpu_anomaly:

        causes.append(
            RootCause(
                timestamp=timestamp(),
                cause="I_O_COMPUTATION_INTERACTION",
                confidence=0.60,
                evidence=(
                    "High disk I/O and high CPU occur "
                    "simultaneously. Possible causes include "
                    "data processing, logging, swapping, "
                    "or repeated I/O operations."
                ),
                affected_processes=""
            )
        )

    # --------------------------------------------------------
    # Network + CPU relationship
    # --------------------------------------------------------

    if network_anomaly and cpu_anomaly:

        causes.append(
            RootCause(
                timestamp=timestamp(),
                cause="NETWORK_COMPUTATION_INTERACTION",
                confidence=0.55,
                evidence=(
                    "High network activity coincides with "
                    "high CPU utilization. Possible causes "
                    "include request processing, serialization, "
                    "compression, encryption, or retry activity."
                ),
                affected_processes=""
            )
        )

    for cause in causes:

        append_csv(
            ROOT_CAUSES_FILE,
            asdict(cause)
        )

    return causes


# ============================================================
# V4 — DECISION ENGINE
# ============================================================

def calculate_action_risk(
    process,
    action_type
):

    risk = 0.0

    if process is None:
        return 1.0

    if is_protected_process(
        psutil.Process(process["pid"])
    ):
        return 1.0

    if action_type == "REDUCE_PRIORITY":

        # Reversible.
        risk = 0.15

    elif action_type == "TERMINATE":

        # Destructive.
        risk = 0.95

    elif action_type == "RESTART":

        # Potentially disruptive.
        risk = 0.75

    elif action_type == "DELETE":

        # Destructive.
        risk = 1.0

    return risk


def choose_action(
    state,
    anomalies,
    causes,
    processes
):

    if not causes:
        return None

    # --------------------------------------------------------
    # Find dominant CPU process
    # --------------------------------------------------------

    cpu_processes = sorted(
        processes,
        key=lambda x: x["cpu"],
        reverse=True
    )

    # --------------------------------------------------------
    # CPU optimization
    # --------------------------------------------------------

    if (
        any(
            a.category == "SYSTEM_CPU"
            for a in anomalies
        )
        and cpu_processes
    ):

        target = cpu_processes[0]

        if target["cpu"] >= CPU_CRITICAL:

            risk = calculate_action_risk(
                target,
                "REDUCE_PRIORITY"
            )

            return Action(
                timestamp=timestamp(),
                action_type="REDUCE_PRIORITY",
                target_pid=target["pid"],
                target_name=target["name"],
                reason=(
                    "Reduce CPU scheduling priority "
                    "of the dominant CPU-consuming "
                    "non-protected process."
                ),
                risk=risk,
                executed=False,
                result="PENDING"
            )

    # --------------------------------------------------------
    # Memory pressure
    # --------------------------------------------------------

    memory_processes = sorted(
        processes,
        key=lambda x: x["rss_mb"],
        reverse=True
    )

    if (
        any(
            a.category == "SYSTEM_MEMORY"
            for a in anomalies
        )
        and memory_processes
    ):

        target = memory_processes[0]

        # In this prototype we do NOT kill the process.
        # Instead we record the problem for future
        # process-specific memory remediation.

        return Action(
            timestamp=timestamp(),
            action_type="NO_SAFE_ACTION",
            target_pid=target["pid"],
            target_name=target["name"],
            reason=(
                "Memory pressure detected, but automatic "
                "termination/restart is not justified by "
                "the current evidence."
            ),
            risk=0.0,
            executed=False,
            result="DEFERRED"
        )

    return Action(
        timestamp=timestamp(),
        action_type="NO_ACTION",
        target_pid=None,
        target_name=None,
        reason="No intervention justified.",
        risk=0.0,
        executed=False,
        result="NO_ACTION"
    )


# ============================================================
# V5 — INTERVENTION
# ============================================================

def execute_reduce_priority(action):

    if action.target_pid is None:
        return False, "No PID supplied."

    if not ENABLE_AUTOMATIC_ACTIONS:
        return False, "Automatic actions disabled."

    if action.risk > 0.50:
        return False, "Risk threshold exceeded."

    if len(intervention_history) >= MAX_INTERVENTIONS_PER_SESSION:
        return False, "Intervention session limit reached."

    if (
        time.time() - last_intervention_time
        < ACTION_COOLDOWN
    ):
        return False, "Action cooldown active."

    try:

        process = psutil.Process(
            action.target_pid
        )

        if is_protected_process(process):
            return False, "Protected process."

        # -----------------------------------------------
        # Store original priority.
        # -----------------------------------------------

        if platform.system() == "Windows":

            original_priority = (
                process.nice()
            )

            # Increase nice value = lower priority.
            new_priority = min(
                original_priority + 1,
                psutil.HIGH_PRIORITY_CLASS
            )

            process.nice(
                psutil.BELOW_NORMAL_PRIORITY_CLASS
            )

            action.executed = True

            action.result = (
                "Process priority reduced."
            )

            return True, str(
                original_priority
            )

        else:

            original_priority = process.nice()

            process.nice(
                original_priority + 5
            )

            action.executed = True

            action.result = (
                "Process priority reduced."
            )

            return True, str(
                original_priority
            )

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
        OSError
    ) as e:

        return False, str(e)


# ============================================================
# ROLLBACK
# ============================================================

def rollback_priority(
    pid,
    original_priority
):

    try:

        process = psutil.Process(pid)

        if platform.system() == "Windows":

            process.nice(
                psutil.NORMAL_PRIORITY_CLASS
            )

        else:

            process.nice(
                int(original_priority)
            )

        return True, "Priority restored."

    except Exception as e:

        return False, str(e)


# ============================================================
# VERIFICATION
# ============================================================

def verify_intervention(
    action,
    cpu_before
):

    time.sleep(
        max(
            SAMPLE_INTERVAL,
            2
        )
    )

    state_after = collect_system_state()

    cpu_after = state_after.cpu_percent

    improved = (
        cpu_after < cpu_before
    )

    rollback_required = not improved

    if improved:

        result = (
            "Intervention appears to have "
            "improved system CPU pressure."
        )

    else:

        result = (
            "Intervention did not improve "
            "system CPU pressure."
        )

    verification = Verification(

        timestamp=timestamp(),

        action_type=action.action_type,

        metric_before=cpu_before,

        metric_after=cpu_after,

        improved=improved,

        rollback_required=rollback_required,

        result=result
    )

    append_csv(
        VERIFICATION_FILE,
        asdict(verification)
    )

    return verification


# ============================================================
# SYSTEM GRAPH
# ============================================================

def build_system_relationships(
    state,
    processes,
    anomalies,
    causes
):

    relationships = []

    # System -> CPU
    if state.cpu_percent >= CPU_WARNING:

        relationships.append(
            {
                "source": "SYSTEM",
                "relationship": "HAS_CPU_PRESSURE",
                "target": state.cpu_percent
            }
        )

    # System -> Memory
    if state.memory_percent >= MEMORY_WARNING:

        relationships.append(
            {
                "source": "SYSTEM",
                "relationship": "HAS_MEMORY_PRESSURE",
                "target": state.memory_percent
            }
        )

    # Process -> CPU
    for process in processes:

        if process["cpu"] >= CPU_WARNING:

            relationships.append(
                {
                    "source": (
                        f'PROCESS:{process["name"]}'
                        f':{process["pid"]}'
                    ),
                    "relationship": "CONSUMES_CPU",
                    "target": process["cpu"]
                }
            )

    # Process -> Memory
    for process in processes:

        if process["rss_mb"] >= 500:

            relationships.append(
                {
                    "source": (
                        f'PROCESS:{process["name"]}'
                        f':{process["pid"]}'
                    ),
                    "relationship": "CONSUMES_MEMORY",
                    "target": process["rss_mb"]
                }
            )

    return relationships


# ============================================================
# ADAPTIVE LEARNING
# ============================================================

def record_outcome(
    action,
    verification
):

    outcome = {
        "timestamp": timestamp(),
        "action": action.action_type,
        "target": action.target_name,
        "pid": action.target_pid,
        "improved": verification.improved,
        "rollback_required":
            verification.rollback_required,
    }

    intervention_history.append(
        outcome
    )

    append_csv(
        ACTIONS_FILE,
        outcome
    )


# ============================================================
# DISPLAY
# ============================================================

def display_state(
    state,
    processes,
    anomalies,
    causes,
    action
):

    print("\n" + "=" * 72)

    print(
        "ADAPTIVE SYSTEMS OPTIMIZER"
    )

    print("=" * 72)

    print(
        f"Time:       {state.timestamp}"
    )

    print(
        f"CPU:        {state.cpu_percent:6.2f}%"
    )

    print(
        f"Memory:     {state.memory_percent:6.2f}%"
    )

    print(
        f"Disk Read:  {state.disk_read_mb_s:6.2f} MB/s"
    )

    print(
        f"Disk Write: {state.disk_write_mb_s:6.2f} MB/s"
    )

    print(
        f"Network TX: {state.network_sent_mb_s:6.2f} MB/s"
    )

    print(
        f"Network RX: {state.network_recv_mb_s:6.2f} MB/s"
    )

    print(
        f"Processes:  {state.process_count}"
    )

    # --------------------------------------------------------
    # Top processes
    # --------------------------------------------------------

    print("\nTOP CPU PROCESSES")

    top_cpu = sorted(
        processes,
        key=lambda x: x["cpu"],
        reverse=True
    )[:5]

    for process in top_cpu:

        print(
            f"  PID {process['pid']:>6} "
            f"{process['name'][:25]:25} "
            f"CPU {process['cpu']:6.2f}% "
            f"RAM {process['rss_mb']:8.1f} MB"
        )

    # --------------------------------------------------------
    # Anomalies
    # --------------------------------------------------------

    print("\nANOMALIES")

    if not anomalies:

        print("  None")

    else:

        for anomaly in anomalies:

            print(
                f"  [{anomaly.severity}] "
                f"{anomaly.category}: "
                f"{anomaly.description}"
            )

    # --------------------------------------------------------
    # Root causes
    # --------------------------------------------------------

    print("\nROOT-CAUSE HYPOTHESES")

    if not causes:

        print("  None")

    else:

        for cause in causes:

            print(
                f"  {cause.cause} "
                f"(confidence="
                f"{cause.confidence:.2f})"
            )

            print(
                f"      {cause.evidence}"
            )

    # --------------------------------------------------------
    # Action
    # --------------------------------------------------------

    print("\nDECISION")

    if action:

        print(
            f"  Action: {action.action_type}"
        )

        print(
            f"  Target: {action.target_name}"
        )

        print(
            f"  Risk:   {action.risk:.2f}"
        )

        print(
            f"  Result: {action.result}"
        )

    print("=" * 72)


# ============================================================
# MAIN CONTROL LOOP
# ============================================================

def main():

    print(
        "\nStarting Adaptive Systems Optimizer..."
    )

    print(
        f"Automatic actions: "
        f"{ENABLE_AUTOMATIC_ACTIONS}"
    )

    print(
        f"Destructive actions: "
        f"{ENABLE_DESTRUCTIVE_ACTIONS}"
    )

    print(
        "\nPress CTRL+C to stop.\n"
    )

    # --------------------------------------------------------
    # Prime process CPU measurements.
    # --------------------------------------------------------

    for process in psutil.process_iter():

        try:
            process.cpu_percent(
                interval=None
            )

        except Exception:
            pass

    time.sleep(1)

    while True:

        try:

            # =================================================
            # V0
            # =================================================

            state = collect_system_state()

            # =================================================
            # PROCESS OBSERVATION
            # =================================================

            processes = (
                collect_process_information()
            )

            # =================================================
            # V1
            # =================================================

            anomalies = detect_anomalies(
                state
            )

            # =================================================
            # V2
            # =================================================

            process_findings = (
                investigate_processes(
                    processes
                )
            )

            # =================================================
            # V3
            # =================================================

            causes = root_cause_analysis(
                state,
                anomalies,
                process_findings
            )

            relationships = (
                build_system_relationships(
                    state,
                    processes,
                    anomalies,
                    causes
                )
            )

            # =================================================
            # V4
            # =================================================

            action = choose_action(
                state,
                anomalies,
                causes,
                processes
            )

            # =================================================
            # DISPLAY
            # =================================================

            display_state(
                state,
                processes,
                anomalies,
                causes,
                action
            )

            # =================================================
            # V5
            # =================================================

            if (
                action
                and action.action_type
                == "REDUCE_PRIORITY"
            ):

                cpu_before = (
                    state.cpu_percent
                )

                success, metadata = (
                    execute_reduce_priority(
                        action
                    )
                )

                if success:

                    last_intervention_time = (
                        time.time()
                    )

                    verification = (
                        verify_intervention(
                            action,
                            cpu_before
                        )
                    )

                    record_outcome(
                        action,
                        verification
                    )

                    # ------------------------------------------------
                    # Rollback
                    # ------------------------------------------------

                    if (
                        verification.rollback_required
                    ):

                        print(
                            "\nROLLBACK TRIGGERED"
                        )

                        try:

                            original_priority = (
                                float(metadata)
                            )

                            rollback_priority(
                                action.target_pid,
                                original_priority
                            )

                        except Exception as e:

                            print(
                                f"Rollback error: {e}"
                            )

            time.sleep(
                SAMPLE_INTERVAL
            )

        except KeyboardInterrupt:

            print(
                "\nOptimizer stopped."
            )

            break

        except Exception as e:

            print(
                "\nCONTROL LOOP ERROR:"
            )

            print(e)

            traceback.print_exc()

            time.sleep(
                SAMPLE_INTERVAL
            )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()