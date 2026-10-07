#!/usr/bin/env python3

"""
V10 — EXECUTION / VERIFICATION / LEARNING LOOP

Architecture:

    Previous-layer decision
            ↓
        Validate
            ↓
        Execute
            ↓
        Verify outcome
            ↓
    Calculate improvement
            ↓
    Store experience
            ↓
    Update learned statistics
            ↓
      Select next action
            ↓
          Repeat

IMPORTANT:
The current executor uses a SAFE SIMULATED SYSTEM.
It does not terminate processes, modify OS settings,
delete files, or change cloud resources.

Run:

    python V10-ExecutionLearning.py --demo

    python V10-ExecutionLearning.py --cycles 10

    python V10-ExecutionLearning.py --stats

    python V10-ExecutionLearning.py --continuous
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sqlite3
import time
import uuid

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


DB_PATH = Path("asoe.db")
DEFAULT_INTERVAL = 1.0


# ============================================================
# TIME
# ============================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ============================================================
# SYSTEM STATE
# ============================================================

@dataclass
class SystemState:
    """
    Simplified representation of the system state.

    Lower workload/resource_pressure is better.
    Higher stability is better.
    """

    workload: float
    resource_pressure: float
    stability: float

    def as_dict(self) -> Dict[str, float]:
        return asdict(self)


# ============================================================
# DECISION
# ============================================================

@dataclass
class Decision:
    """
    Represents the decision handed to the execution layer.
    """

    action_type: str
    target: str
    parameters: Dict[str, Any]

    expected_improvement: float
    risk: float
    confidence: float

    allowed: bool
    requires_human: bool = False

    reason: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ============================================================
# EXECUTION RESULT
# ============================================================

@dataclass
class ExecutionResult:
    success: bool
    changed: bool
    rolled_back: bool

    message: str

    state_after: Dict[str, Any]


# ============================================================
# EXPERIENCE DATABASE
# ============================================================

# ============================================================
# EXPERIENCE DATABASE
# ============================================================

class ExperienceStore:
    """
    Persistent memory for the adaptive system.

    Stores:

        state before
        decision
        action
        state after
        success
        improvement
        reward

    This becomes the foundation for the future ML dataset.
    """

    def __init__(self, path: Path = DB_PATH) -> None:
        self.path = path
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:

        with self._connect() as conn:

            # ------------------------------------------------
            # V10 EXPERIENCE TABLE
            # ------------------------------------------------

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_experiences (
                    experience_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    cycle INTEGER NOT NULL,

                    state_before TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    state_after TEXT NOT NULL,

                    success INTEGER NOT NULL,
                    changed INTEGER NOT NULL,
                    rolled_back INTEGER NOT NULL,

                    improvement REAL NOT NULL,
                    reward REAL NOT NULL,

                    message TEXT NOT NULL
                )
                """
            )

            # ------------------------------------------------
            # V10 ACTION STATISTICS TABLE
            # ------------------------------------------------

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS action_statistics (
                    action_type TEXT PRIMARY KEY,

                    attempts INTEGER NOT NULL DEFAULT 0,
                    successes INTEGER NOT NULL DEFAULT 0,

                    total_improvement REAL NOT NULL DEFAULT 0,
                    total_reward REAL NOT NULL DEFAULT 0,

                    learned_confidence REAL NOT NULL DEFAULT 0.5
                )
                """
            )

            conn.commit()

    # --------------------------------------------------------
    # SAVE EXPERIENCE
    # --------------------------------------------------------

    def save_experience(
        self,
        cycle: int,
        state_before: SystemState,
        decision: Decision,
        state_after: SystemState,
        result: ExecutionResult,
        improvement: float,
        reward: float,
    ) -> str:

        experience_id = (
            f"experience_{uuid.uuid4().hex[:12]}"
        )

        with self._connect() as conn:

            conn.execute(
                """
                INSERT INTO execution_experiences (
                    experience_id,
                    timestamp,
                    cycle,

                    state_before,
                    decision,
                    state_after,

                    success,
                    changed,
                    rolled_back,

                    improvement,
                    reward,

                    message
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    experience_id,
                    utc_now(),
                    cycle,

                    json.dumps(
                        state_before.as_dict()
                    ),

                    json.dumps(
                        decision.as_dict()
                    ),

                    json.dumps(
                        state_after.as_dict()
                    ),

                    int(result.success),
                    int(result.changed),
                    int(result.rolled_back),

                    improvement,
                    reward,

                    result.message,
                ),
            )

            conn.commit()

        return experience_id

    # --------------------------------------------------------
    # UPDATE LEARNING STATISTICS
    # --------------------------------------------------------

    def update_action_statistics(
        self,
        action_type: str,
        success: bool,
        improvement: float,
        reward: float,
    ) -> None:

        with self._connect() as conn:

            row = conn.execute(
                """
                SELECT
                    attempts,
                    successes,
                    total_improvement,
                    total_reward,
                    learned_confidence
                FROM action_statistics
                WHERE action_type = ?
                """,
                (action_type,),
            ).fetchone()

            if row is None:

                attempts = 0
                successes = 0
                total_improvement = 0.0
                total_reward = 0.0
                learned_confidence = 0.5

            else:

                attempts = int(
                    row["attempts"]
                )

                successes = int(
                    row["successes"]
                )

                total_improvement = float(
                    row["total_improvement"]
                )

                total_reward = float(
                    row["total_reward"]
                )

                learned_confidence = float(
                    row["learned_confidence"]
                )

            # --------------------------------------------
            # Update accumulated statistics
            # --------------------------------------------

            attempts += 1
            successes += int(success)

            total_improvement += improvement
            total_reward += reward

            # --------------------------------------------
            # Online confidence update
            # --------------------------------------------

            observed_success = (
                1.0 if success else 0.0
            )

            learning_rate = (
                1.0 / min(attempts, 20)
            )

            learned_confidence += (
                learning_rate
                * (
                    observed_success
                    - learned_confidence
                )
            )

            learned_confidence = max(
                0.0,
                min(
                    1.0,
                    learned_confidence
                ),
            )

            # --------------------------------------------
            # Write updated statistics
            # --------------------------------------------

            conn.execute(
                """
                INSERT INTO action_statistics (
                    action_type,
                    attempts,
                    successes,
                    total_improvement,
                    total_reward,
                    learned_confidence
                )
                VALUES (?, ?, ?, ?, ?, ?)

                ON CONFLICT(action_type)
                DO UPDATE SET

                    attempts =
                        excluded.attempts,

                    successes =
                        excluded.successes,

                    total_improvement =
                        excluded.total_improvement,

                    total_reward =
                        excluded.total_reward,

                    learned_confidence =
                        excluded.learned_confidence
                """,
                (
                    action_type,
                    attempts,
                    successes,
                    total_improvement,
                    total_reward,
                    learned_confidence,
                ),
            )

            conn.commit()

    # --------------------------------------------------------
    # EXPERIENCE COUNT
    # --------------------------------------------------------

    def count_experiences(self) -> int:

        with self._connect() as conn:

            row = conn.execute(
                """
                SELECT COUNT(*) AS count
                FROM execution_experiences
                """
            ).fetchone()

            return int(row["count"])

    # --------------------------------------------------------
    # STATISTICS
    # --------------------------------------------------------

    def statistics(self) -> list[dict[str, Any]]:

        with self._connect() as conn:

            rows = conn.execute(
                """
                SELECT
                    action_type,
                    attempts,
                    successes,
                    total_improvement,
                    total_reward,
                    learned_confidence
                FROM action_statistics
                ORDER BY attempts DESC
                """
            ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

# ============================================================
# SIMULATED SYSTEM
# ============================================================

class DemoSystem:
    """
    Safe simulated system.

    This is intentionally isolated from the real computer.
    """

    def __init__(self) -> None:

        self.state = SystemState(
            workload=0.70,
            resource_pressure=0.78,
            stability=0.90,
        )

    def snapshot(self) -> SystemState:

        return SystemState(
            workload=self.state.workload,
            resource_pressure=self.state.resource_pressure,
            stability=self.state.stability,
        )

    def apply(self, action_type: str) -> None:

        # ---------------------------------------------
        # Optimize resource usage
        # ---------------------------------------------

        if action_type == "optimize_resource":

            self.state.resource_pressure *= 0.72
            self.state.workload *= 0.92

            self.state.stability = min(
                1.0,
                self.state.stability + 0.025,
            )

        # ---------------------------------------------
        # Rebalance workload
        # ---------------------------------------------

        elif action_type == "rebalance_workload":

            self.state.resource_pressure *= 0.82
            self.state.workload *= 0.88

            self.state.stability = min(
                1.0,
                self.state.stability + 0.015,
            )

        # ---------------------------------------------
        # Reduce load
        # ---------------------------------------------

        elif action_type == "reduce_load":

            self.state.resource_pressure *= 0.86
            self.state.workload *= 0.84

            self.state.stability = min(
                1.0,
                self.state.stability + 0.01,
            )

        # ---------------------------------------------
        # Observation only
        # ---------------------------------------------

        elif action_type == "observe_only":

            pass

        else:

            raise ValueError(
                f"Unsupported demo action: {action_type}"
            )

        # ---------------------------------------------
        # Simulated environmental drift
        # ---------------------------------------------

        self.state.resource_pressure = min(
            1.0,
            max(
                0.0,
                self.state.resource_pressure
                + random.uniform(-0.025, 0.035),
            ),
        )

        self.state.workload = min(
            1.0,
            max(
                0.0,
                self.state.workload
                + random.uniform(-0.02, 0.03),
            ),
        )


# ============================================================
# LEARNING POLICY
# ============================================================

class LearningPolicy:
    """
    Lightweight online learning policy.

    This is deliberately NOT the final ML model.

    It learns action success statistics from previous
    experiences and incorporates them into future decisions.
    """

    ACTIONS = (
        "optimize_resource",
        "rebalance_workload",
        "reduce_load",
        "observe_only",
    )

    def __init__(
        self,
        store: ExperienceStore,
    ) -> None:

        self.store = store

    def learned_confidence(
        self,
        action_type: str,
    ) -> float:

        for row in self.store.statistics():

            if row["action_type"] == action_type:

                return float(
                    row["learned_confidence"]
                )

        return 0.5

    def choose_action(
        self,
        state: SystemState,
    ) -> Decision:

        candidates = []

        for action in self.ACTIONS:

            learned = (
                self.learned_confidence(action)
            )

            if action == "optimize_resource":

                expected = min(
                    1.0,
                    state.resource_pressure * 0.90,
                )

                risk = 0.15

            elif action == "rebalance_workload":

                expected = min(
                    1.0,
                    state.workload * 0.75,
                )

                risk = 0.10

            elif action == "reduce_load":

                expected = min(
                    1.0,
                    state.resource_pressure * 0.55,
                )

                risk = 0.08

            else:

                expected = 0.05
                risk = 0.01

            # -----------------------------------------
            # Action score
            # -----------------------------------------

            score = (
                0.50 * expected
                + 0.40 * learned
                - 0.10 * risk
            )

            candidates.append(
                (
                    score,
                    action,
                    expected,
                    risk,
                    learned,
                )
            )

        candidates.sort(
            reverse=True
        )

        (
            score,
            action,
            expected,
            risk,
            confidence,
        ) = candidates[0]

        return Decision(
            action_type=action,
            target="demo_system",
            parameters={},

            expected_improvement=expected,
            risk=risk,
            confidence=confidence,

            allowed=True,
            requires_human=False,

            reason=(
                "Selected by learned action policy; "
                f"score={score:.4f}"
            ),
        )


# ============================================================
# EXECUTION LAYER
# ============================================================

class Executor:
    """
    Executes actions approved by the decision layer.

    ONLY safe demo actions are currently registered.
    """

    SAFE_ACTIONS = {
        "optimize_resource",
        "rebalance_workload",
        "reduce_load",
        "observe_only",
    }

    # --------------------------------------------------------
    # VALIDATE
    # --------------------------------------------------------

    def validate(
        self,
        decision: Decision,
    ) -> tuple[bool, str]:

        if not decision.allowed:

            return (
                False,
                "Decision was not authorized.",
            )

        if decision.requires_human:

            return (
                False,
                "Decision requires human approval.",
            )

        if decision.action_type not in self.SAFE_ACTIONS:

            return (
                False,
                "Action is not registered "
                "as a safe executable action.",
            )

        if not 0.0 <= decision.risk <= 1.0:

            return (
                False,
                "Risk must be between 0 and 1.",
            )

        if not 0.0 <= decision.confidence <= 1.0:

            return (
                False,
                "Confidence must be between 0 and 1.",
            )

        return True, "Validated."

    # --------------------------------------------------------
    # EXECUTE
    # --------------------------------------------------------

    def execute(
        self,
        decision: Decision,
        system: DemoSystem,
    ) -> ExecutionResult:

        valid, message = self.validate(
            decision
        )

        if not valid:

            return ExecutionResult(
                success=False,
                changed=False,
                rolled_back=False,

                message=message,

                state_after=(
                    system
                    .snapshot()
                    .as_dict()
                ),
            )

        before = system.snapshot()

        try:

            system.apply(
                decision.action_type
            )

        except Exception as exc:

            return ExecutionResult(
                success=False,
                changed=False,
                rolled_back=False,

                message=(
                    f"Execution failed: {exc}"
                ),

                state_after=(
                    system
                    .snapshot()
                    .as_dict()
                ),
            )

        after = system.snapshot()

        changed = (
            not math.isclose(
                before.resource_pressure,
                after.resource_pressure,
            )
            or not math.isclose(
                before.workload,
                after.workload,
            )
            or not math.isclose(
                before.stability,
                after.stability,
            )
        )

        return ExecutionResult(
            success=True,
            changed=changed,
            rolled_back=False,

            message=(
                "Action executed and "
                "system state changed."
            ),

            state_after=after.as_dict(),
        )


# ============================================================
# VERIFICATION
# ============================================================

class Verification:
    """
    Determines whether an intervention improved
    the system state.
    """

    @staticmethod
    def improvement(
        before: SystemState,
        after: SystemState,
    ) -> float:

        # Lower workload and resource pressure
        # are better.
        #
        # Higher stability is better.

        before_score = (
            0.45 * before.resource_pressure
            + 0.35 * before.workload
            + 0.20 * (1.0 - before.stability)
        )

        after_score = (
            0.45 * after.resource_pressure
            + 0.35 * after.workload
            + 0.20 * (1.0 - after.stability)
        )

        raw = (
            before_score - after_score
        ) / max(
            before_score,
            1e-9,
        )

        return max(
            -1.0,
            min(1.0, raw),
        )

    @staticmethod
    def reward(
        improvement: float,
        result: ExecutionResult,
        decision: Decision,
    ) -> float:

        reward = improvement

        if result.success:

            reward += 0.10

        if result.changed:

            reward += 0.05

        # Penalize risk.

        reward -= (
            decision.risk * 0.10
        )

        if result.rolled_back:

            reward -= 0.50

        return max(
            -1.0,
            min(1.0, reward),
        )


# ============================================================
# ADAPTIVE EXECUTION ENGINE
# ============================================================

class AdaptiveExecutionEngine:

    def __init__(
        self,
        database: Path = DB_PATH,
        interval: float = DEFAULT_INTERVAL,
    ) -> None:

        self.store = ExperienceStore(
            database
        )

        self.system = DemoSystem()

        self.policy = LearningPolicy(
            self.store
        )

        self.executor = Executor()

        self.verifier = Verification()

        self.interval = interval

        self.cycle = 0

    # --------------------------------------------------------
    # ONE COMPLETE CYCLE
    # --------------------------------------------------------

    def run_cycle(self) -> Dict[str, Any]:

        self.cycle += 1

        # ---------------------------------------------
        # 1. Observe
        # ---------------------------------------------

        before = (
            self.system.snapshot()
        )

        # ---------------------------------------------
        # 2. Decide
        # ---------------------------------------------

        decision = (
            self.policy.choose_action(
                before
            )
        )

        # ---------------------------------------------
        # 3. Execute
        # ---------------------------------------------

        result = (
            self.executor.execute(
                decision,
                self.system,
            )
        )

        # ---------------------------------------------
        # 4. Observe result
        # ---------------------------------------------

        after = (
            self.system.snapshot()
        )

        # ---------------------------------------------
        # 5. Verify
        # ---------------------------------------------

        improvement = (
            self.verifier.improvement(
                before,
                after,
            )
        )

        # ---------------------------------------------
        # 6. Calculate reward
        # ---------------------------------------------

        reward = (
            self.verifier.reward(
                improvement,
                result,
                decision,
            )
        )

        # ---------------------------------------------
        # 7. Save experience
        # ---------------------------------------------

        experience_id = (
            self.store.save_experience(
                cycle=self.cycle,
                state_before=before,
                decision=decision,
                state_after=after,
                result=result,
                improvement=improvement,
                reward=reward,
            )
        )

        # ---------------------------------------------
        # 8. Update learned statistics
        # ---------------------------------------------

        self.store.update_action_statistics(
            action_type=(
                decision.action_type
            ),

            success=result.success,

            improvement=improvement,

            reward=reward,
        )

        # ---------------------------------------------
        # 9. Return complete result
        # ---------------------------------------------

        return {

            "cycle": self.cycle,

            "experience_id": experience_id,

            "decision": (
                decision.as_dict()
            ),

            "result": (
                asdict(result)
            ),

            "state_before": (
                before.as_dict()
            ),

            "state_after": (
                after.as_dict()
            ),

            "improvement": round(
                improvement,
                6,
            ),

            "reward": round(
                reward,
                6,
            ),

            "learned_confidence": round(
                self.policy.learned_confidence(
                    decision.action_type
                ),
                6,
            ),
        }

    # --------------------------------------------------------
    # RUN
    # --------------------------------------------------------

    def run(
        self,
        cycles: int,
        continuous: bool = False,
    ) -> None:

        print("=" * 70)
        print(
            "V10 EXECUTION / VERIFICATION / LEARNING ENGINE"
        )
        print("=" * 70)

        print(
            f"Database: "
            f"{self.store.path.resolve()}"
        )

        print(
            f"Existing experiences: "
            f"{self.store.count_experiences()}"
        )

        print()

        while (
            continuous
            or self.cycle < cycles
        ):

            result = (
                self.run_cycle()
            )

            print(
                f"[CYCLE {result['cycle']}]"
            )

            print(
                "  Action:       "
                f"{result['decision']['action_type']}"
            )

            print(
                "  Confidence:   "
                f"{result['decision']['confidence']:.3f}"
            )

            print(
                "  Improvement:  "
                f"{result['improvement']:.3f}"
            )

            print(
                "  Reward:       "
                f"{result['reward']:.3f}"
            )

            print(
                "  Success:      "
                f"{result['result']['success']}"
            )

            print(
                "  Experience:   "
                f"{result['experience_id']}"
            )

            print(
                "  Learned conf: "
                f"{result['learned_confidence']:.3f}"
            )

            print()

            if (
                not continuous
                and self.cycle >= cycles
            ):

                break

            time.sleep(
                self.interval
            )

        print("=" * 70)
        print(
            "FEEDBACK CYCLE COMPLETE"
        )
        print("=" * 70)

    # --------------------------------------------------------
    # STATISTICS
    # --------------------------------------------------------

    def print_stats(self) -> None:

        print("=" * 70)
        print(
            "LEARNED ACTION STATISTICS"
        )
        print("=" * 70)

        stats = (
            self.store.statistics()
        )

        if not stats:

            print(
                "No experiences recorded yet."
            )

            return

        for row in stats:

            attempts = row[
                "attempts"
            ]

            successes = row[
                "successes"
            ]

            success_rate = (
                successes / attempts
                if attempts
                else 0.0
            )

            avg_improvement = (
                row[
                    "total_improvement"
                ] / attempts
                if attempts
                else 0.0
            )

            print(
                f"\nAction: "
                f"{row['action_type']}"
            )

            print(
                f"  attempts:           "
                f"{attempts}"
            )

            print(
                f"  successes:          "
                f"{successes}"
            )

            print(
                f"  success rate:       "
                f"{success_rate:.3f}"
            )

            print(
                f"  avg improvement:    "
                f"{avg_improvement:.3f}"
            )

            print(
                f"  learned confidence: "
                f"{row['learned_confidence']:.3f}"
            )


# ============================================================
# COMMAND LINE
# ============================================================

def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "V10 execution, verification, "
            "and online learning layer."
        )
    )

    parser.add_argument(
        "--demo",
        action="store_true",
        help=(
            "Run one complete safe "
            "feedback cycle."
        ),
    )

    parser.add_argument(
        "--cycles",
        type=int,
        default=None,
        help=(
            "Run N safe feedback cycles."
        ),
    )

    parser.add_argument(
        "--continuous",
        action="store_true",
        help=(
            "Continuously repeat the "
            "safe demo cycle."
        ),
    )

    parser.add_argument(
        "--stats",
        action="store_true",
        help=(
            "Display learned statistics "
            "from asoe.db."
        ),
    )

    parser.add_argument(
        "--db",
        default=str(DB_PATH),
        help=(
            "SQLite database path."
        ),
    )

    args = parser.parse_args()

    engine = AdaptiveExecutionEngine(
        database=Path(args.db)
    )

    if args.stats:

        engine.print_stats()
        return

    if args.demo:

        engine.run(
            cycles=1
        )

        return

    if args.cycles is not None:

        if args.cycles < 1:

            parser.error(
                "--cycles must be at least 1"
            )

        engine.run(
            cycles=args.cycles
        )

        return

    if args.continuous:

        engine.run(
            cycles=1,
            continuous=True
        )

        return

    parser.print_help()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()