"""
Adaptive Systems Optimization Engine
V6 - V9 Extension

V6: Learning / feedback
V7: Controlled autonomy
V8: ML-ready adaptive decision system
V9: Distributed / API-ready architecture

Designed to sit above an existing V0-V5 engine.

Core loop:

Observe
    ↓
Detect
    ↓
Diagnose
    ↓
Decide
    ↓
Intervene
    ↓
Verify
    ↓
LEARN
    ↓
ADAPT
    ↓
REPEAT

Python 3.10+
Standard library only.

Optional:
    scikit-learn
can later be installed to activate the ML adapter.
"""



from __future__ import annotations

import argparse
import json
import math
import os
import sqlite3
import statistics
import time
import uuid

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Optional


# ============================================================
# GLOBAL UTILITIES
# ============================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def safe_json(data: Any) -> str:
    return json.dumps(data, default=str, separators=(",", ":"))


# ============================================================
# V6 — EXPERIENCE / LEARNING MODEL
# ============================================================

@dataclass
class Experience:
    experience_id: str
    timestamp: str

    problem_type: str
    target: str

    action_type: str
    action_parameters: dict

    pre_state: dict
    post_state: dict

    success: bool
    changed: bool
    rolled_back: bool

    improvement: float
    cost: float
    risk: float

    duration_seconds: float

    confidence_before: float
    confidence_after: float

    notes: str = ""


# ============================================================
# V6 — PERSISTENT KNOWLEDGE STORE
# ============================================================

class KnowledgeStore:

    def __init__(self, database: str = "asoe.db"):
        self.database = database
        self.connection = sqlite3.connect(
            database,
            check_same_thread=False
        )

        self.connection.row_factory = sqlite3.Row

        self.initialize()

    def initialize(self):

        cursor = self.connection.cursor()

        # ----------------------------------------------------
        # Experiences
        # ----------------------------------------------------

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS experiences (
                experience_id TEXT PRIMARY KEY,
                timestamp TEXT,

                problem_type TEXT,
                target TEXT,

                action_type TEXT,
                action_parameters TEXT,

                pre_state TEXT,
                post_state TEXT,

                success INTEGER,
                changed INTEGER,
                rolled_back INTEGER,

                improvement REAL,
                cost REAL,
                risk REAL,

                duration_seconds REAL,

                confidence_before REAL,
                confidence_after REAL,

                notes TEXT
            )
        """)

        # ----------------------------------------------------
        # Knowledge about interventions
        # ----------------------------------------------------

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS intervention_knowledge (
                problem_type TEXT,
                action_type TEXT,
                target TEXT,

                attempts INTEGER DEFAULT 0,
                successes INTEGER DEFAULT 0,
                failures INTEGER DEFAULT 0,
                rollbacks INTEGER DEFAULT 0,

                average_improvement REAL DEFAULT 0,
                average_cost REAL DEFAULT 0,
                average_risk REAL DEFAULT 0,

                confidence REAL DEFAULT 0.5,

                last_updated TEXT,

                PRIMARY KEY (
                    problem_type,
                    action_type,
                    target
                )
            )
        """)

        # ----------------------------------------------------
        # Feature observations for future ML
        # ----------------------------------------------------

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS feature_observations (
                feature_id TEXT PRIMARY KEY,
                timestamp TEXT,
                problem_type TEXT,
                target TEXT,
                features TEXT,
                outcome REAL
            )
        """)

        # ----------------------------------------------------
        # Nodes for V9
        # ----------------------------------------------------

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS nodes (
                node_id TEXT PRIMARY KEY,
                hostname TEXT,
                node_type TEXT,
                status TEXT,
                last_seen TEXT,
                metadata TEXT
            )
        """)

        self.connection.commit()

    # --------------------------------------------------------
    # EXPERIENCE
    # --------------------------------------------------------

    def save_experience(self, experience: Experience):

        cursor = self.connection.cursor()

        cursor.execute("""
            INSERT INTO experiences VALUES (
                ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
            )
        """, (
            experience.experience_id,
            experience.timestamp,

            experience.problem_type,
            experience.target,

            experience.action_type,
            safe_json(experience.action_parameters),

            safe_json(experience.pre_state),
            safe_json(experience.post_state),

            int(experience.success),
            int(experience.changed),
            int(experience.rolled_back),

            experience.improvement,
            experience.cost,
            experience.risk,

            experience.duration_seconds,

            experience.confidence_before,
            experience.confidence_after,

            experience.notes
        ))

        self.connection.commit()

    # --------------------------------------------------------
    # UPDATE KNOWLEDGE
    # --------------------------------------------------------

    def update_knowledge(
        self,
        experience: Experience
    ):

        cursor = self.connection.cursor()

        cursor.execute("""
            SELECT *
            FROM intervention_knowledge
            WHERE problem_type = ?
              AND action_type = ?
              AND target = ?
        """, (
            experience.problem_type,
            experience.action_type,
            experience.target
        ))

        row = cursor.fetchone()

        if row is None:

            attempts = 1
            successes = int(experience.success)
            failures = int(not experience.success)
            rollbacks = int(experience.rolled_back)

            confidence = self.calculate_confidence(
                attempts,
                successes,
                rollbacks
            )

            cursor.execute("""
                INSERT INTO intervention_knowledge
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                experience.problem_type,
                experience.action_type,
                experience.target,

                attempts,
                successes,
                failures,
                rollbacks,

                experience.improvement,
                experience.cost,
                experience.risk,

                confidence,
                utc_now()
            ))

        else:

            attempts = row["attempts"] + 1
            successes = row["successes"] + int(experience.success)
            failures = row["failures"] + int(not experience.success)
            rollbacks = row["rollbacks"] + int(
                experience.rolled_back
            )

            average_improvement = (
                row["average_improvement"] *
                row["attempts"] +
                experience.improvement
            ) / attempts

            average_cost = (
                row["average_cost"] *
                row["attempts"] +
                experience.cost
            ) / attempts

            average_risk = (
                row["average_risk"] *
                row["attempts"] +
                experience.risk
            ) / attempts

            confidence = self.calculate_confidence(
                attempts,
                successes,
                rollbacks
            )

            cursor.execute("""
                UPDATE intervention_knowledge
                SET
                    attempts = ?,
                    successes = ?,
                    failures = ?,
                    rollbacks = ?,

                    average_improvement = ?,
                    average_cost = ?,
                    average_risk = ?,

                    confidence = ?,
                    last_updated = ?

                WHERE problem_type = ?
                  AND action_type = ?
                  AND target = ?
            """, (
                attempts,
                successes,
                failures,
                rollbacks,

                average_improvement,
                average_cost,
                average_risk,

                confidence,
                utc_now(),

                experience.problem_type,
                experience.action_type,
                experience.target
            ))

        self.connection.commit()

    @staticmethod
    def calculate_confidence(
        attempts: int,
        successes: int,
        rollbacks: int
    ) -> float:

        if attempts == 0:
            return 0.5

        success_rate = successes / attempts

        rollback_penalty = min(
            rollbacks / attempts,
            1.0
        )

        # Bayesian-like smoothing
        smoothed_success = (
            successes + 1
        ) / (
            attempts + 2
        )

        confidence = (
            0.70 * smoothed_success +
            0.30 * success_rate
        )

        confidence *= (
            1.0 - 0.5 * rollback_penalty
        )

        return max(
            0.0,
            min(1.0, confidence)
        )

    # --------------------------------------------------------
    # KNOWLEDGE QUERY
    # --------------------------------------------------------

    def get_candidates(
        self,
        problem_type: str,
        target: str
    ):

        cursor = self.connection.cursor()

        cursor.execute("""
            SELECT *
            FROM intervention_knowledge
            WHERE problem_type = ?
              AND (
                    target = ?
                    OR target = '*'
                  )
            ORDER BY confidence DESC
        """, (
            problem_type,
            target
        ))

        return cursor.fetchall()

    # --------------------------------------------------------
    # ML DATA
    # --------------------------------------------------------

    def save_features(
        self,
        problem_type: str,
        target: str,
        features: dict,
        outcome: float
    ):

        feature_id = new_id("feature")

        self.connection.execute("""
            INSERT INTO feature_observations
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            feature_id,
            utc_now(),
            problem_type,
            target,
            safe_json(features),
            outcome
        ))

        self.connection.commit()


# ============================================================
# V6 — FEEDBACK / OUTCOME EVALUATION
# ============================================================

class FeedbackEngine:

    @staticmethod
    def calculate_improvement(
        pre_state: dict,
        post_state: dict,
        metric: str
    ) -> float:

        if metric not in pre_state:
            return 0.0

        if metric not in post_state:
            return 0.0

        before = float(pre_state[metric])
        after = float(post_state[metric])

        if before == 0:
            return 0.0

        # Positive = improvement
        improvement = (
            before - after
        ) / abs(before)

        return improvement

    @staticmethod
    def evaluate(
        pre_state: dict,
        post_state: dict,
        success_threshold: float = 0.05
    ) -> tuple[float, bool]:

        common = set(
            pre_state.keys()
        ).intersection(
            post_state.keys()
        )

        if not common:
            return 0.0, False

        improvements = []

        for metric in common:

            before = float(pre_state[metric])
            after = float(post_state[metric])

            if before == 0:
                continue

            improvement = (
                before - after
            ) / abs(before)

            improvements.append(improvement)

        if not improvements:
            return 0.0, False

        result = statistics.mean(
            improvements
        )

        return result, result >= success_threshold


# ============================================================
# V7 — CONTROLLED AUTONOMY
# ============================================================

@dataclass
class AutonomyDecision:

    allowed: bool
    confidence: float
    risk: float

    reason: str

    requires_human: bool


class AutonomyController:

    def __init__(
        self,
        minimum_confidence: float = 0.70,
        maximum_risk: float = 0.30,
        auto_execute: bool = False
    ):

        self.minimum_confidence = (
            minimum_confidence
        )

        self.maximum_risk = maximum_risk

        self.auto_execute = auto_execute

    def authorize(
        self,
        confidence: float,
        risk: float,
        action_type: str
    ) -> AutonomyDecision:

        # High-risk actions always require
        # human approval in this version.

        high_risk_actions = {
            "terminate_process",
            "delete_resource",
            "modify_production",
            "shutdown_service",
            "reconfigure_network"
        }

        if action_type in high_risk_actions:

            return AutonomyDecision(
                allowed=False,
                confidence=confidence,
                risk=risk,
                reason="High-risk action requires human approval.",
                requires_human=True
            )

        if confidence < self.minimum_confidence:

            return AutonomyDecision(
                allowed=False,
                confidence=confidence,
                risk=risk,
                reason="Insufficient historical confidence.",
                requires_human=True
            )

        if risk > self.maximum_risk:

            return AutonomyDecision(
                allowed=False,
                confidence=confidence,
                risk=risk,
                reason="Action risk exceeds autonomy threshold.",
                requires_human=True
            )

        if not self.auto_execute:

            return AutonomyDecision(
                allowed=False,
                confidence=confidence,
                risk=risk,
                reason="Engine is operating in dry-run/manual mode.",
                requires_human=True
            )

        return AutonomyDecision(
            allowed=True,
            confidence=confidence,
            risk=risk,
            reason="Action satisfies autonomy policy.",
            requires_human=False
        )


# ============================================================
# V8 — ML ADAPTER
# ============================================================

class MLAdapter:

    """
    ML boundary.

    The engine can operate without ML.

    Once enough historical data exists, this class can be
    replaced or extended with scikit-learn, PyTorch,
    XGBoost, etc.

    The important architectural decision is that the rest
    of the engine does NOT need to know which ML framework
    is being used.
    """

    def __init__(self):

        self.model = None
        self.enabled = False

        try:

            from sklearn.ensemble import RandomForestRegressor

            self.model = RandomForestRegressor(
                n_estimators=100,
                random_state=42
            )

            self.enabled = True

        except ImportError:

            self.enabled = False

    def train(
        self,
        X: list[list[float]],
        y: list[float]
    ) -> bool:

        if not self.enabled:
            return False

        if len(X) < 10:
            return False

        self.model.fit(X, y)

        return True

    def predict(
        self,
        features: list[float]
    ) -> Optional[float]:

        if not self.enabled:
            return None

        if self.model is None:
            return None

        return float(
            self.model.predict(
                [features]
            )[0]
        )


# ============================================================
# V8 — ADAPTIVE DECISION ENGINE
# ============================================================

class AdaptiveDecisionEngine:

    def __init__(
        self,
        knowledge: KnowledgeStore,
        ml: MLAdapter
    ):

        self.knowledge = knowledge
        self.ml = ml

    def select_action(
        self,
        problem_type: str,
        target: str,
        proposed_actions: list[dict]
    ) -> Optional[dict]:

        candidates = self.knowledge.get_candidates(
            problem_type,
            target
        )

        historical = {}

        for candidate in candidates:

            historical[
                candidate["action_type"]
            ] = candidate

        scored = []

        for action in proposed_actions:

            action_type = action["action_type"]

            confidence = 0.50

            if action_type in historical:

                confidence = historical[
                    action_type
                ]["confidence"]

            risk = float(
                action.get("risk", 0.20)
            )

            expected_improvement = float(
                action.get(
                    "expected_improvement",
                    0.0
                )
            )

            # Historical knowledge becomes more
            # important than the initial estimate.

            if action_type in historical:

                expected_improvement = (
                    0.70 *
                    historical[action_type][
                        "average_improvement"
                    ]
                    +
                    0.30 *
                    expected_improvement
                )

            score = (
                0.50 * confidence +
                0.40 * expected_improvement -
                0.10 * risk
            )

            scored.append(
                (
                    score,
                    {
                        **action,
                        "confidence": confidence,
                        "risk": risk,
                        "expected_improvement":
                            expected_improvement,
                        "score": score
                    }
                )
            )

        if not scored:
            return None

        scored.sort(
            key=lambda item: item[0],
            reverse=True
        )

        return scored[0][1]


# ============================================================
# V9 — DISTRIBUTED NODE REGISTRY
# ============================================================

@dataclass
class Node:

    node_id: str
    hostname: str
    node_type: str
    status: str
    metadata: dict


class DistributedCoordinator:

    def __init__(
        self,
        knowledge: KnowledgeStore
    ):

        self.knowledge = knowledge

    def register_node(
        self,
        node: Node
    ):

        self.knowledge.connection.execute("""
            INSERT OR REPLACE INTO nodes
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            node.node_id,
            node.hostname,
            node.node_type,
            node.status,
            utc_now(),
            safe_json(node.metadata)
        ))

        self.knowledge.connection.commit()

    def heartbeat(
        self,
        node_id: str,
        status: str = "online"
    ):

        self.knowledge.connection.execute("""
            UPDATE nodes
            SET status = ?,
                last_seen = ?
            WHERE node_id = ?
        """, (
            status,
            utc_now(),
            node_id
        ))

        self.knowledge.connection.commit()

    def get_nodes(self):

        cursor = self.knowledge.connection.cursor()

        cursor.execute("""
            SELECT *
            FROM nodes
        """)

        return cursor.fetchall()


# ============================================================
# V6-V9 FEEDBACK LOOP
# ============================================================

class AdaptiveFeedbackLoop:

    def __init__(
        self,
        database: str = "asoe.db",
        auto_execute: bool = False
    ):

        self.knowledge = KnowledgeStore(
            database
        )

        self.feedback = FeedbackEngine()

        self.autonomy = AutonomyController(
            auto_execute=auto_execute
        )

        self.ml = MLAdapter()

        self.decision_engine = (
            AdaptiveDecisionEngine(
                self.knowledge,
                self.ml
            )
        )

        self.distributed = (
            DistributedCoordinator(
                self.knowledge
            )
        )

    # --------------------------------------------------------
    # MAIN V6-V9 PROCESS
    # --------------------------------------------------------

    def process_result(
        self,
        problem_type: str,
        target: str,
        proposed_actions: list[dict],
        pre_state: dict,
        post_state: dict,
        intervention_result: dict,
        duration_seconds: float = 0.0
    ):

        # ====================================================
        # V6 — SELECT / EVALUATE
        # ====================================================

        selected_action = (
            self.decision_engine.select_action(
                problem_type,
                target,
                proposed_actions
            )
        )

        if selected_action is None:

            return {
                "success": False,
                "stage": "V6",
                "message": "No viable action found."
            }

        # ====================================================
        # V7 — AUTONOMY
        # ====================================================

        autonomy = self.autonomy.authorize(
            confidence=selected_action[
                "confidence"
            ],
            risk=selected_action[
                "risk"
            ],
            action_type=selected_action[
                "action_type"
            ]
        )

        # ====================================================
        # V6 — OUTCOME EVALUATION
        # ====================================================

        improvement, successful = (
            self.feedback.evaluate(
                pre_state,
                post_state
            )
        )

        success = (
            intervention_result.get(
                "success",
                successful
            )
            and successful
        )

        # ====================================================
        # V6 — CREATE EXPERIENCE
        # ====================================================

        confidence_before = (
            selected_action[
                "confidence"
            ]
        )

        confidence_after = (
            self._update_confidence(
                confidence_before,
                success,
                intervention_result.get(
                    "rolled_back",
                    False
                )
            )
        )

        experience = Experience(

            experience_id=new_id(
                "experience"
            ),

            timestamp=utc_now(),

            problem_type=problem_type,
            target=target,

            action_type=selected_action[
                "action_type"
            ],

            action_parameters=selected_action.get(
                "parameters",
                {}
            ),

            pre_state=pre_state,
            post_state=post_state,

            success=success,

            changed=intervention_result.get(
                "changed",
                False
            ),

            rolled_back=intervention_result.get(
                "rolled_back",
                False
            ),

            improvement=improvement,

            cost=float(
                intervention_result.get(
                    "cost",
                    0.0
                )
            ),

            risk=float(
                selected_action["risk"]
            ),

            duration_seconds=duration_seconds,

            confidence_before=confidence_before,

            confidence_after=confidence_after,

            notes=intervention_result.get(
                "message",
                ""
            )
        )

        # ====================================================
        # V6 — STORE EXPERIENCE
        # ====================================================

        self.knowledge.save_experience(
            experience
        )

        self.knowledge.update_knowledge(
            experience
        )

        # ====================================================
        # V8 — SAVE ML FEATURES
        # ====================================================

        features = self.build_features(
            problem_type,
            target,
            selected_action,
            pre_state
        )

        self.knowledge.save_features(
            problem_type,
            target,
            features,
            improvement
        )

        return {
            "success": success,

            "selected_action":
                selected_action,

            "autonomy":
                asdict(autonomy),

            "improvement":
                improvement,

            "experience_id":
                experience.experience_id,

            "confidence_before":
                confidence_before,

            "confidence_after":
                confidence_after,

            "ml_enabled":
                self.ml.enabled
        }

    # --------------------------------------------------------
    # CONFIDENCE UPDATE
    # --------------------------------------------------------

    @staticmethod
    def _update_confidence(
        confidence: float,
        success: bool,
        rolled_back: bool
    ) -> float:

        if success:

            confidence += (
                0.05 *
                (1.0 - confidence)
            )

        else:

            confidence -= (
                0.10 *
                confidence
            )

        if rolled_back:

            confidence *= 0.75

        return max(
            0.0,
            min(1.0, confidence)
        )

    # --------------------------------------------------------
    # FEATURE GENERATION
    # --------------------------------------------------------

    @staticmethod
    def build_features(
        problem_type: str,
        target: str,
        action: dict,
        state: dict
    ) -> dict:

        numeric_state = {}

        for key, value in state.items():

            try:
                numeric_state[key] = float(
                    value
                )

            except (
                TypeError,
                ValueError
            ):
                continue

        return {
            "problem_type": problem_type,
            "target": target,
            "action_type":
                action["action_type"],
            "risk":
                action.get("risk", 0.0),
            "expected_improvement":
                action.get(
                    "expected_improvement",
                    0.0
                ),
            "state":
                numeric_state
        }

    # --------------------------------------------------------
    # ML TRAINING
    # --------------------------------------------------------

    def train_ml_model(self):

        cursor = self.knowledge.connection.cursor()

        cursor.execute("""
            SELECT features, outcome
            FROM feature_observations
        """)

        rows = cursor.fetchall()

        X = []
        y = []

        for row in rows:

            try:

                data = json.loads(
                    row["features"]
                )

                state = data.get(
                    "state",
                    {}
                )

                features = [
                    float(value)
                    for value in state.values()
                ]

                if not features:
                    continue

                X.append(features)

                y.append(
                    float(row["outcome"])
                )

            except Exception:

                continue

        if len(X) < 10:

            return {
                "trained": False,
                "reason":
                    "At least 10 usable experiences are recommended."
            }

        # Make feature vectors equal length.

        max_length = max(
            len(row)
            for row in X
        )

        normalized = []

        for row in X:

            row = row[:]

            while len(row) < max_length:
                row.append(0.0)

            normalized.append(row)

        trained = self.ml.train(
            normalized,
            y
        )

        return {
            "trained": trained,
            "samples": len(normalized),
            "ml_enabled": self.ml.enabled
        }


# ============================================================
# DEMONSTRATION / TEST HARNESS
# ============================================================

def demo():

    print()
    print("=" * 70)
    print("ADAPTIVE SYSTEMS OPTIMIZATION ENGINE")
    print("V6-V9 FEEDBACK / LEARNING / AUTONOMY / ML / DISTRIBUTED")
    print("=" * 70)

    engine = AdaptiveFeedbackLoop(
        database="asoe.db",
        auto_execute=False
    )

    # --------------------------------------------------------
    # V9 NODE REGISTRATION
    # --------------------------------------------------------

    node = Node(
        node_id="local-node",
        hostname=os.uname().nodename,
        node_type="local",
        status="online",
        metadata={
            "platform": os.name
        }
    )

    engine.distributed.register_node(
        node
    )

    print()
    print("[V9] Node registered.")

    # --------------------------------------------------------
    # SIMULATED V0-V5 RESULT
    # --------------------------------------------------------

    problem_type = "memory_pressure"

    target = "example_process"

    proposed_actions = [

        {
            "action_type":
                "reconfigure_process",

            "parameters": {
                "strategy":
                    "resource_limit_adjustment"
            },

            "expected_improvement":
                0.20,

            "risk":
                0.10
        },

        {
            "action_type":
                "restart_process",

            "parameters": {},

            "expected_improvement":
                0.50,

            "risk":
                0.25
        },

        {
            "action_type":
                "terminate_process",

            "parameters": {},

            "expected_improvement":
                0.90,

            "risk":
                0.90
        }
    ]

    # --------------------------------------------------------
    # STATE BEFORE V5 INTERVENTION
    # --------------------------------------------------------

    pre_state = {
        "memory_usage": 90.0,
        "cpu_usage": 70.0
    }

    # --------------------------------------------------------
    # STATE AFTER V5 INTERVENTION
    # --------------------------------------------------------

    post_state = {
        "memory_usage": 65.0,
        "cpu_usage": 50.0
    }

    # --------------------------------------------------------
    # RESULT FROM V5
    # --------------------------------------------------------

    intervention_result = {

        "success": True,

        "changed": True,

        "rolled_back": False,

        "cost": 0.05,

        "message":
            "Intervention completed successfully."
    }

    # --------------------------------------------------------
    # RUN V6-V9
    # --------------------------------------------------------

    result = engine.process_result(

        problem_type=problem_type,

        target=target,

        proposed_actions=proposed_actions,

        pre_state=pre_state,

        post_state=post_state,

        intervention_result=intervention_result,

        duration_seconds=2.4
    )

    print()
    print("[V6-V9 RESULT]")

    print(
        json.dumps(
            result,
            indent=4
        )
    )

    # --------------------------------------------------------
    # TRAIN ML
    # --------------------------------------------------------

    training_result = (
        engine.train_ml_model()
    )

    print()
    print("[V8 ML STATUS]")

    print(
        json.dumps(
            training_result,
            indent=4
        )
    )

    print()
    print("=" * 70)
    print("FEEDBACK LOOP COMPLETE")
    print("=" * 70)
    print()


# ============================================================
# CLI
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=
        "Adaptive Systems Optimization Engine V6-V9"
    )

    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run the V6-V9 demonstration."
    )

    parser.add_argument(
        "--train",
        action="store_true",
        help="Train the ML adapter from stored experiences."
    )

    parser.add_argument(
        "--database",
        default="asoe.db",
        help="SQLite database path."
    )

    args = parser.parse_args()

    if args.demo:

        demo()

        return

    if args.train:

        engine = AdaptiveFeedbackLoop(
            database=args.database
        )

        result = engine.train_ml_model()

        print(
            json.dumps(
                result,
                indent=4
            )
        )

        return

    print()
    print(
        "Adaptive Systems Optimization Engine "
        "V6-V9"
    )

    print()
    print(
        "Run:"
    )

    print(
        "    python adaptive_v6_v9.py --demo"
    )

    print(
        "to test the feedback loop."
    )

    print(
        "Run:"
    )

    print(
        "    python adaptive_v6_v9.py --train"
    )

    print(
        "to train the ML layer."
    )


if __name__ == "__main__":
    main()