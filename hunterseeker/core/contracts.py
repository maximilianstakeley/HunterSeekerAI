from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import hashlib
import json


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_id(payload: Any) -> str:
    raw = json.dumps(
        payload,
        sort_keys=True,
        default=str,
    ).encode("utf-8")

    return hashlib.sha256(raw).hexdigest()[:24]


@dataclass(frozen=True)
class RuntimeConfig:
    dry_run: bool = True
    auto_execute: bool = False

    interval_seconds: float = 5.0

    model_registry: Path = Path(
        "artifacts/model_registry.json"
    )

    experience_db: Path = Path(
        "artifacts/experience_memory.sqlite3"
    )

    perception_model: Path = Path(
        "artifacts/hunterseeker_five_dataset_model.joblib"
    )

    action_outcome_model: Path = Path(
        "artifacts/action_outcome_model.joblib"
    )

    retrain_every_experiences: int = 100

    minimum_training_experiences: int = 100

    minimum_candidate_gain: float = 0.02

    drift_window: int = 100


# ============================================================
# V0
# ============================================================

@dataclass(frozen=True)
class Observation:
    observation_id: str
    timestamp_utc: str
    source: str

    payload: Dict[str, Any]

    provenance: Dict[str, Any] = field(
        default_factory=dict
    )


# ============================================================
# V1
# ============================================================

@dataclass(frozen=True)
class DetectionResult:
    observation_id: str

    anomaly_probability: float
    threat_probability: float

    threat_label: str
    attack_family: str

    confidence: float
    uncertainty: float

    model_version: str

    evidence_features: Dict[str, float] = field(
        default_factory=dict
    )


# ============================================================
# V2
# ============================================================

@dataclass(frozen=True)
class EvidenceResult:
    observation_id: str

    signals: List[Dict[str, Any]]

    relationships: List[Dict[str, Any]]

    persistence_score: float

    rationale: str


# ============================================================
# V6 CONTEXT
# ============================================================

@dataclass(frozen=True)
class ContextResult:
    observation_id: str

    history_count: int

    temporal_features: Dict[str, float]

    correlated_observations: List[str]


# ============================================================
# V3 DECISION
# ============================================================

@dataclass(frozen=True)
class DecisionCandidate:
    observation_id: str

    action_candidates: List[str]

    chosen_action_hint: str

    rationale: str

    prerequisites: List[str] = field(
        default_factory=list
    )


# ============================================================
# V7 OUTCOME PREDICTION
# ============================================================

@dataclass(frozen=True)
class OutcomePrediction:
    action: str

    predicted_success: float

    expected_benefit: float
    expected_risk: float
    expected_cost: float

    predicted_value: float


# ============================================================
# V8 POLICY
# ============================================================

@dataclass(frozen=True)
class PolicyDecision:
    observation_id: str

    action: str

    confidence: float

    expected_value: float

    rationale: str

    reversible: bool

    policy_version: str


# ============================================================
# V9
# ============================================================

@dataclass(frozen=True)
class ActionPlan:
    action: str

    authorized: bool

    target: Optional[str]

    parameters: Dict[str, Any]

    reason: str


# ============================================================
# V5
# ============================================================

@dataclass(frozen=True)
class ActionResult:
    action: str

    authorized: bool

    succeeded: bool

    simulated: bool

    reverted: bool

    target: Optional[str]

    before: Dict[str, Any]

    after: Dict[str, Any]

    error: Optional[str] = None


# ============================================================
# V4
# ============================================================

@dataclass(frozen=True)
class VerificationResult:
    verified: bool

    improved: bool

    collateral_damage: bool

    rollback_required: bool

    rollback_performed: bool

    verification_score: float

    explanation: str

    learning_eligible: bool


# ============================================================
# V10
# ============================================================

@dataclass(frozen=True)
class Experience:
    experience_id: str

    timestamp_utc: str

    observation: Observation

    detection: DetectionResult

    evidence: EvidenceResult

    context: ContextResult

    decision: DecisionCandidate

    policy: PolicyDecision

    action_result: ActionResult

    verification: VerificationResult

    reward: float

    model_version: str

    policy_version: str

    learning_eligible: bool


def dataclass_to_dict(value: Any) -> Dict[str, Any]:
    return asdict(value)