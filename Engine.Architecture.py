#!/usr/bin/env python3
"""HunterSeekerAI four-layer runtime architecture contracts.

This module contains structural boundaries only. It deliberately has no
network-execution, remediation, or autonomous-control implementation.

Layer 1 OBSERVE
    Ingest telemetry/events and preserve provenance.

Layer 2 REPRESENT / DETECT
    Convert observations into canonical behavioral evidence and estimate
    anomaly/threat state.

Layer 3 INVESTIGATE / DECIDE
    Correlate evidence, determine confidence, select a bounded response
    candidate, and record the rationale.

Layer 4 ACT / VERIFY / LEARN
    Execute only an explicitly authorized action, verify its effect, revert
    when appropriate, and store the experience for future learning.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

ARCHITECTURE_VERSION = "four-layer-runtime-v1"
ARCHITECTURE_LAYERS: Dict[str, str] = {
    "layer_1_observe": "Telemetry/data acquisition and provenance; no ML decisions",
    "layer_2_represent_detect": "Canonical behavioral representation and threat inference",
    "layer_3_investigate_decide": "Evidence correlation, confidence, rationale, and bounded decision selection",
    "layer_4_act_verify_learn": "Authorized action, verification/reversion, and experience capture",
}


@dataclass(frozen=True)
class Observation:
    """Layer 1 output: immutable observation with provenance."""

    source: str
    timestamp_utc: str
    payload: Dict[str, Any]
    provenance: Dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def now(source: str, payload: Dict[str, Any], provenance: Optional[Dict[str, Any]] = None) -> "Observation":
        return Observation(
            source=source,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            payload=dict(payload),
            provenance=dict(provenance or {}),
        )


@dataclass(frozen=True)
class BehavioralEvidence:
    """Layer 2 output: model-ready canonical evidence and detection scores."""

    observation_id: str
    features: Dict[str, float]
    categorical_features: Dict[str, str]
    anomaly_probability: Optional[float]
    threat_label: str
    model_version: str


@dataclass(frozen=True)
class DecisionCandidate:
    """Layer 3 output: a proposed bounded response, not an execution request."""

    action: str
    confidence: float
    rationale: str
    prerequisites: List[str] = field(default_factory=list)
    reversible: bool = True


@dataclass(frozen=True)
class ActionResult:
    """Layer 4 output: recorded result of an externally authorized action."""

    action: str
    authorized: bool
    succeeded: bool
    verified: bool
    reverted: bool
    metrics_before: Dict[str, Any] = field(default_factory=dict)
    metrics_after: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class RuntimeState:
    """Shared state boundary for future stage integration."""

    architecture_version: str = ARCHITECTURE_VERSION
    observations: int = 0
    detections: int = 0
    decisions: int = 0
    actions: int = 0
    verified_actions: int = 0
    learned_experiences: int = 0
