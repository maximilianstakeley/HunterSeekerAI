from __future__ import annotations

from hunterseeker.core.contracts import (
    DetectionResult,
    EvidenceResult,
    Observation,
)


class EvidenceEngine:

    def __init__(self, config):
        self.config = config

    def analyze(
        self,
        observation: Observation,
        detection: DetectionResult,
    ) -> EvidenceResult:

        system = observation.payload.get(
            "system",
            {},
        )

        signals = []

        thresholds = {
            "cpu_percent": 85.0,
            "memory_percent": 85.0,
            "disk_percent": 90.0,
        }

        for name, threshold in thresholds.items():

            value = float(
                system.get(
                    name,
                    0.0,
                )
            )

            if value >= threshold:

                signals.append(
                    {
                        "signal": name,
                        "value": value,
                        "threshold": threshold,
                        "severity":
                            min(
                                1.0,
                                value / threshold,
                            ),
                    }
                )

        relationships = []

        if (
            signals
            and
            detection.threat_probability >= 0.50
        ):

            relationships.append(
                {
                    "type":
                        "resource_threat_correlation",

                    "strength":
                        detection
                        .threat_probability,
                }
            )

        persistence_score = min(
            1.0,
            len(signals) / 3.0,
        )

        return EvidenceResult(
            observation_id=
                observation.observation_id,

            signals=signals,

            relationships=relationships,

            persistence_score=
                persistence_score,

            rationale=(
                "Correlated signals detected."
                if relationships
                else
                "Insufficient multi-signal evidence."
            ),
        )