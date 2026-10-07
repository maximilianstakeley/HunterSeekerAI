from __future__ import annotations

from pathlib import Path
import json

from hunterseeker.core.contracts import (
    OutcomePrediction,
)


class OutcomePredictionEngine:

    ACTIONS = (
        "do_nothing",
        "lower_priority",
        "isolate_process",
        "reclaim_temp_files",
    )

    def __init__(self, config):

        self.config = config

        self.model = None

        self.version = "prior-v7"

        self._load_model()

    def _load_model(self):

        path = Path(
            self.config.action_outcome_model
        )

        if not path.exists():
            return

        try:

            import joblib

            self.model = joblib.load(
                path
            )

            self.version = path.name

        except Exception:

            self.model = None

    def _vector(
        self,
        observation,
        detection,
        evidence,
        context,
        action,
    ):

        system = observation.payload.get(
            "system",
            {},
        )

        vector = [
            detection.threat_probability,
            detection.confidence,
            detection.uncertainty,

            len(evidence.signals),

            evidence.persistence_score,

            context.temporal_features.get(
                "anomaly_current",
                0.0,
            ),

            context.temporal_features.get(
                "anomaly_delta",
                0.0,
            ),

            context.temporal_features.get(
                "anomaly_mean",
                0.0,
            ),

            float(
                system.get(
                    "cpu_percent",
                    0.0,
                )
            ) / 100.0,

            float(
                system.get(
                    "memory_percent",
                    0.0,
                )
            ) / 100.0,

            float(
                system.get(
                    "disk_percent",
                    0.0,
                )
            ) / 100.0,
        ]

        vector.extend(
            1.0 if action == candidate else 0.0
            for candidate in self.ACTIONS
        )

        return [vector]

    def predict(
        self,
        observation,
        detection,
        evidence,
        context,
    ):

        output = []

        priors = {
            "do_nothing":
                (0.10, 0.02, 0.01),

            "lower_priority":
                (0.45, 0.12, 0.05),

            "isolate_process":
                (0.80, 0.30, 0.20),

            "reclaim_temp_files":
                (0.35, 0.08, 0.05),
        }

        for action in self.ACTIONS:

            benefit, risk, cost = (
                priors[action]
            )

            learned_value = None

            if self.model is not None:

                try:

                    learned_value = float(
                        self.model.predict(
                            self._vector(
                                observation,
                                detection,
                                evidence,
                                context,
                                action,
                            )
                        )[0]
                    )

                except Exception:

                    learned_value = None

            if learned_value is None:

                learned_value = (
                    benefit
                    - risk
                    - cost
                )

            success = 1.0 / (
                1.0
                +
                max(
                    0.0,
                    -learned_value,
                )
            )

            output.append(
                OutcomePrediction(
                    action=action,

                    predicted_success=
                        success,

                    expected_benefit=
                        benefit,

                    expected_risk=
                        risk,

                    expected_cost=
                        cost,

                    predicted_value=
                        learned_value,
                )
            )

        return output