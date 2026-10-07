from __future__ import annotations

from pathlib import Path
import numpy as np
import pandas as pd

from hunterseeker.core.contracts import (
    DetectionResult,
    Observation,
    RuntimeConfig,
)


class DetectionEngine:

    def __init__(
        self,
        config: RuntimeConfig,
    ) -> None:

        self.config = config

        self.bundle = None

        self.model_version = "fallback"

        self._load_model()

    def _load_model(self) -> None:

        path = Path(
            self.config.perception_model
        )

        if not path.exists():
            return

        try:

            import joblib

            self.bundle = joblib.load(
                path
            )

            self.model_version = str(
                self.bundle.get(
                    "model_version",
                    path.name,
                )
            )

        except Exception:

            self.bundle = None

    def _build_feature_frame(
        self,
        observation: Observation,
    ) -> pd.DataFrame:

        system = observation.payload.get(
            "system",
            {},
        )

        row = {
            "duration": np.nan,

            "source_port": np.nan,

            "destination_port": np.nan,

            "bytes_in": np.nan,

            "bytes_out": np.nan,

            "packets_in": np.nan,

            "packets_out": np.nan,

            "missed_bytes": np.nan,

            "source_ip_bytes": np.nan,

            "destination_ip_bytes": np.nan,

            "cpu_usage":
                system.get(
                    "cpu_percent",
                    np.nan,
                ),

            "memory_usage":
                system.get(
                    "memory_percent",
                    np.nan,
                ),

            "disk_usage":
                system.get(
                    "disk_percent",
                    np.nan,
                ),

            "network_usage": np.nan,

            "process_count":
                system.get(
                    "process_count",
                    np.nan,
                ),

            "temperature": np.nan,

            "power": np.nan,

            "protocol": "unknown",

            "service": "unknown",
        }

        return pd.DataFrame([row])

    def detect(
        self,
        observation: Observation,
    ) -> DetectionResult:

        if self.bundle is not None:

            try:

                preprocessor = (
                    self.bundle["preprocessor"]
                )

                estimator = (
                    self.bundle["estimator"]
                )

                X = self._build_feature_frame(
                    observation
                )

                transformed = (
                    preprocessor.transform(X)
                )

                if hasattr(
                    estimator,
                    "predict_proba",
                ):

                    probability = float(
                        estimator
                        .predict_proba(
                            transformed
                        )[0][1]
                    )

                else:

                    probability = float(
                        estimator.predict(
                            transformed
                        )[0]
                    )

                probability = max(
                    0.0,
                    min(
                        1.0,
                        probability,
                    ),
                )

                confidence = abs(
                    probability - 0.5
                ) * 2.0

                uncertainty = (
                    1.0 - confidence
                )

                if probability >= 0.80:
                    label = "known_threat"

                elif probability >= 0.50:
                    label = "suspicious"

                else:
                    label = "normal"

                return DetectionResult(
                    observation_id=
                        observation.observation_id,

                    anomaly_probability=
                        probability,

                    threat_probability=
                        probability,

                    threat_label=label,

                    attack_family=
                        "unknown",

                    confidence=confidence,

                    uncertainty=uncertainty,

                    model_version=
                        self.model_version,
                )

            except Exception:
                pass

        # Explicit fallback.
        # This is NOT the trained network detector.

        system = observation.payload.get(
            "system",
            {},
        )

        cpu = float(
            system.get(
                "cpu_percent",
                0.0,
            )
        )

        memory = float(
            system.get(
                "memory_percent",
                0.0,
            )
        )

        score = (
            0.60
            * max(
                0.0,
                (cpu - 75.0) / 25.0,
            )
            +
            0.40
            * max(
                0.0,
                (memory - 80.0) / 20.0,
            )
        )

        score = max(
            0.0,
            min(
                1.0,
                score,
            )
        )

        confidence = (
            abs(score - 0.5) * 2.0
        )

        return DetectionResult(
            observation_id=
                observation.observation_id,

            anomaly_probability=score,

            threat_probability=score,

            threat_label=(
                "suspicious"
                if score >= 0.50
                else "normal"
            ),

            attack_family="host_resource",

            confidence=confidence,

            uncertainty=1.0 - confidence,

            model_version=
                "fallback-host-v1",
        )