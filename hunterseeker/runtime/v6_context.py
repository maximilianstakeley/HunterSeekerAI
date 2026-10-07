from __future__ import annotations

from collections import deque

from hunterseeker.core.contracts import (
    ContextResult,
)


class ContextLearningEngine:

    def __init__(
        self,
        config,
        history_size: int = 128,
    ) -> None:

        self.history = deque(
            maxlen=history_size
        )

    def update(
        self,
        observation,
        detection,
        evidence,
    ):

        self.history.append(
            (
                observation,
                detection,
                evidence,
            )
        )

        probabilities = [
            item[1].anomaly_probability
            for item in self.history
        ]

        current = probabilities[-1]

        previous = (
            probabilities[-2]
            if len(probabilities) >= 2
            else current
        )

        return ContextResult(
            observation_id=
                observation.observation_id,

            history_count=
                len(self.history),

            temporal_features={
                "anomaly_current":
                    current,

                "anomaly_delta":
                    current - previous,

                "anomaly_mean":
                    sum(probabilities)
                    /
                    len(probabilities),

                "anomaly_max":
                    max(probabilities),
            },

            correlated_observations=[
                item[0].observation_id
                for item in list(
                    self.history
                )[-5:]
                if item[1]
                .threat_probability
                >= 0.50
            ],
        )