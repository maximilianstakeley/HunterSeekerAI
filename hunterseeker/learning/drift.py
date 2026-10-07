from __future__ import annotations

from collections import deque
import math


class DriftDetector:

    def __init__(
        self,
        window=100,
    ):

        self.window = window

        self.reference = []

        self.current = deque(
            maxlen=window
        )

    def fit_reference(
        self,
        values,
    ):

        self.reference = [
            float(x)
            for x in values
        ]

    def update(
        self,
        value,
    ):

        self.current.append(
            float(value)
        )

    def detect(
        self,
        threshold=0.20,
    ):

        if (
            len(self.reference) < 10
            or
            len(self.current) < 10
        ):

            return {
                "drift": False,

                "score": 0.0,

                "reason":
                    "insufficient data",
            }

        reference_mean = (
            sum(self.reference)
            /
            len(self.reference)
        )

        current_mean = (
            sum(self.current)
            /
            len(self.current)
        )

        reference_std = math.sqrt(
            sum(
                (
                    x -
                    reference_mean
                ) ** 2
                for x in self.reference
            )
            /
            len(self.reference)
        )

        scale = max(
            reference_std,
            1e-6,
        )

        score = abs(
            current_mean
            -
            reference_mean
        ) / scale

        normalized = min(
            1.0,
            score / 5.0,
        )

        return {
            "drift":
                normalized >= threshold,

            "score":
                normalized,

            "reason":
                "distribution changed"
                if normalized >= threshold
                else
                "within reference range",
        }