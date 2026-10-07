from __future__ import annotations

from hunterseeker.core.contracts import (
    DecisionCandidate,
)


class DecisionEngine:

    def __init__(self, config):
        self.config = config

    def decide(
        self,
        observation,
        detection,
        evidence,
        context,
        predicted_outcomes,
    ):

        candidates = [
            "do_nothing"
        ]

        if (
            detection.threat_probability
            >= 0.75
        ):

            candidates.append(
                "isolate_process"
            )

        if any(
            s["signal"] == "cpu_percent"
            for s in evidence.signals
        ):

            candidates.append(
                "lower_priority"
            )

        if any(
            s["signal"] == "disk_percent"
            for s in evidence.signals
        ):

            candidates.append(
                "reclaim_temp_files"
            )

        candidates = list(
            dict.fromkeys(
                candidates
            )
        )

        return DecisionCandidate(
            observation_id=
                observation.observation_id,

            action_candidates=
                candidates,

            chosen_action_hint=
                candidates[0],

            rationale=
                evidence.rationale,

            prerequisites=[
                "V9 safety gate required",
                "V4 verification required",
            ],
        )