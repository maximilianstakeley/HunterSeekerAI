from __future__ import annotations

from hunterseeker.core.contracts import (
    PolicyDecision,
)


class PolicyEngine:

    def __init__(self, config):

        self.config = config

        self.policy_version = (
            "v8-prior-policy"
        )

    def select(
        self,
        observation,
        detection,
        evidence,
        decision,
        predicted_outcomes,
    ):

        allowed = set(
            decision.action_candidates
        )

        options = [
            item
            for item in predicted_outcomes
            if item.action in allowed
        ]

        if not options:

            action = "do_nothing"
            value = 0.0
            confidence = 1.0

        else:

            best = max(
                options,
                key=lambda x:
                    x.predicted_value,
            )

            action = best.action

            value = (
                best.predicted_value
            )

            confidence = (
                best.predicted_success
            )

        return PolicyDecision(
            observation_id=
                observation.observation_id,

            action=action,

            confidence=max(
                0.0,
                min(
                    1.0,
                    confidence,
                ),
            ),

            expected_value=value,

            rationale=
                decision.rationale,

            reversible=(
                action != "terminate"
            ),

            policy_version=
                self.policy_version,
        )