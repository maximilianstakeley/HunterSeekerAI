from __future__ import annotations

from hunterseeker.core.contracts import (
    ActionPlan,
)


class SafetyOrchestrator:

    ALLOWED_ACTIONS = {
        "do_nothing",
        "lower_priority",
        "isolate_process",
        "reclaim_temp_files",
    }

    def __init__(self, config):

        self.config = config

    def gate(
        self,
        policy,
        observation,
        detection,
        evidence,
    ):

        action = policy.action

        authorized = False

        if action in self.ALLOWED_ACTIONS:

            if action == "do_nothing":

                authorized = True

            elif (
                policy.confidence
                >= 0.70
                and
                (
                    detection
                    .threat_probability
                    >= 0.50

                    or

                    any(
                        signal["severity"]
                        >= 0.90
                        for signal
                        in evidence.signals
                    )
                )
            ):

                authorized = True

        target = None

        if action in {
            "lower_priority",
            "isolate_process",
        }:

            target = str(
                observation.payload
                .get("host", {})
                .get("pid")
            )

        return ActionPlan(
            action=action,

            authorized=authorized,

            target=target,

            parameters={},

            reason=(
                "approved"
                if authorized
                else
                "rejected by deterministic safety gate"
            ),
        )