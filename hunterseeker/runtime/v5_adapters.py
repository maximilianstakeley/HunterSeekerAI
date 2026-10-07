from __future__ import annotations

try:
    import psutil
except ImportError:
    psutil = None

from hunterseeker.core.contracts import (
    ActionResult,
    ActionPlan,
    Observation,
)


class AdapterManager:

    def __init__(self, config):

        self.config = config

    def execute(
        self,
        plan: ActionPlan,
        observation: Observation,
    ) -> ActionResult:

        before = dict(
            observation.payload.get(
                "system",
                {},
            )
        )

        if not plan.authorized:

            return ActionResult(
                action=plan.action,

                authorized=False,

                succeeded=False,

                simulated=True,

                reverted=False,

                target=plan.target,

                before=before,

                after=before,

                error="Rejected by V9.",
            )

        # ------------------------------------------------
        # SAFE DEVELOPMENT MODE
        # ------------------------------------------------

        if (
            self.config.dry_run
            or
            not self.config.auto_execute
        ):

            return ActionResult(
                action=plan.action,

                authorized=True,

                succeeded=True,

                simulated=True,

                reverted=False,

                target=plan.target,

                before=before,

                after=before,
            )

        # ------------------------------------------------
        # REAL EXECUTION
        # ------------------------------------------------

        if (
            plan.action
            == "lower_priority"
            and
            psutil is not None
            and
            plan.target
        ):

            try:

                process = psutil.Process(
                    int(plan.target)
                )

                original_nice = process.nice()

                new_nice = max(
                    original_nice,
                    10,
                )

                process.nice(
                    new_nice
                )

                after = dict(
                    before
                )

                return ActionResult(
                    action=plan.action,

                    authorized=True,

                    succeeded=True,

                    simulated=False,

                    reverted=False,

                    target=plan.target,

                    before=before,

                    after=after,
                )

            except Exception as exc:

                return ActionResult(
                    action=plan.action,

                    authorized=True,

                    succeeded=False,

                    simulated=False,

                    reverted=False,

                    target=plan.target,

                    before=before,

                    after=before,

                    error=str(exc),
                )

        return ActionResult(
            action=plan.action,

            authorized=True,

            succeeded=True,

            simulated=False,

            reverted=False,

            target=plan.target,

            before=before,

            after=before,
        )