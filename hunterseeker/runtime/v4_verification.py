from __future__ import annotations

from hunterseeker.core.contracts import (
    VerificationResult,
)


class VerificationEngine:

    def __init__(self, config):

        self.config = config

    def verify(
        self,
        observation,
        plan,
        result,
    ):

        # ------------------------------------------------
        # CRITICAL:
        # dry-run cannot teach the policy that an action
        # actually worked.
        # ------------------------------------------------

        if result.simulated:

            return VerificationResult(
                verified=False,

                improved=False,

                collateral_damage=False,

                rollback_required=False,

                rollback_performed=False,

                verification_score=0.0,

                explanation=(
                    "Dry-run; "
                    "no environmental effect measured."
                ),

                learning_eligible=False,
            )

        if not result.succeeded:

            return VerificationResult(
                verified=False,

                improved=False,

                collateral_damage=False,

                rollback_required=False,

                rollback_performed=False,

                verification_score=0.0,

                explanation=(
                    result.error
                    or
                    "execution failed"
                ),

                learning_eligible=False,
            )

        before_cpu = float(
            result.before.get(
                "cpu_percent",
                0.0,
            )
        )

        after_cpu = float(
            result.after.get(
                "cpu_percent",
                before_cpu,
            )
        )

        improved = (
            after_cpu
            <
            before_cpu - 1.0
        )

        return VerificationResult(
            verified=True,

            improved=improved,

            collateral_damage=False,

            rollback_required=False,

            rollback_performed=
                result.reverted,

            verification_score=(
                1.0
                if improved
                else 0.5
            ),

            explanation=(
                "Post-action verification completed."
            ),

            learning_eligible=True,
        )