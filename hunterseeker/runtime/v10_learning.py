from __future__ import annotations

from hunterseeker.core.contracts import (
    Experience,
    stable_id,
    utc_now,
)

from hunterseeker.learning.experience_store import (
    ExperienceStore,
)


class LearningEngine:

    def __init__(
        self,
        config,
    ):

        self.config = config

        self.store = ExperienceStore(
            config.experience_db
        )

        self.experiences_since_training = 0

    def _calculate_reward(
        self,
        detection,
        action_result,
        verification,
    ):

        # No environmental evidence.
        if (
            action_result.simulated
            or
            not verification.learning_eligible
        ):

            return 0.0

        reward = 0.0

        if action_result.succeeded:
            reward += 0.10

        if verification.verified:
            reward += 0.20

        if verification.improved:
            reward += 0.65

        if verification.collateral_damage:
            reward -= 0.80

        if verification.rollback_required:
            reward -= 0.30

        if (
            action_result.action
            == "do_nothing"
            and
            detection.threat_probability
            >= 0.50
        ):

            reward -= 0.50

        return max(
            -1.0,
            min(
                1.0,
                reward,
            ),
        )

    def record(
        self,
        observation,
        detection,
        evidence,
        context,
        decision,
        policy,
        action_result,
        verification,
    ):

        reward = self._calculate_reward(
            detection,
            action_result,
            verification,
        )

        experience_id = stable_id(
            {
                "observation":
                    observation.observation_id,

                "action":
                    policy.action,

                "verified":
                    verification.verified,

                "reward":
                    reward,
            }
        )

        experience = Experience(
            experience_id=
                experience_id,

            timestamp_utc=
                utc_now(),

            observation=
                observation,

            detection=
                detection,

            evidence=
                evidence,

            context=
                context,

            decision=
                decision,

            policy=
                policy,

            action_result=
                action_result,

            verification=
                verification,

            reward=
                reward,

            model_version=
                detection.model_version,

            policy_version=
                policy.policy_version,

            learning_eligible=
                verification.learning_eligible
                and
                not action_result.simulated
                and
                action_result.succeeded,
        )

        self.store.insert(
            experience
        )

        if experience.learning_eligible:

            self.experiences_since_training += 1

        return experience