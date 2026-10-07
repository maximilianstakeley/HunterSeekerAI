from __future__ import annotations

import argparse
import time
from pathlib import Path

from hunterseeker.core.contracts import (
    RuntimeConfig,
)

from hunterseeker.runtime.v0_observation import (
    ObservationEngine,
)

from hunterseeker.runtime.v1_detection import (
    DetectionEngine,
)

from hunterseeker.runtime.v2_evidence import (
    EvidenceEngine,
)

from hunterseeker.runtime.v3_decision import (
    DecisionEngine,
)

from hunterseeker.runtime.v4_verification import (
    VerificationEngine,
)

from hunterseeker.runtime.v5_adapters import (
    AdapterManager,
)

from hunterseeker.runtime.v6_context import (
    ContextLearningEngine,
)

from hunterseeker.runtime.v7_outcome import (
    OutcomePredictionEngine,
)

from hunterseeker.runtime.v8_policy import (
    PolicyEngine,
)

from hunterseeker.runtime.v9_safety import (
    SafetyOrchestrator,
)

from hunterseeker.runtime.v10_learning import (
    LearningEngine,
)


def build_engine(args):

    config = RuntimeConfig(

        dry_run=(
            not args.execute
        ),

        auto_execute=(
            args.execute
        ),

        interval_seconds=
            args.interval,

        model_registry=
            Path(args.registry),

        experience_db=
            Path(args.experience_db),

        perception_model=
            Path(args.model),

        action_outcome_model=
            Path(
                args.action_model
            ),

        retrain_every_experiences=
            args.retrain_every,

        minimum_training_experiences=
            args.minimum_experiences,
    )

    return {

        "config":
            config,

        "v0":
            ObservationEngine(
                config
            ),

        "v1":
            DetectionEngine(
                config
            ),

        "v2":
            EvidenceEngine(
                config
            ),

        "v3":
            DecisionEngine(
                config
            ),

        "v4":
            VerificationEngine(
                config
            ),

        "v5":
            AdapterManager(
                config
            ),

        "v6":
            ContextLearningEngine(
                config
            ),

        "v7":
            OutcomePredictionEngine(
                config
            ),

        "v8":
            PolicyEngine(
                config
            ),

        "v9":
            SafetyOrchestrator(
                config
            ),

        "v10":
            LearningEngine(
                config
            ),
    }


def run_cycle(
    engine,
):

    v0 = engine["v0"]
    v1 = engine["v1"]
    v2 = engine["v2"]
    v3 = engine["v3"]
    v4 = engine["v4"]
    v5 = engine["v5"]
    v6 = engine["v6"]
    v7 = engine["v7"]
    v8 = engine["v8"]
    v9 = engine["v9"]
    v10 = engine["v10"]

    # ============================================
    # V0
    # ============================================

    observation = v0.observe()

    # ============================================
    # V1
    # ============================================

    detection = v1.detect(
        observation
    )

    # ============================================
    # V2
    # ============================================

    evidence = v2.analyze(
        observation,
        detection,
    )

    # ============================================
    # V6
    # ============================================

    context = v6.update(
        observation,
        detection,
        evidence,
    )

    # ============================================
    # V7
    # ============================================

    outcomes = v7.predict(
        observation,
        detection,
        evidence,
        context,
    )

    # ============================================
    # V3
    # ============================================

    decision = v3.decide(
        observation=
            observation,

        detection=
            detection,

        evidence=
            evidence,

        context=
            context,

        predicted_outcomes=
            outcomes,
    )

    # ============================================
    # V8
    # ============================================

    policy = v8.select(
        observation=
            observation,

        detection=
            detection,

        evidence=
            evidence,

        decision=
            decision,

        predicted_outcomes=
            outcomes,
    )

    # ============================================
    # V9
    # ============================================

    plan = v9.gate(
        policy,
        observation,
        detection,
        evidence,
    )

    # ============================================
    # V5
    # ============================================

    action_result = v5.execute(
        plan,
        observation,
    )

    # ============================================
    # V4
    # ============================================

    verification = v4.verify(
        observation,
        plan,
        action_result,
    )

    # ============================================
    # V10
    # ============================================

    experience = v10.record(
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
    )

    return {
        "observation":
            observation,

        "detection":
            detection,

        "evidence":
            evidence,

        "context":
            context,

        "outcomes":
            outcomes,

        "decision":
            decision,

        "policy":
            policy,

        "plan":
            plan,

        "action_result":
            action_result,

        "verification":
            verification,

        "experience":
            experience,
    }


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--once",
        action="store_true",
    )

    parser.add_argument(
        "--continuous",
        action="store_true",
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=5.0,
    )

    parser.add_argument(
        "--execute",
        action="store_true",
        help="Enable authorized actions.",
    )

    parser.add_argument(
        "--model",
        default=
        "artifacts/hunterseeker_five_dataset_model.joblib",
    )

    parser.add_argument(
        "--action-model",
        default=
        "artifacts/action_outcome_model.joblib",
    )

    parser.add_argument(
        "--registry",
        default=
        "artifacts/model_registry.json",
    )

    parser.add_argument(
        "--experience-db",
        default=
        "artifacts/experience_memory.sqlite3",
    )

    parser.add_argument(
        "--retrain-every",
        type=int,
        default=100,
    )

    parser.add_argument(
        "--minimum-experiences",
        type=int,
        default=100,
    )

    args = parser.parse_args()

    engine = build_engine(
        args
    )

    while True:

        try:

            report = run_cycle(
                engine
            )

            detection = (
                report["detection"]
            )

            experience = (
                report["experience"]
            )

            print(
                "\n"
                "[CYCLE] "
                f"threat="
                f"{detection.threat_label} "
                f"prob="
                f"{detection.threat_probability:.4f} "
                f"action="
                f"{report['policy'].action} "
                f"simulated="
                f"{report['action_result'].simulated} "
                f"verified="
                f"{report['verification'].verified} "
                f"learning="
                f"{experience.learning_eligible} "
                f"reward="
                f"{experience.reward:.4f}"
            )

        except Exception as exc:

            print(
                "[ENGINE ERROR]",
                repr(exc),
            )

        if (
            args.once
            or
            not args.continuous
        ):
            break

        time.sleep(
            max(
                0.1,
                args.interval,
            )
        )


if __name__ == "__main__":
    raise SystemExit(
        main()
    )