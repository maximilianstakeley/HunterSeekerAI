from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np

from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error


ACTIONS = [
    "do_nothing",
    "lower_priority",
    "isolate_process",
    "reclaim_temp_files",
]


class RewardModelTrainer:

    def __init__(
        self,
        experience_db,
        registry,
    ):

        self.experience_db = Path(
            experience_db
        )

        self.registry = Path(
            registry
        )

    def load_experiences(self):

        with sqlite3.connect(
            self.experience_db
        ) as conn:

            rows = conn.execute(
                """
                SELECT payload_json
                FROM experiences
                WHERE learning_eligible = 1
                """
            ).fetchall()

        results = []

        for row in rows:

            results.append(
                json.loads(row[0])
            )

        return results

    def feature_vector(
        self,
        experience,
        action,
    ):

        detection = (
            experience["detection"]
        )

        evidence = (
            experience["evidence"]
        )

        context = (
            experience["context"]
        )

        system = (
            experience["observation"]
            ["payload"]
            .get(
                "system",
                {},
            )
        )

        vector = [

            float(
                detection[
                    "threat_probability"
                ]
            ),

            float(
                detection[
                    "confidence"
                ]
            ),

            float(
                detection[
                    "uncertainty"
                ]
            ),

            float(
                len(
                    evidence[
                        "signals"
                    ]
                )
            ),

            float(
                evidence[
                    "persistence_score"
                ]
            ),

            float(
                context[
                    "temporal_features"
                ].get(
                    "anomaly_current",
                    0.0,
                )
            ),

            float(
                context[
                    "temporal_features"
                ].get(
                    "anomaly_delta",
                    0.0,
                )
            ),

            float(
                system.get(
                    "cpu_percent",
                    0.0,
                )
            ) / 100.0,

            float(
                system.get(
                    "memory_percent",
                    0.0,
                )
            ) / 100.0,

            float(
                system.get(
                    "disk_percent",
                    0.0,
                )
            ) / 100.0,
        ]

        vector.extend(
            1.0 if action == candidate else 0.0
            for candidate in ACTIONS
        )

        return vector

    def train_candidate(
        self,
        minimum_experiences=100,
    ):

        experiences = (
            self.load_experiences()
        )

        if len(experiences) < minimum_experiences:

            return {
                "trained": False,

                "reason":
                    "not enough verified experiences",

                "count":
                    len(experiences),
            }

        X = []
        y = []

        for experience in experiences:

            action = (
                experience[
                    "policy"
                ]["action"]
            )

            X.append(
                self.feature_vector(
                    experience,
                    action,
                )
            )

            y.append(
                float(
                    experience["reward"]
                )
            )

        X = np.asarray(
            X,
            dtype=float,
        )

        y = np.asarray(
            y,
            dtype=float,
        )

        (
            X_train,
            X_test,
            y_train,
            y_test,
        ) = train_test_split(
            X,
            y,
            test_size=0.20,
            random_state=42,
        )

        model = RandomForestRegressor(
            n_estimators=250,

            max_depth=10,

            min_samples_leaf=3,

            random_state=42,

            n_jobs=-1,
        )

        model.fit(
            X_train,
            y_train,
        )

        prediction = model.predict(
            X_test
        )

        mse = mean_squared_error(
            y_test,
            prediction,
        )

        candidate_path = Path(
            "artifacts/action_outcome_candidate.joblib"
        )

        joblib.dump(
            model,
            candidate_path,
        )

        return {
            "trained": True,

            "model":
                str(candidate_path),

            "validation_mse":
                float(mse),

            "experience_count":
                len(experiences),
        }