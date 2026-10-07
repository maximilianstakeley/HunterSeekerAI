from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from hunterseeker.core.contracts import (
    Experience,
)


class ExperienceStore:

    def __init__(
        self,
        database_path: Path,
    ):

        self.database_path = Path(
            database_path
        )

        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._initialize()

    def _connect(self):

        return sqlite3.connect(
            self.database_path
        )

    def _initialize(self):

        with self._connect() as conn:

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS experiences (
                    experience_id TEXT PRIMARY KEY,
                    timestamp_utc TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    reward REAL NOT NULL,
                    model_version TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    learning_eligible INTEGER NOT NULL
                )
                """
            )

            conn.commit()

    def insert(
        self,
        experience: Experience,
    ):

        payload = json.dumps(
            experience,
            default=lambda obj:
                obj.__dict__,
            sort_keys=True,
        )

        with self._connect() as conn:

            conn.execute(
                """
                INSERT OR REPLACE INTO experiences
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    experience.experience_id,

                    experience.timestamp_utc,

                    payload,

                    experience.reward,

                    experience.model_version,

                    experience.policy_version,

                    int(
                        experience.learning_eligible
                    ),
                ),
            )

            conn.commit()

    def count_eligible(self) -> int:

        with self._connect() as conn:

            row = conn.execute(
                """
                SELECT COUNT(*)
                FROM experiences
                WHERE learning_eligible = 1
                """
            ).fetchone()

        return int(row[0])

    def load_eligible(self):

        results = []

        with self._connect() as conn:

            rows = conn.execute(
                """
                SELECT payload_json
                FROM experiences
                WHERE learning_eligible = 1
                ORDER BY timestamp_utc
                """
            ).fetchall()

        for row in rows:

            try:
                results.append(
                    json.loads(row[0])
                )

            except json.JSONDecodeError:
                continue

        return results