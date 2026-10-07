from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class ModelRegistry:

    def __init__(
        self,
        path,
    ):

        self.path = Path(path)

        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._initialize()

    def _initialize(self):

        if not self.path.exists():

            self._save(
                {
                    "registry_version": "1.0",

                    "champion": {},

                    "candidates": [],
                }
            )

    def _load(self):

        return json.loads(
            self.path.read_text(
                encoding="utf-8"
            )
        )

    def _save(self, data):

        self.path.write_text(
            json.dumps(
                data,
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )

    def register_candidate(
        self,
        role,
        model_path,
        metrics,
        dataset_version,
    ):

        data = self._load()

        entry = {
            "role": role,

            "path":
                str(model_path),

            "metrics":
                metrics,

            "dataset_version":
                dataset_version,

            "created_at":
                datetime.now(
                    timezone.utc
                ).isoformat(),

            "status":
                "candidate",
        }

        data["candidates"].append(
            entry
        )

        self._save(
            data
        )

        return entry

    def promote(
        self,
        role,
        candidate,
    ):

        data = self._load()

        candidate["status"] = (
            "champion"
        )

        data.setdefault(
            "champion",
            {}
        )[role] = candidate

        self._save(
            data
        )

    def champion(
        self,
        role,
    ):

        data = self._load()

        return (
            data
            .get("champion", {})
            .get(role)
        )