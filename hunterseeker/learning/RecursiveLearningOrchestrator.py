from pathlib import Path
import json
from datetime import datetime, timezone


def register_perception_model(
    model_path,
    manifest_path,
    metrics,
):

    registry_path = Path(
        "artifacts/model_registry.json"
    )

    registry_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if registry_path.exists():

        try:

            registry = json.loads(
                registry_path.read_text(
                    encoding="utf-8"
                )
            )

        except Exception:

            registry = {}

    else:

        registry = {}

    registry.setdefault(
        "registry_version",
        "1.0"
    )

    registry.setdefault(
        "champion",
        {}
    )

    registry.setdefault(
        "candidates",
        []
    )

    model_entry = {

        "role":
            "perception",

        "stage":
            "V1",

        "path":
            str(model_path),

        "manifest":
            str(manifest_path),

        "metrics":
            metrics,

        "created_at":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "status":
            "champion",
    }

    registry["champion"][
        "perception"
    ] = model_entry

    registry_path.write_text(
        json.dumps(
            registry,
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )

    print(
        "[REGISTRY] "
        "V1 perception model registered."
    )