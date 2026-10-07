from __future__ import annotations


class ChampionChallenger:

    def __init__(
        self,
        minimum_gain=0.02,
    ):

        self.minimum_gain = (
            minimum_gain
        )

    def should_promote(
        self,
        champion_metric,
        candidate_metric,
        lower_is_better=True,
    ):

        if champion_metric is None:
            return True

        if lower_is_better:

            required = (
                champion_metric
                *
                (
                    1.0
                    -
                    self.minimum_gain
                )
            )

            return (
                candidate_metric
                <
                required
            )

        required = (
            champion_metric
            *
            (
                1.0
                +
                self.minimum_gain
            )
        )

        return (
            candidate_metric
            >
            required
        )