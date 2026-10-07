from __future__ import annotations

import platform
import socket
import os
import time

try:
    import psutil
except ImportError:
    psutil = None

from hunterseeker.core.contracts import (
    Observation,
    RuntimeConfig,
    stable_id,
    utc_now,
)


class ObservationEngine:

    def __init__(
        self,
        config: RuntimeConfig,
    ) -> None:

        self.config = config

        self.sequence = 0

    def observe(self) -> Observation:

        self.sequence += 1

        payload = {
            "host": {
                "hostname": socket.gethostname(),
                "platform": platform.platform(),
                "pid": os.getpid(),
            },

            "system": {},

            "network": {},

            "processes": [],
        }

        if psutil is not None:

            vm = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            net = psutil.net_io_counters()

            payload["system"] = {
                "cpu_percent":
                    float(
                        psutil.cpu_percent(
                            interval=0.0
                        )
                    ),

                "memory_percent":
                    float(vm.percent),

                "disk_percent":
                    float(disk.percent),

                "process_count":
                    float(len(psutil.pids())),

                "network_bytes_sent":
                    float(net.bytes_sent),

                "network_bytes_recv":
                    float(net.bytes_recv),

                "timestamp":
                    time.time(),
            }

            for proc in psutil.process_iter(
                ["pid", "name", "cpu_percent", "memory_percent"]
            ):

                try:
                    payload["processes"].append(
                        proc.info
                    )

                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                ):
                    continue

        observation_id = stable_id(
            {
                "sequence": self.sequence,
                "payload": payload,
            }
        )

        return Observation(
            observation_id=observation_id,
            timestamp_utc=utc_now(),
            source="V0",
            payload=payload,
            provenance={
                "psutil_available":
                    psutil is not None
            },
        )