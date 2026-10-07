#!/usr/bin/env python3
"""
HunterSeekerAI - PreprocessData.py

Layered five-dataset defensive network anomaly pipeline.

The implementation is separated into explicit boundaries:
    Layer 1: observation/acquisition + provenance
    Layer 2: canonical behavioral representation + data-quality controls
    Layer 3: threat detection + cross-dataset evaluation
    Layer 4: adaptive decision/action/verification loop (scaffold only)

Target datasets
---------------
1. UNSW-NB15
2. CIC-IDS2017
3. CSE-CIC-IDS2018
4. TON-IoT (network-flow subset when using the configured public mirror)
5. BoT-IoT

Design
------
DATA SOURCE -> DATASET-SPECIFIC DISCOVERY -> STREAMING READER
-> CANONICAL SCHEMA -> BOUNDED DATASET/CLASS RESERVOIRS
-> EQUAL DATASET + CLASS SAMPLING -> TRAIN/VALIDATION SPLIT
-> IMPUTER + SCALER FIT ON TRAINING ONLY -> INCREMENTAL CLASSIFIER
-> PER-DATASET + GLOBAL VALIDATION METRICS -> MODEL + MANIFEST

Important
---------
- The default remote mode is "auto": try an official public source first,
  then fall back to a configured public mirror when the official provider
  requires interactive authentication or the page is not directly streamable.
- Public mirrors/subsets are recorded in the manifest. The code does not label
  a mirror as the original full official corpus.
- Training is blocked unless all five requested datasets contribute both
  benign and attack samples after normalization.
- Balancing happens BEFORE model fitting. A very large dataset cannot dominate
  the classifier merely because it contains more raw rows.
- No offensive/execution functionality is included. This program is solely a
  defensive data ingestion and supervised anomaly/malware classifier trainer.

Typical usage
-------------
Five-dataset smoke test (network access may be required for remote sources):

    python PreprocessData.py --source-mode auto --train --stats \
        --sample-per-dataset-class 10000

Start with a small bounded run:

    python PreprocessData.py --source-mode public --train --stats \
        --sample-per-dataset-class 2000 --chunk-size 20000

Local files:

    python PreprocessData.py --input unsw=/path/to/UNSW.csv \
        --input cic2017=/path/to/CIC.csv \
        --input cic2018=/path/to/CIC2018.csv \
        --input toniot=/path/to/TON.csv \
        --input botiot=/path/to/BOT.csv \
        --train --stats

Self-test (no network, creates temporary synthetic files):

    python PreprocessData.py --self-test

Dependencies
------------
Required:
    pandas, numpy, scikit-learn, requests, beautifulsoup4, joblib

Optional remote-provider helpers:
    kagglehub            (public Kaggle mirrors)
    huggingface_hub      (public TON-IoT network mirror)
    pyarrow              (Parquet inputs)

The program gives an explicit installation message when an optional provider
library is missing instead of silently skipping a requested dataset.
"""

from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import html
import io
import json
import math
import os
import random
import re
import signal
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, unquote, urljoin, urlparse
import xml.etree.ElementTree as ET

import numpy as np
import pandas as pd
import requests
from bs4 import BeautifulSoup
from sklearn.impute import SimpleImputer
from sklearn.base import clone
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.compose import ColumnTransformer
from sklearn.inspection import permutation_importance
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, RobustScaler
from hunterseeker_architecture import ARCHITECTURE_LAYERS, ARCHITECTURE_VERSION


# ---------------------------------------------------------------------------
# Constants and configuration
# ---------------------------------------------------------------------------

PIPELINE_VERSION = "five-dataset-orchestrator-v7-layered"
DEFAULT_MODEL_PATH = Path("artifacts/hunterseeker_five_dataset_model.joblib")
DEFAULT_MANIFEST_PATH = Path("artifacts/hunterseeker_five_dataset_run_manifest.json")
DEFAULT_CHUNK_SIZE = 20_000
DEFAULT_SAMPLE_PER_DATASET_CLASS = 10_000
DEFAULT_VALIDATION_FRACTION = 0.20
DEFAULT_RANDOM_STATE = 42
DEFAULT_TRAIN_BATCH_SIZE = 4096

DEFAULT_HTTP_TIMEOUT = (20, 120)

TARGET_DATASETS = (
    "unsw",
    "cic2017",
    "cic2018",
    "toniot",
    "botiot",
)

DATASET_DISPLAY_NAMES = {
    "unsw": "UNSW-NB15",
    "cic2017": "CIC-IDS2017",
    "cic2018": "CSE-CIC-IDS2018",
    "toniot": "TON-IoT",
    "botiot": "BoT-IoT",
}

# Official project pages. These are recorded in provenance and used for source
# discovery. The SharePoint URLs are intentionally not treated as guaranteed
# anonymous file endpoints.
OFFICIAL_SOURCES: Dict[str, Dict[str, Any]] = {
    "unsw": {
        "page": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        "sharepoint": (
            "https://unsw-my.sharepoint.com/:f:/g/personal/"
            "z5025758_ad_unsw_edu_au/EnuQZZn3XuNBjgfcUu4DIVMBLCHyoLHqOswirpOQifr1ag"
        ),
    },
    "cic2017": {
        "page": "https://www.unb.ca/cic/datasets/ids-2017.html",
        # Prefer these archive names when an intermediary download page is found.
        "preferred_names": (
            "MachineLearningCSV.zip",
            "GeneratedLabelledFlows.zip",
        ),
    },
    "cic2018": {
        "page": "https://www.unb.ca/cic/datasets/ids-2018.html",
        "s3_bucket": "cse-cic-ids2018",
        "s3_region": "ca-central-1",
        "s3_prefix": "Processed Traffic Data for ML Algorithms/",
    },
    "toniot": {
        "page": "https://research.unsw.edu.au/projects/toniot-datasets",
        "sharepoint": None,
    },
    "botiot": {
        "page": "https://research.unsw.edu.au/projects/bot-iot-dataset",
        "sharepoint": None,
    },
}

# Public mirrors found to be usable through their public provider APIs.
# These are intentionally represented as mirrors/subsets in provenance.
PUBLIC_SOURCES: Dict[str, Dict[str, Any]] = {
    "unsw": {
        "provider": "kagglehub",
        "repo": "dhoogla/unswnb15",
        "kind": "public_mirror",
        "scope": "public Kaggle mirror",
    },
    "cic2017": {
        "provider": "kagglehub",
        "repo": "dhoogla/cicids2017",
        "kind": "public_mirror",
        "scope": "public Kaggle mirror",
    },
    "cic2018": {
        "provider": "kagglehub",
        "repo": "dhoogla/csecicids2018",
        "kind": "public_mirror",
        "scope": "public Kaggle mirror",
    },
    "toniot": {
        "provider": "huggingface_hub",
        "repo": "codymlewis/TON_IoT_network",
        "kind": "public_subset_mirror",
        "scope": "public TON-IoT network-flow subset/mirror",
    },
    "botiot": {
        "provider": "kagglehub",
        "repo_5pct": "vigneshvenkateswaran/bot-iot-5-data",
        "repo_full": "vigneshvenkateswaran/bot-iot",
        "kind": "public_mirror_or_subset",
        "scope_5pct": "public 5% BoT-IoT distribution",
        "scope_full": "public BoT-IoT distribution",
    },
}

# Canonical numeric feature set. Dataset-specific aliases are mapped into this
# fixed schema. Keeping the common schema small helps make cross-dataset
# training stable and prevents source-specific column explosion.
CANONICAL_FEATURES = [
    "duration",
    "source_port",
    "destination_port",
    "bytes_in",
    "bytes_out",
    "packets_in",
    "packets_out",
    "missed_bytes",
    "source_ip_bytes",
    "destination_ip_bytes",
    "cpu_usage",
    "memory_usage",
    "disk_usage",
    "network_usage",
    "process_count",
    "temperature",
    "power",
]

CATEGORICAL_MODEL_FEATURES = ["protocol", "service", "source_port_class", "destination_port_class"]
DERIVED_NUMERIC_FEATURES = [
    "total_bytes",
    "total_packets",
    "bytes_per_second",
    "packets_per_second",
    "mean_packet_size",
    "byte_direction_ratio",
    "packet_direction_ratio",
    "source_byte_fraction",
]
MODEL_NUMERIC_FEATURES = list(CANONICAL_FEATURES) + DERIVED_NUMERIC_FEATURES
NONNEGATIVE_FEATURES = [
    "duration", "bytes_in", "bytes_out", "packets_in", "packets_out",
    "missed_bytes", "source_ip_bytes", "destination_ip_bytes", "process_count",
]

METADATA_COLUMNS = {
    "timestamp",
    "source",
    "destination",
    "protocol",
    "service",
    "label_raw",
    "attack_type",
    "dataset",
    "row_id",
}

LABEL_ALIASES = {
    "label": [
        "label",
        "class",
        "target",
        "attack",
        "is_attack",
        "anomaly",
        "binary_label",
    ],
    "attack_type": [
        "attack_type",
        "attacktype",
        "attack_category",
        "category",
        "attack_name",
        "subcategory",
        "subclass",
        "detailed_label",
        "detailedlabel",
        "attack_cat",
        "type",
    ],
}

COLUMN_ALIASES: Dict[str, List[str]] = {
    "timestamp": [
        "timestamp",
        "time",
        "ts",
        "datetime",
        "date_time",
        "flow_start",
        "start_time",
    ],
    "source": [
        "source",
        "src",
        "src_ip",
        "source_ip",
        "source_address",
        "id_orig_h",
        "id_orig_addr",
        "srcaddr",
        "src_addr",
    ],
    "destination": [
        "destination",
        "dst",
        "dst_ip",
        "destination_ip",
        "destination_address",
        "id_resp_h",
        "id_resp_addr",
        "dstaddr",
        "dst_addr",
    ],
    "protocol": [
        "protocol",
        "proto",
        "transport_protocol",
        "ip_proto",
        "protocol_type",
    ],
    "service": [
        "service",
        "application",
        "app_proto",
        "service_type",
    ],
    "source_port": [
        "source_port",
        "src_port",
        "sport",
        "sourceport",
        "id_orig_p",
        "id_orig_port",
    ],
    "destination_port": [
        "destination_port",
        "dst_port",
        "dport",
        "destinationport",
        "id_resp_p",
        "id_resp_port",
    ],
    "duration": [
        "duration",
        "flow_duration",
        "dur",
        "connection_duration",
    ],
    "bytes_in": [
        "bytes_in",
        "in_bytes",
        "source_bytes",
        "src_bytes",
        "sbytes",
        "orig_bytes",
        "forward_bytes",
        "total_length_of_fwd_packets",
        "totlen_fwd_pkts",
        "fwd_bytes",
    ],
    "bytes_out": [
        "bytes_out",
        "out_bytes",
        "destination_bytes",
        "dst_bytes",
        "dbytes",
        "resp_bytes",
        "backward_bytes",
        "total_length_of_bwd_packets",
        "totlen_bwd_pkts",
        "bwd_bytes",
    ],
    "packets_in": [
        "packets_in",
        "in_packets",
        "source_packets",
        "src_packets",
        "spkts",
        "orig_pkts",
        "total_fwd_packets",
        "fwd_pkts",
    ],
    "packets_out": [
        "packets_out",
        "out_packets",
        "destination_packets",
        "dst_packets",
        "dpkts",
        "resp_pkts",
        "total_backward_packets",
        "bwd_pkts",
    ],
    "missed_bytes": [
        "missed_bytes",
        "missed",
        "missedbytes",
    ],
    "source_ip_bytes": [
        "source_ip_bytes",
        "src_ip_bytes",
        "orig_ip_bytes",
        "source_ipbytes",
    ],
    "destination_ip_bytes": [
        "destination_ip_bytes",
        "dst_ip_bytes",
        "resp_ip_bytes",
        "destination_ipbytes",
    ],
    "cpu_usage": [
        "cpu_usage",
        "cpu",
        "cpu_percent",
        "cpu_utilization",
        "cpu_usage_percent",
        "processor_usage",
        "processor_utilization",
    ],
    "memory_usage": [
        "memory_usage",
        "memory",
        "memory_percent",
        "memory_utilization",
        "ram_usage",
        "ram_percent",
        "mem_usage",
        "mem_percent",
    ],
    "disk_usage": [
        "disk_usage",
        "disk",
        "disk_percent",
        "disk_utilization",
        "disk_usage_percent",
    ],
    "network_usage": [
        "network_usage",
        "network",
        "network_utilization",
        "network_percent",
        "network_usage_percent",
        "network_load",
    ],
    "process_count": [
        "process_count",
        "processes",
        "process_count_total",
        "num_processes",
        "number_of_processes",
        "process_num",
    ],
    "temperature": [
        "temperature",
        "temp",
        "temperature_c",
        "temperature_celsius",
        "cpu_temperature",
        "device_temperature",
    ],
    "power": [
        "power",
        "power_usage",
        "power_consumption",
        "power_watts",
        "watts",
        "energy",
        "energy_consumption",
    ],
}

# A few dataset-specific aliases/derived mappings that are common in the
# source families. They are applied after generic aliases.
DATASET_ALIASES: Dict[str, Dict[str, List[str]]] = {
    "unsw": {
        "attack_type": ["attack_cat"],
        "bytes_in": ["sbytes"],
        "bytes_out": ["dbytes"],
        "packets_in": ["spkts"],
        "packets_out": ["dpkts"],
    },
    "cic2017": {
        "attack_type": ["label"],
        "duration": ["flow_duration"],
        "packets_in": ["tot_fwd_pkts"],
        "packets_out": ["tot_bwd_pkts"],
        "bytes_in": ["totlen_fwd_pkts"],
        "bytes_out": ["totlen_bwd_pkts"],
    },
    "cic2018": {
        "attack_type": ["label"],
    },
    "toniot": {
        "attack_type": ["type"],
        "bytes_in": ["src_bytes"],
        "bytes_out": ["dst_bytes"],
        "packets_in": ["src_pkts"],
        "packets_out": ["dst_pkts"],
    },
    "botiot": {
        "attack_type": ["category", "subcategory"],
    },
}

BENIGN_TOKENS = {
    "benign",
    "normal",
    "norm",
    "normaltraffic",
    "normal_traffic",
    "background",
    "benigntraffic",
    "benign_traffic",
    "0",
    "0.0",
    "false",
    "no",
    "no_attack",
    "noattack",
}

UNKNOWN_TOKENS = {
    "",
    "nan",
    "none",
    "null",
    "unknown",
    "-",
    "?",
}

STOP_REQUESTED = False


# ---------------------------------------------------------------------------
# Exceptions / dataclasses
# ---------------------------------------------------------------------------


class PipelineInterrupted(Exception):
    """Raised after Ctrl+C at a safe processing boundary."""


class ProviderAccessError(RuntimeError):
    """A requested source cannot currently be accessed automatically."""


@dataclass
class SourceInfo:
    dataset: str
    mode: str
    provider: str
    reference: str
    scope: str
    files: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class DatasetStats:
    dataset: str
    source_provider: str = ""
    source_reference: str = ""
    source_scope: str = ""
    rows_seen: int = 0
    rows_labeled: int = 0
    benign_seen: int = 0
    attack_seen: int = 0
    unknown_seen: int = 0
    batches: int = 0
    reservoir_benign: int = 0
    reservoir_attack: int = 0
    train_benign: int = 0
    train_attack: int = 0
    validation_benign: int = 0
    validation_attack: int = 0
    exact_duplicate_rows_in_pool: int = 0
    near_duplicate_rows_in_pool: int = 0
    feature_source_map: Dict[str, str] = field(default_factory=dict)
    feature_present_rows: Dict[str, int] = field(default_factory=dict)
    feature_missing_rows: Dict[str, int] = field(default_factory=dict)
    unused_raw_columns: Dict[str, int] = field(default_factory=dict)
    label_values: Dict[str, int] = field(default_factory=dict)
    unknown_label_values: Dict[str, int] = field(default_factory=dict)
    attack_type_values: Dict[str, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    @property
    def attack_rate_seen(self) -> float:
        return self.attack_seen / self.rows_labeled if self.rows_labeled else 0.0


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


def request_stop(signum: int, frame: object) -> None:
    global STOP_REQUESTED
    STOP_REQUESTED = True
    print("\n[STOP] Interrupt received. Finishing the current safe boundary...")


def check_stop() -> None:
    if STOP_REQUESTED:
        raise PipelineInterrupted()


def normalize_name(value: object) -> str:
    value = html.unescape(str(value).strip().lower())
    value = re.sub(r"[^a-z0-9]+", "_", value)
    return re.sub(r"_+", "_", value).strip("_")


def clean_string(value: object) -> str:
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except Exception:
        pass
    return html.unescape(str(value)).strip()


def stable_code(value: object, buckets: int = 128) -> float:
    """Stable numeric code for categorical values; independent of Python hash randomization."""
    text = clean_string(value).lower()
    if not text:
        return 0.0
    digest = hashlib.blake2b(text.encode("utf-8"), digest_size=8).digest()
    integer = int.from_bytes(digest, byteorder="big", signed=False)
    return float((integer % buckets) + 1)


def safe_float_series(series: pd.Series) -> pd.Series:
    """Convert a mixed numeric column to finite float values with NaN for failures."""
    if pd.api.types.is_numeric_dtype(series):
        out = pd.to_numeric(series, errors="coerce")
    else:
        text = series.astype(str).str.strip()
        # Remove common thousands separators but do not alter decimal points.
        text = text.str.replace(",", "", regex=False)
        out = pd.to_numeric(text, errors="coerce")
    return out.replace([np.inf, -np.inf], np.nan).astype("float64")


def parse_bool_or_numeric_label(value: object) -> Optional[int]:
    """Strict binary label parser: unknown text is unknown, not automatically attack."""
    token = clean_string(value).lower()
    if token in UNKNOWN_TOKENS:
        return None
    if token in BENIGN_TOKENS:
        return 0
    try:
        number = float(token)
        if math.isfinite(number):
            if number == 0:
                return 0
            if number == 1:
                return 1
    except Exception:
        pass
    attack_words = (
        "attack", "malicious", "anomaly", "bot", "dos", "ddos", "scan",
        "exploit", "injection", "backdoor", "ransom", "trojan", "brute",
        "patator", "heartbleed", "slowloris", "hulk", "goldeneye", "webattack",
        "infiltration", "sql", "xss", "ftp", "ssh", "mirai", "gafgyt", "flood",
        "recon", "worm", "credential", "password", "malware", "botnet",
    )
    if any(word in token for word in attack_words):
        return 1
    return None


def classify_series(series: pd.Series) -> pd.Series:
    return series.map(parse_bool_or_numeric_label).astype("Float64")


def canonical_column_map(frame: pd.DataFrame) -> Dict[str, str]:
    return {normalize_name(col): col for col in frame.columns}


def find_column(
    frame: pd.DataFrame,
    aliases: Sequence[str],
    normalized_map: Optional[Dict[str, str]] = None,
) -> Optional[str]:
    mapping = normalized_map or canonical_column_map(frame)
    for alias in aliases:
        name = normalize_name(alias)
        if name in mapping:
            return mapping[name]
    return None


def infer_label_columns(frame: pd.DataFrame, dataset: str) -> Tuple[Optional[str], Optional[str]]:
    mapping = canonical_column_map(frame)

    label_col: Optional[str] = None
    attack_type_col: Optional[str] = None

    for alias in LABEL_ALIASES["label"]:
        candidate = mapping.get(normalize_name(alias))
        if candidate is not None:
            label_col = candidate
            break

    dataset_aliases = DATASET_ALIASES.get(dataset, {})
    attack_aliases = []
    attack_aliases.extend(dataset_aliases.get("attack_type", []))
    attack_aliases.extend(LABEL_ALIASES["attack_type"])

    # Preserve source attack-family text whenever possible.
    for alias in attack_aliases:
        candidate = mapping.get(normalize_name(alias))
        if candidate is not None:
            attack_type_col = candidate
            break

    return label_col, attack_type_col


def choose_alias(frame: pd.DataFrame, dataset: str, canonical: str) -> Optional[str]:
    mapping = canonical_column_map(frame)
    aliases: List[str] = []
    aliases.extend(DATASET_ALIASES.get(dataset, {}).get(canonical, []))
    aliases.extend(COLUMN_ALIASES.get(canonical, []))
    for alias in aliases:
        candidate = mapping.get(normalize_name(alias))
        if candidate is not None:
            return candidate
    return None


def parse_timestamp(series: pd.Series) -> pd.Series:
    if pd.api.types.is_numeric_dtype(series):
        numeric = pd.to_numeric(series, errors="coerce")
        # Dataset timestamps are often Unix seconds. Use the magnitude to
        # choose seconds rather than accidentally interpreting them as ns.
        median = numeric.dropna().abs().median() if numeric.notna().any() else np.nan
        if pd.notna(median) and median > 1e8:
            return pd.to_datetime(numeric, unit="s", errors="coerce", utc=True)
    return pd.to_datetime(series, errors="coerce", utc=True)


def extract_attack_type(
    frame: pd.DataFrame,
    dataset: str,
    label_col: Optional[str],
    attack_type_col: Optional[str],
    anomaly: pd.Series,
) -> pd.Series:
    if attack_type_col is not None:
        attack_type = frame[attack_type_col].astype("string").fillna("unknown")
    elif label_col is not None:
        attack_type = frame[label_col].astype("string").fillna("unknown")
    else:
        attack_type = pd.Series("unknown", index=frame.index, dtype="string")

    # For textual labels such as CIC's `Label`, benign stays benign while an
    # attack retains its original attack family/name.
    attack_type = attack_type.astype(str).map(clean_string)
    attack_type = attack_type.where(attack_type != "", "unknown")
    benign_mask = anomaly.notna() & anomaly.eq(0)
    attack_type = attack_type.where(~benign_mask, "benign")
    return attack_type.astype("string")


# ---------------------------------------------------------------------------
# Schema normalization
# ---------------------------------------------------------------------------


def build_schema_audit(frame: pd.DataFrame, dataset: str) -> Dict[str, Any]:
    mapping = canonical_column_map(frame)
    used_columns: set[str] = set()
    feature_source_map: Dict[str, Optional[str]] = {}
    for feature in CANONICAL_FEATURES:
        source_col = choose_alias(frame, dataset, feature)
        feature_source_map[feature] = source_col
        if source_col is not None:
            used_columns.add(source_col)

    label_col, attack_type_col = infer_label_columns(frame, dataset)
    for column in (label_col, attack_type_col):
        if column is not None:
            used_columns.add(column)
    for canonical in ("timestamp", "source", "destination", "protocol", "service"):
        source_col = choose_alias(frame, dataset, canonical)
        if source_col is not None:
            used_columns.add(source_col)

    unused = [str(c) for c in frame.columns if str(c) not in used_columns]
    return {
        "feature_source_map": {k: v for k, v in feature_source_map.items()},
        "used_columns": sorted(used_columns),
        "unused_columns": sorted(unused),
        "label_column": label_col,
        "attack_type_column": attack_type_col,
        "raw_columns": [str(c) for c in frame.columns],
    }


def _attack_type_anomaly_fallback(attack_type: pd.Series, anomaly: pd.Series) -> pd.Series:
    fallback = attack_type.map(parse_bool_or_numeric_label)
    missing = anomaly.isna()
    anomaly = anomaly.copy()
    anomaly.loc[missing] = fallback.loc[missing]
    return anomaly.astype("Float64")


def _port_class(value: object) -> str:
    number = safe_float_series(pd.Series([value])).iloc[0]
    if pd.isna(number):
        return "unknown"
    number = float(number)
    if number <= 1023:
        return "well_known"
    if number <= 49151:
        return "registered"
    return "ephemeral"


def normalize_frame(frame: pd.DataFrame, dataset: str) -> pd.DataFrame:
    """Map raw data to an explicit cross-dataset behavioral representation."""
    check_stop()
    if frame.empty:
        return pd.DataFrame()

    frame = frame.copy()
    frame.columns = [str(c).strip() for c in frame.columns]
    audit = build_schema_audit(frame, dataset)

    label_col, attack_type_col = infer_label_columns(frame, dataset)
    if label_col is None:
        raise ValueError(
            f"{DATASET_DISPLAY_NAMES[dataset]}: no usable label column found. "
            f"Columns include: {list(frame.columns)[:20]}"
        )

    anomaly = classify_series(frame[label_col])
    attack_type = extract_attack_type(frame, dataset, label_col, attack_type_col, anomaly)
    anomaly = _attack_type_anomaly_fallback(attack_type, anomaly)
    attack_type = attack_type.where(anomaly.fillna(0).astype(float) != 0, "benign")

    out = pd.DataFrame(index=frame.index)
    ts_col = choose_alias(frame, dataset, "timestamp")
    src_col = choose_alias(frame, dataset, "source")
    dst_col = choose_alias(frame, dataset, "destination")
    protocol_col = choose_alias(frame, dataset, "protocol")
    service_col = choose_alias(frame, dataset, "service")

    out["timestamp"] = parse_timestamp(frame[ts_col]) if ts_col else pd.NaT
    out["source"] = frame[src_col].astype("string") if src_col else ""
    out["destination"] = frame[dst_col].astype("string") if dst_col else ""
    out["protocol"] = frame[protocol_col].astype("string") if protocol_col else ""
    out["service"] = frame[service_col].astype("string") if service_col else ""

    for feature in CANONICAL_FEATURES:
        source_col = choose_alias(frame, dataset, feature)
        if source_col is None:
            out[feature] = np.nan
        else:
            out[feature] = safe_float_series(frame[source_col])

    out["anomaly"] = anomaly
    out["label_raw"] = frame[label_col].astype("string").fillna("unknown")
    out["attack_type"] = attack_type.astype("string")
    out["dataset"] = dataset
    out.attrs["schema_audit"] = audit
    return out.reset_index(drop=True)


def feature_frame(frame: pd.DataFrame) -> pd.DataFrame:
    return frame[CANONICAL_FEATURES].copy()


def model_feature_frame(frame: pd.DataFrame) -> pd.DataFrame:
    """Build a dataset-independent behavioral feature frame without source identifiers."""
    out = frame.copy()
    for feature in MODEL_NUMERIC_FEATURES:
        if feature not in out:
            out[feature] = np.nan

    out["total_bytes"] = out["bytes_in"].fillna(0) + out["bytes_out"].fillna(0)
    out["total_packets"] = out["packets_in"].fillna(0) + out["packets_out"].fillna(0)
    denom_time = out["duration"].clip(lower=1e-9)
    denom_packets = out["total_packets"].clip(lower=1.0)
    out["bytes_per_second"] = out["total_bytes"] / denom_time
    out["packets_per_second"] = out["total_packets"] / denom_time
    out["mean_packet_size"] = out["total_bytes"] / denom_packets
    out["byte_direction_ratio"] = out["bytes_in"] / (out["bytes_out"].abs() + 1.0)
    out["packet_direction_ratio"] = out["packets_in"] / (out["packets_out"].abs() + 1.0)
    out["source_byte_fraction"] = out["bytes_in"] / (out["total_bytes"] + 1.0)
    out["source_port_class"] = out["source_port"].map(_port_class)
    out["destination_port_class"] = out["destination_port"].map(_port_class)

    for column in NONNEGATIVE_FEATURES + DERIVED_NUMERIC_FEATURES:
        if column in out:
            series = pd.to_numeric(out[column], errors="coerce")
            finite = series.replace([np.inf, -np.inf], np.nan)
            nonnegative = finite.where(finite >= 0)
            # Log transform is deterministic and reduces heavy-tailed flow-scale differences.
            out[column] = np.log1p(nonnegative)

    return out[MODEL_NUMERIC_FEATURES + CATEGORICAL_MODEL_FEATURES].copy()


# ---------------------------------------------------------------------------
# Local file streaming
# ---------------------------------------------------------------------------


def detect_delimiter(sample: str) -> str:
    candidates = ["|", ",", "\t", ";"]
    scores: Dict[str, int] = {}
    for delimiter in candidates:
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters="|,\t;")
            # Favor the detected delimiter if it is one of our choices.
            if dialect.delimiter == delimiter:
                scores[delimiter] = scores.get(delimiter, 0) + 100
        except csv.Error:
            pass
        scores[delimiter] = scores.get(delimiter, 0) + sample.count(delimiter)

    return max(candidates, key=lambda value: scores[value])


def validate_local_input(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"Dataset file not found: {path}")
    if not path.is_file():
        raise ValueError(f"Dataset input is not a file: {path}")
    lower = path.name.lower()
    if not lower.endswith((".csv", ".csv.gz", ".gz", ".zip", ".parquet", ".pq")):
        raise ValueError(
            f"Unsupported input {path.name}. Supported formats: CSV, CSV.GZ, GZ, ZIP, Parquet."
        )


def stream_csv_file(
    path_or_handle: Any,
    *,
    chunk_size: int,
    source_name: str,
    compression: Optional[str] = None,
) -> Iterator[pd.DataFrame]:
    # For local files, inspect a small sample to determine whether the source is
    # comma-, pipe-, tab-, or semicolon-delimited.
    if isinstance(path_or_handle, (str, Path)):
        open_target = open(path_or_handle, "rb")
        should_close = True
    else:
        open_target = path_or_handle
        should_close = False

    try:
        raw = open_target.read(65_536)
        if hasattr(open_target, "seek"):
            try:
                open_target.seek(0)
            except Exception:
                pass
        sample = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
        delimiter = detect_delimiter(sample)
        print(f"[READ] {source_name} delimiter={delimiter!r}")

        reader = pd.read_csv(
            open_target if not isinstance(path_or_handle, (str, Path)) else path_or_handle,
            sep=delimiter,
            chunksize=chunk_size,
            low_memory=False,
            compression=compression,
            on_bad_lines="warn",
        )
        for chunk in reader:
            check_stop()
            yield chunk
    finally:
        if should_close:
            open_target.close()


def stream_parquet(path: Path, *, chunk_size: int, source_name: str) -> Iterator[pd.DataFrame]:
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise ProviderAccessError(
            "Parquet input requires pyarrow. Install with: pip install pyarrow"
        ) from exc

    parquet_file = pq.ParquetFile(path)
    for batch in parquet_file.iter_batches(batch_size=chunk_size):
        check_stop()
        yield batch.to_pandas()


def stream_zip(path: Path, *, chunk_size: int, source_name: str) -> Iterator[pd.DataFrame]:
    with zipfile.ZipFile(path, "r") as archive:
        members = [
            info for info in archive.infolist()
            if not info.is_dir()
            and info.filename.lower().endswith((".csv", ".csv.gz", ".gz", ".parquet", ".pq"))
        ]
        if not members:
            raise ValueError(f"No supported dataset files found inside {path}")

        for info in members:
            check_stop()
            member_name = info.filename
            print(f"[ZIP] {path.name}!{member_name}")
            lower = member_name.lower()
            with archive.open(info, "r") as member:
                if lower.endswith((".parquet", ".pq")):
                    # pyarrow needs a file-like seekable source for some zip
                    # members. Copy only this member to a NamedTemporaryFile.
                    with tempfile.NamedTemporaryFile(suffix=".parquet") as tmp:
                        tmp.write(member.read())
                        tmp.flush()
                        yield from stream_parquet(
                            Path(tmp.name),
                            chunk_size=chunk_size,
                            source_name=f"{source_name}!{member_name}",
                        )
                else:
                    compression = "gzip" if lower.endswith((".csv.gz", ".gz")) else None
                    if compression == "gzip":
                        import gzip
                        with gzip.GzipFile(fileobj=member, mode="rb") as gz:
                            yield from stream_csv_file(
                                gz,
                                chunk_size=chunk_size,
                                source_name=f"{source_name}!{member_name}",
                            )
                    else:
                        # zip member is a binary stream. read_csv can consume it.
                        yield from stream_csv_file(
                            member,
                            chunk_size=chunk_size,
                            source_name=f"{source_name}!{member_name}",
                        )


def stream_local_path(path: Path, *, chunk_size: int, source_name: str) -> Iterator[pd.DataFrame]:
    validate_local_input(path)
    lower = path.name.lower()
    if lower.endswith(".zip"):
        yield from stream_zip(path, chunk_size=chunk_size, source_name=source_name)
    elif lower.endswith((".parquet", ".pq")):
        yield from stream_parquet(path, chunk_size=chunk_size, source_name=source_name)
    elif lower.endswith((".csv.gz", ".gz")):
        yield from stream_csv_file(
            path,
            chunk_size=chunk_size,
            source_name=source_name,
            compression="gzip",
        )
    else:
        yield from stream_csv_file(path, chunk_size=chunk_size, source_name=source_name)


def iter_files_recursively(root: Path) -> Iterator[Path]:
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name.lower().endswith(
            (".csv", ".csv.gz", ".gz", ".zip", ".parquet", ".pq")
        ):
            yield path


# ---------------------------------------------------------------------------
# HTTP / official-source discovery
# ---------------------------------------------------------------------------


def make_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({
        "User-Agent": "HunterSeekerAI/1.0 (+defensive-dataset-ingestion)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    return session


def response_looks_like_login(response: requests.Response) -> bool:
    content_type = response.headers.get("content-type", "").lower()
    final_url = response.url.lower()
    if "login" in final_url or "signin" in final_url or "microsoftonline" in final_url:
        return True
    if "text/html" in content_type:
        sample = response.text[:100_000].lower()
        markers = (
            "sign in",
            "sign-in",
            "login.microsoftonline.com",
            "your account",
            "we need to verify",
        )
        return any(marker in sample for marker in markers)
    return False


def stream_remote_csv(
    url: str,
    *,
    session: requests.Session,
    chunk_size: int,
    source_name: str,
) -> Iterator[pd.DataFrame]:
    response = session.get(url, stream=True, timeout=DEFAULT_HTTP_TIMEOUT, allow_redirects=True)
    response.raise_for_status()
    if response_looks_like_login(response):
        response.close()
        raise ProviderAccessError(f"{source_name}: provider returned an authentication/login page")

    content_type = response.headers.get("content-type", "").lower()
    if "text/html" in content_type:
        response.close()
        raise ProviderAccessError(f"{source_name}: expected data but received HTML")

    # pandas can consume response.raw. It needs a binary, seekless-compatible
    # stream for CSV chunking, which requests provides.
    response.raw.decode_content = True
    try:
        first = response.raw.read(65_536)
        if hasattr(response.raw, "seek"):
            try:
                response.raw.seek(0)
            except Exception:
                pass
        # urllib3 response.raw is normally non-seekable. If we cannot rewind,
        # download the small prefix plus the remainder to a temp file so the
        # delimiter can still be detected safely.
        if not hasattr(response.raw, "seek") or not response.raw.seekable():
            with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
                temp_path = Path(tmp.name)
                tmp.write(first)
                for block in response.iter_content(chunk_size=1024 * 1024):
                    if block:
                        tmp.write(block)
            response.close()
            try:
                yield from stream_csv_file(
                    temp_path,
                    chunk_size=chunk_size,
                    source_name=source_name,
                )
            finally:
                temp_path.unlink(missing_ok=True)
            return

        delimiter = detect_delimiter(first.decode("utf-8", errors="replace"))
        reader = pd.read_csv(
            response.raw,
            sep=delimiter,
            chunksize=chunk_size,
            low_memory=False,
            on_bad_lines="warn",
        )
        for chunk in reader:
            check_stop()
            yield chunk
    finally:
        response.close()


def download_to_temp(url: str, *, session: requests.Session, suffix: str = "") -> Path:
    response = session.get(url, stream=True, timeout=DEFAULT_HTTP_TIMEOUT, allow_redirects=True)
    response.raise_for_status()
    if response_looks_like_login(response):
        response.close()
        raise ProviderAccessError("Provider returned an interactive authentication page")

    total = response.headers.get("content-length")
    if total:
        print(f"[DOWNLOAD] {url} ({int(total):,} bytes)")
    else:
        print(f"[DOWNLOAD] {url}")

    tmp = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    temp_path = Path(tmp.name)
    try:
        with tmp:
            for block in response.iter_content(chunk_size=4 * 1024 * 1024):
                if block:
                    tmp.write(block)
    finally:
        response.close()
    return temp_path


def extract_candidate_links(page_url: str, html_text: str) -> List[str]:
    """Robust link extraction for official UNB/UNSW pages and intermediary pages."""
    soup = BeautifulSoup(html_text, "html.parser")
    links: List[str] = []

    def add(value: str) -> None:
        value = html.unescape(value.strip().strip("'\""))
        if not value:
            return
        full = urljoin(page_url, value)
        if full not in links:
            links.append(full)

    for tag in soup.find_all(True):
        for attr in ("href", "src", "data-href", "data-url", "data-download-url", "download-url"):
            value = tag.get(attr)
            if isinstance(value, str):
                add(value)
        onclick = tag.get("onclick")
        if isinstance(onclick, str):
            for match in re.findall(r"(?:https?://|/)[^'\"\s)]+", onclick):
                add(match)

    # Catch full URLs embedded in scripts, JSON, and inline page text.
    for match in re.findall(r"https?://[^\"'<>\s]+", html_text):
        add(match)

    return links


def score_download_link(url: str, preferred_names: Sequence[str]) -> int:
    lower = unquote(url).lower()
    score = 0
    for name in preferred_names:
        if name.lower() in lower:
            score += 100
    for token in ("machinelearning", "generatedlabelled", "labelled", "csv", "zip", "download"):
        if token in lower:
            score += 10
    if any(lower.endswith(ext) for ext in (".zip", ".csv", ".csv.gz", ".parquet")):
        score += 40
    if "javascript:" in lower:
        score -= 100
    return score


def discover_official_download_urls(
    page_url: str,
    *,
    session: requests.Session,
    preferred_names: Sequence[str],
    max_depth: int = 2,
) -> List[str]:
    visited: set[str] = set()
    queue: List[Tuple[str, int]] = [(page_url, 0)]
    discovered: List[str] = []

    while queue:
        check_stop()
        current, depth = queue.pop(0)
        if current in visited or depth > max_depth:
            continue
        visited.add(current)
        try:
            response = session.get(current, timeout=DEFAULT_HTTP_TIMEOUT, allow_redirects=True)
            response.raise_for_status()
        except requests.RequestException as exc:
            print(f"[DISCOVER] failed {current}: {exc}")
            continue

        if response_looks_like_login(response):
            continue
        content_type = response.headers.get("content-type", "").lower()
        if "text/html" not in content_type:
            discovered.append(response.url)
            continue

        links = extract_candidate_links(response.url, response.text)
        for link in links:
            score = score_download_link(link, preferred_names)
            parsed = urlparse(link)
            path_lower = parsed.path.lower()
            if score >= 50 or path_lower.endswith((".zip", ".csv", ".csv.gz", ".parquet", ".pq")):
                discovered.append(link)
            elif depth < max_depth and parsed.scheme in ("http", "https"):
                # Follow likely intermediate dataset/download pages but avoid
                # unrestricted crawling.
                if any(token in link.lower() for token in ("download", "dataset", "cic", "research")):
                    queue.append((link, depth + 1))

    # Deduplicate and rank.
    unique = list(dict.fromkeys(discovered))
    unique.sort(key=lambda u: score_download_link(u, preferred_names), reverse=True)
    return unique


def list_public_s3_keys(
    bucket: str,
    region: str,
    prefix: str,
    *,
    session: requests.Session,
) -> List[str]:
    keys: List[str] = []
    continuation: Optional[str] = None
    endpoint = f"https://{bucket}.s3.{region}.amazonaws.com/"

    while True:
        check_stop()
        params = {"list-type": "2", "prefix": prefix, "max-keys": "1000"}
        if continuation:
            params["continuation-token"] = continuation
        response = session.get(endpoint, params=params, timeout=DEFAULT_HTTP_TIMEOUT)
        response.raise_for_status()
        root = ET.fromstring(response.text)
        namespace = "{http://s3.amazonaws.com/doc/2006-03-01}"
        for node in root.findall(f"{namespace}Contents"):
            key_node = node.find(f"{namespace}Key")
            if key_node is not None and key_node.text:
                key = key_node.text
                if key.lower().endswith((".csv", ".csv.gz", ".parquet", ".pq")):
                    keys.append(key)
        truncated = root.find(f"{namespace}IsTruncated")
        if truncated is None or (truncated.text or "").lower() != "true":
            break
        token_node = root.find(f"{namespace}NextContinuationToken")
        if token_node is None or not token_node.text:
            break
        continuation = token_node.text
    return keys


def stream_official_sharepoint(
    dataset: str,
    *,
    session: requests.Session,
    chunk_size: int,
) -> Tuple[Iterator[pd.DataFrame], SourceInfo]:
    source = OFFICIAL_SOURCES[dataset]
    sharepoint = source.get("sharepoint")
    if not sharepoint:
        raise ProviderAccessError(f"{dataset}: no official SharePoint URL is configured")

    candidates = [
        sharepoint + ("&" if "?" in sharepoint else "?") + "download=1",
        sharepoint + ("&" if "?" in sharepoint else "?") + "download=1&web=1",
        sharepoint,
    ]
    last_error: Optional[Exception] = None
    for url in candidates:
        try:
            response = session.get(url, stream=True, timeout=DEFAULT_HTTP_TIMEOUT, allow_redirects=True)
            if response_looks_like_login(response):
                final_url = response.url
                response.close()
                last_error = ProviderAccessError(
                    f"redirected to interactive authentication: {final_url}"
                )
                continue
            content_type = response.headers.get("content-type", "").lower()
            if "text/html" in content_type:
                response.close()
                last_error = ProviderAccessError("received HTML instead of dataset bytes")
                continue
            response.close()
            return (
                stream_remote_csv(
                    url,
                    session=session,
                    chunk_size=chunk_size,
                    source_name=f"{DATASET_DISPLAY_NAMES[dataset]} official SharePoint",
                ),
                SourceInfo(
                    dataset=dataset,
                    mode="official",
                    provider="UNSW SharePoint",
                    reference=sharepoint,
                    scope="official provider endpoint",
                    notes=["Validated as an anonymous data endpoint if accessible; otherwise auto mode falls back to public mirror."],
                ),
            )
        except (requests.RequestException, ProviderAccessError) as exc:
            last_error = exc

    raise ProviderAccessError(
        f"{DATASET_DISPLAY_NAMES[dataset]} official SharePoint cannot currently be acquired automatically: {last_error}"
    )


def stream_official_cic2018(
    *,
    session: requests.Session,
    chunk_size: int,
) -> Tuple[Iterator[pd.DataFrame], SourceInfo]:
    source = OFFICIAL_SOURCES["cic2018"]
    keys = list_public_s3_keys(
        source["s3_bucket"],
        source["s3_region"],
        source["s3_prefix"],
        session=session,
    )
    if not keys:
        raise ProviderAccessError("CSE-CIC-IDS2018 public S3 listing returned no supported files")

    base = f"https://{source['s3_bucket']}.s3.{source['s3_region']}.amazonaws.com"

    def generator() -> Iterator[pd.DataFrame]:
        for key in keys:
            check_stop()
            url = f"{base}/{requests.utils.quote(key, safe='/')}"
            if key.lower().endswith((".csv", ".csv.gz")):
                yield from stream_remote_csv(
                    url,
                    session=session,
                    chunk_size=chunk_size,
                    source_name=f"CSE-CIC-IDS2018 official S3/{Path(key).name}",
                )
            else:
                temp_path = download_to_temp(
                    url,
                    session=session,
                    suffix=Path(key).suffix,
                )
                try:
                    yield from stream_local_path(
                        temp_path,
                        chunk_size=chunk_size,
                        source_name=f"CSE-CIC-IDS2018 official S3/{Path(key).name}",
                    )
                finally:
                    temp_path.unlink(missing_ok=True)

    return (
        generator(),
        SourceInfo(
            dataset="cic2018",
            mode="official",
            provider="UNB / AWS S3",
            reference=OFFICIAL_SOURCES["cic2018"]["page"],
            scope="official public S3 objects",
            files=keys,
        ),
    )


def stream_official_cic2017(
    *,
    session: requests.Session,
    chunk_size: int,
) -> Tuple[Iterator[pd.DataFrame], SourceInfo]:
    source = OFFICIAL_SOURCES["cic2017"]
    links = discover_official_download_urls(
        source["page"],
        session=session,
        preferred_names=source["preferred_names"],
        max_depth=3,
    )
    if not links:
        raise ProviderAccessError("CIC-IDS2017 official page did not expose an accessible archive")

    # Try links in ranked order until one actually provides data.
    last_error: Optional[Exception] = None
    for link in links:
        try:
            temp_path = download_to_temp(link, session=session, suffix=Path(urlparse(link).path).suffix)
            return (
                stream_local_path(
                    temp_path,
                    chunk_size=chunk_size,
                    source_name=f"CIC-IDS2017 official/{Path(urlparse(link).path).name or 'download'}",
                ),
                SourceInfo(
                    dataset="cic2017",
                    mode="official",
                    provider="UNB/CIC",
                    reference=link,
                    scope="official public ML archive",
                    files=[link],
                ),
            )
        except (requests.RequestException, ProviderAccessError, ValueError) as exc:
            last_error = exc
            try:
                temp_path.unlink(missing_ok=True)  # type: ignore[name-defined]
            except Exception:
                pass
    raise ProviderAccessError(f"CIC-IDS2017 official download candidates failed: {last_error}")


# ---------------------------------------------------------------------------
# Public mirror acquisition
# ---------------------------------------------------------------------------


def public_kaggle_root(dataset: str, *, botiot_full: bool = False) -> Tuple[Path, SourceInfo]:
    try:
        import kagglehub
    except ImportError as exc:
        raise ProviderAccessError(
            "Kaggle public mirror requires kagglehub. Install with: pip install kagglehub"
        ) from exc

    config = PUBLIC_SOURCES[dataset]
    if dataset == "botiot":
        repo = config["repo_full"] if botiot_full else config["repo_5pct"]
        scope = config["scope_full"] if botiot_full else config["scope_5pct"]
    else:
        repo = config["repo"]
        scope = config["scope"]

    print(f"[KAGGLE] downloading public source {repo}")
    root = Path(kagglehub.dataset_download(repo))
    if not root.exists():
        raise ProviderAccessError(f"Kaggle returned a non-existent dataset path: {root}")

    return (
        root,
        SourceInfo(
            dataset=dataset,
            mode="public",
            provider="Kaggle",
            reference=repo,
            scope=scope,
            files=[str(p) for p in iter_files_recursively(root)],
            notes=["Public mirror; not represented as an official provider endpoint."],
        ),
    )


def public_toniot_root() -> Tuple[Path, SourceInfo]:
    config = PUBLIC_SOURCES["toniot"]
    try:
        from huggingface_hub import HfApi, hf_hub_download
    except ImportError as exc:
        raise ProviderAccessError(
            "TON-IoT public mirror requires huggingface_hub. Install with: pip install huggingface_hub"
        ) from exc

    api = HfApi()
    repo = config["repo"]
    files = api.list_repo_files(repo_id=repo, repo_type="dataset")
    data_files = [
        name for name in files
        if name.lower().endswith((".csv", ".csv.gz", ".parquet", ".pq"))
    ]
    if not data_files:
        raise ProviderAccessError(f"No supported data files found in public TON-IoT mirror {repo}")

    # Download files individually so a repository containing README/assets does
    # not bring unnecessary content into the project.
    temp_dir = Path(tempfile.mkdtemp(prefix="hunterseeker_toniot_"))
    local_files: List[str] = []
    for remote_name in data_files:
        check_stop()
        print(f"[HF] downloading {repo}:{remote_name}")
        path = Path(
            hf_hub_download(
                repo_id=repo,
                filename=remote_name,
                repo_type="dataset",
            )
        )
        target = temp_dir / Path(remote_name).name
        if target.exists():
            # Keep deterministic names when different remote directories have
            # duplicate basenames.
            stem = target.stem
            target = temp_dir / f"{stem}_{len(local_files)}{target.suffix}"
        # Use a copy/link rather than relying on provider cache path layout.
        import shutil
        shutil.copy2(path, target)
        local_files.append(str(target))

    return (
        temp_dir,
        SourceInfo(
            dataset="toniot",
            mode="public",
            provider="Hugging Face",
            reference=repo,
            scope=config["scope"],
            files=local_files,
            notes=[
                "Public TON-IoT network-flow subset/mirror. It is not the complete heterogeneous TON-IoT collection."
            ],
        ),
    )


def iter_public_files(root: Path) -> Iterator[Path]:
    yield from iter_files_recursively(root)


def stream_public_dataset(
    dataset: str,
    *,
    chunk_size: int,
    botiot_full: bool,
) -> Tuple[Iterator[pd.DataFrame], SourceInfo]:
    if dataset == "toniot":
        root, info = public_toniot_root()
    else:
        root, info = public_kaggle_root(dataset, botiot_full=botiot_full)

    paths = list(iter_public_files(root))
    if not paths:
        raise ProviderAccessError(f"No supported files found under public source root {root}")

    def generator() -> Iterator[pd.DataFrame]:
        try:
            for path in paths:
                check_stop()
                yield from stream_local_path(
                    path,
                    chunk_size=chunk_size,
                    source_name=f"{DATASET_DISPLAY_NAMES[dataset]} public/{path.name}",
                )
        finally:
            # TON helper uses a temporary copied directory. Remove it after
            # streaming; Kaggle cache is managed by kagglehub and is retained.
            if dataset == "toniot":
                import shutil
                shutil.rmtree(root, ignore_errors=True)

    info.files = [str(p) for p in paths]
    return generator(), info


def acquire_dataset(
    dataset: str,
    *,
    source_mode: str,
    session: requests.Session,
    chunk_size: int,
    botiot_full: bool,
) -> Tuple[Iterator[pd.DataFrame], SourceInfo]:
    errors: List[str] = []

    if source_mode in ("official", "auto"):
        try:
            if dataset == "cic2018":
                return stream_official_cic2018(session=session, chunk_size=chunk_size)
            if dataset == "cic2017":
                return stream_official_cic2017(session=session, chunk_size=chunk_size)
            if dataset in ("unsw", "toniot", "botiot"):
                return stream_official_sharepoint(
                    dataset,
                    session=session,
                    chunk_size=chunk_size,
                )
        except Exception as exc:
            errors.append(f"official: {exc}")
            if source_mode == "official":
                raise ProviderAccessError(
                    f"{DATASET_DISPLAY_NAMES[dataset]} official source failed: {exc}"
                ) from exc

    if source_mode in ("public", "auto"):
        try:
            return stream_public_dataset(
                dataset,
                chunk_size=chunk_size,
                botiot_full=botiot_full,
            )
        except Exception as exc:
            errors.append(f"public: {exc}")

    message = f"{DATASET_DISPLAY_NAMES[dataset]} could not be acquired. " + " | ".join(errors)
    raise ProviderAccessError(message)


# ---------------------------------------------------------------------------
# Bounded dataset/class reservoir
# ---------------------------------------------------------------------------


class DataFrameReservoir:
    """Uniform reservoir sample for one dataset/class in canonical feature space."""

    def __init__(self, capacity: int, random_state: int) -> None:
        if capacity < 1:
            raise ValueError("Reservoir capacity must be >= 1")
        self.capacity = int(capacity)
        self.rng = np.random.default_rng(random_state)
        self.seen = 0
        self.data = np.empty((capacity, len(CANONICAL_FEATURES)), dtype=np.float64)
        self.attack_type = np.empty(capacity, dtype=object)
        self.protocol = np.empty(capacity, dtype=object)
        self.service = np.empty(capacity, dtype=object)
        self.row_id = np.empty(capacity, dtype=object)
        self.size = 0

    def add(
        self,
        x: np.ndarray,
        attack_type: Sequence[object],
        protocol: Sequence[object],
        service: Sequence[object],
        row_id: Sequence[object],
    ) -> None:
        if len(x) == 0:
            return
        if x.shape[1] != len(CANONICAL_FEATURES):
            raise ValueError("Reservoir feature width does not match canonical schema")

        # Process rows independently for exact uniform reservoir sampling.
        for i in range(len(x)):
            self.seen += 1
            if self.size < self.capacity:
                index = self.size
                self.size += 1
            else:
                index = int(self.rng.integers(0, self.seen))
                if index >= self.capacity:
                    continue
            self.data[index] = x[i]
            self.attack_type[index] = attack_type[i]
            self.protocol[index] = protocol[i]
            self.service[index] = service[i]
            self.row_id[index] = row_id[i]

    def frame(self, dataset: str, anomaly: int) -> pd.DataFrame:
        if self.size == 0:
            return pd.DataFrame(columns=CANONICAL_FEATURES + ["protocol", "service", "attack_type", "row_id", "anomaly", "dataset"])
        frame = pd.DataFrame(self.data[:self.size], columns=CANONICAL_FEATURES)
        frame["protocol"] = self.protocol[:self.size]
        frame["service"] = self.service[:self.size]
        frame["attack_type"] = self.attack_type[:self.size]
        frame["row_id"] = self.row_id[:self.size]
        frame["anomaly"] = int(anomaly)
        frame["dataset"] = dataset
        return frame


class BalancedReservoirBank:
    """Two class reservoirs for every requested dataset."""

    def __init__(self, datasets: Sequence[str], capacity_per_class: int, random_state: int) -> None:
        self.datasets = list(datasets)
        self.capacity_per_class = capacity_per_class
        self.banks: Dict[Tuple[str, int], DataFrameReservoir] = {}
        for d_index, dataset in enumerate(self.datasets):
            for class_value in (0, 1):
                seed = random_state + (d_index * 10_000) + class_value
                self.banks[(dataset, class_value)] = DataFrameReservoir(
                    capacity=capacity_per_class,
                    random_state=seed,
                )

    def add_frame(self, frame: pd.DataFrame, dataset: str) -> None:
        labels = frame["anomaly"].astype("Float64")
        for class_value in (0, 1):
            mask = labels == class_value
            if not mask.any():
                continue
            subset = frame.loc[mask]
            x = feature_frame(subset).to_numpy(dtype=np.float64)
            attack_type = subset["attack_type"].astype(str).tolist()
            protocol = subset["protocol"].astype(str).tolist()
            service = subset["service"].astype(str).tolist()
            row_ids = subset["row_id"].astype(str).tolist()
            self.banks[(dataset, class_value)].add(x, attack_type, protocol, service, row_ids)

    def counts(self) -> Dict[str, Dict[str, int]]:
        out: Dict[str, Dict[str, int]] = {}
        for dataset in self.datasets:
            out[dataset] = {
                "benign": self.banks[(dataset, 0)].size,
                "attack": self.banks[(dataset, 1)].size,
            }
        return out

    def balanced_frame(self, datasets: Sequence[str], *, random_state: int) -> pd.DataFrame:
        pieces: List[pd.DataFrame] = []
        for dataset in datasets:
            benign = self.banks[(dataset, 0)].frame(dataset, 0)
            attack = self.banks[(dataset, 1)].frame(dataset, 1)
            if benign.empty or attack.empty:
                raise ValueError(
                    f"{DATASET_DISPLAY_NAMES[dataset]} lacks both classes in its bounded reservoir: "
                    f"benign={len(benign)}, attack={len(attack)}"
                )
            # Dataset balancing first: use the same number of rows from each
            # class and therefore the same total from every dataset.
            n = min(len(benign), len(attack))
            if n < self.capacity_per_class:
                print(
                    f"[BALANCE] {DATASET_DISPLAY_NAMES[dataset]}: usable balanced capacity reduced to {n:,} "
                    f"because one class has fewer sampled rows."
                )
            benign = benign.sample(n=n, random_state=random_state)
            attack = attack.sample(n=n, random_state=random_state + 1)
            pieces.extend([benign, attack])

        combined = pd.concat(pieces, ignore_index=True)
        return combined.sample(frac=1.0, random_state=random_state).reset_index(drop=True)


# ---------------------------------------------------------------------------
# Dataset ingestion audit
# ---------------------------------------------------------------------------


def assign_row_ids(frame: pd.DataFrame, dataset: str, batch_index: int) -> pd.Series:
    return pd.Series(
        [f"{dataset}:{batch_index}:{i}" for i in range(len(frame))],
        index=frame.index,
        dtype="string",
    )


def update_stats_from_normalized(stats: DatasetStats, frame: pd.DataFrame) -> None:
    stats.rows_seen += len(frame)
    if len(frame) == 0:
        return
    labels = frame["anomaly"]
    valid = labels.notna()
    stats.rows_labeled += int(valid.sum())
    stats.benign_seen += int((labels == 0).sum())
    stats.attack_seen += int((labels == 1).sum())
    stats.unknown_seen += int((~valid).sum())


def ingest_to_reservoir(
    dataset: str,
    raw_stream: Iterator[pd.DataFrame],
    bank: BalancedReservoirBank,
    stats: DatasetStats,
) -> None:
    for batch_index, raw in enumerate(raw_stream):
        check_stop()
        stats.batches += 1
        normalized = normalize_frame(raw, dataset)
        normalized["row_id"] = assign_row_ids(normalized, dataset, batch_index).to_numpy()
        update_schema_and_label_stats(stats, raw, normalized)
        update_stats_from_normalized(stats, normalized)
        labeled = normalized[normalized["anomaly"].notna()].copy()
        if labeled.empty:
            continue
        bank.add_frame(labeled, dataset)


def ensure_all_five_datasets_contributed(
    datasets: Sequence[str],
    counts: Dict[str, Dict[str, int]],
) -> None:
    missing: List[str] = []
    for dataset in datasets:
        entry = counts.get(dataset, {})
        if entry.get("benign", 0) < 1 or entry.get("attack", 0) < 1:
            missing.append(
                f"{DATASET_DISPLAY_NAMES[dataset]}(benign={entry.get('benign', 0)},attack={entry.get('attack', 0)})"
            )
    if missing:
        raise RuntimeError(
            "Training gate failed: every requested dataset must contribute both benign and attack samples. "
            + ", ".join(missing)
        )


# ---------------------------------------------------------------------------
# Layer 3/4 preparation: evidence separation, leakage controls, model/evaluation
# ---------------------------------------------------------------------------


def _row_fingerprint(frame: pd.DataFrame, *, near: bool = False) -> pd.Series:
    """Stable row hash used for duplicate detection and grouped splitting."""
    tmp = frame.copy()
    if near:
        for col in MODEL_NUMERIC_FEATURES:
            if col in tmp:
                values = pd.to_numeric(tmp[col], errors="coerce").replace([np.inf, -np.inf], np.nan)
                # Compress magnitude while preserving sign for near-duplicate auditing.
                values = values.fillna(-9_999_999.0)
                tmp[col] = np.sign(values) * np.round(np.log1p(np.abs(values)), 2)
    else:
        for col in MODEL_NUMERIC_FEATURES:
            if col in tmp:
                tmp[col] = pd.to_numeric(tmp[col], errors="coerce").round(8)
    cols = [c for c in MODEL_NUMERIC_FEATURES + ["protocol", "service", "anomaly"] if c in tmp]
    return pd.util.hash_pandas_object(tmp[cols], index=False).astype("uint64").astype(str)


def deduplicate_balanced_pool(
    pool: pd.DataFrame,
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    exact = _row_fingerprint(pool, near=False)
    near = _row_fingerprint(pool, near=True)
    work = pool.copy()
    work["__exact_fp"] = exact.to_numpy()
    work["__near_fp"] = near.to_numpy()
    exact_duplicates = int(work.duplicated("__exact_fp", keep="first").sum())
    unique = work.drop_duplicates("__exact_fp", keep="first").copy()
    near_duplicate_rows = int(unique.duplicated("__near_fp", keep=False).sum())
    audit = {
        "input_rows": int(len(pool)),
        "exact_duplicate_rows_removed": exact_duplicates,
        "rows_after_exact_dedup": int(len(unique)),
        "near_duplicate_rows_flagged": near_duplicate_rows,
        "exact_duplicate_rate": float(exact_duplicates / len(pool)) if len(pool) else 0.0,
        "near_duplicate_rate_among_unique": float(near_duplicate_rows / len(unique)) if len(unique) else 0.0,
    }
    unique = unique.drop(columns=["__exact_fp", "__near_fp"])
    return unique.reset_index(drop=True), audit


def _grouped_stratified_split(
    pool: pd.DataFrame,
    *,
    validation_fraction: float,
    random_state: int,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    if not (0.0 < validation_fraction < 1.0):
        raise ValueError("validation_fraction must be between 0 and 1")

    work = pool.copy()
    work["__split_group"] = _row_fingerprint(work, near=False).to_numpy()
    train_parts: List[pd.DataFrame] = []
    validation_parts: List[pd.DataFrame] = []

    for dataset in sorted(work["dataset"].unique()):
        for class_value in (0, 1):
            subset = work[(work["dataset"] == dataset) & (work["anomaly"] == class_value)].copy()
            if len(subset) < 2:
                raise ValueError(
                    f"Not enough {DATASET_DISPLAY_NAMES[dataset]} class={class_value} rows for grouped validation split"
                )
            groups = subset.groupby("__split_group", sort=False).size().reset_index(name="rows")
            groups = groups.sample(frac=1.0, random_state=random_state + len(train_parts) * 17 + class_value)
            target = max(1, int(round(len(subset) * validation_fraction)))
            chosen: List[str] = []
            rows = 0
            for _, row in groups.iterrows():
                if rows >= target and chosen:
                    break
                chosen.append(str(row["__split_group"]))
                rows += int(row["rows"])
            chosen_set = set(chosen)
            val_mask = subset["__split_group"].isin(chosen_set)
            validation_parts.append(subset.loc[val_mask].drop(columns=["__split_group"]))
            train_parts.append(subset.loc[~val_mask].drop(columns=["__split_group"]))

    train = pd.concat(train_parts, ignore_index=True).sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    validation = pd.concat(validation_parts, ignore_index=True).sample(frac=1.0, random_state=random_state + 1).reset_index(drop=True)

    overlap = set(_row_fingerprint(train, near=False)).intersection(set(_row_fingerprint(validation, near=False)))
    if overlap:
        raise RuntimeError(f"Leakage gate failed: {len(overlap)} exact fingerprint groups cross train/validation")
    return train, validation


class BehavioralPreprocessor:
    """Train-only preprocessing with numeric missing indicators and categorical one-hot encoding."""

    def __init__(self) -> None:
        self.numeric_features = list(MODEL_NUMERIC_FEATURES)
        self.categorical_features = list(CATEGORICAL_MODEL_FEATURES)
        try:
            encoder = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
        except TypeError:
            encoder = OneHotEncoder(handle_unknown="ignore", sparse=False)
        try:
            numeric_imputer = SimpleImputer(
                strategy="median",
                add_indicator=True,
                keep_empty_features=True,
            )
        except TypeError:
            numeric_imputer = SimpleImputer(strategy="median", add_indicator=True)

        self.transformer = ColumnTransformer(
            transformers=[
                (
                    "numeric",
                    Pipeline([
                        ("imputer", numeric_imputer),
                        ("scaler", RobustScaler()),
                    ]),
                    self.numeric_features,
                ),
                (
                    "categorical",
                    Pipeline([
                        ("imputer", SimpleImputer(strategy="most_frequent")),
                        ("encoder", encoder),
                    ]),
                    self.categorical_features,
                ),
            ],
            remainder="drop",
            sparse_threshold=0.0,
        )
        self.feature_names: Optional[np.ndarray] = None

    def fit(self, frame: pd.DataFrame) -> "BehavioralPreprocessor":
        model_frame = model_feature_frame(frame)
        self.transformer.fit(model_frame)
        try:
            self.feature_names = self.transformer.get_feature_names_out()
        except Exception:
            self.feature_names = None
        return self

    def transform(self, frame: pd.DataFrame) -> np.ndarray:
        model_frame = model_feature_frame(frame)
        return np.asarray(self.transformer.transform(model_frame), dtype=np.float64)


class ThreatDetectionModel:
    """Layer 3 detector. Default model is nonlinear HistGradientBoosting over the canonical behavioral representation."""

    def __init__(self, random_state: int = DEFAULT_RANDOM_STATE, model_family: str = "hist_gradient_boosting") -> None:
        self.random_state = random_state
        self.model_family = model_family
        self.preprocessor = BehavioralPreprocessor()
        if model_family == "hist_gradient_boosting":
            self.estimator = HistGradientBoostingClassifier(
                learning_rate=0.05,
                max_iter=300,
                max_leaf_nodes=31,
                min_samples_leaf=20,
                l2_regularization=1.0,
                early_stopping=True,
                random_state=random_state,
            )
        elif model_family == "logistic":
            self.estimator = LogisticRegression(
                max_iter=1000,
                C=1.0,
                class_weight="balanced",
                solver="lbfgs",
                random_state=random_state,
            )
        else:
            raise ValueError(f"Unsupported model family: {model_family}")
        self.initialized = False

    def fit(self, train: pd.DataFrame, *, batch_size: int = DEFAULT_TRAIN_BATCH_SIZE) -> None:
        # Fit all transformers strictly on training data only.
        self.preprocessor.fit(train)
        x = self.preprocessor.transform(train)
        y = train["anomaly"].astype(np.int64).to_numpy()
        self.estimator.fit(x, y)
        self.initialized = True

    def predict(self, frame: pd.DataFrame) -> np.ndarray:
        if not self.initialized:
            raise RuntimeError("ThreatDetectionModel is not fitted")
        return self.estimator.predict(self.preprocessor.transform(frame))

    def probabilities(self, frame: pd.DataFrame) -> Optional[np.ndarray]:
        if not self.initialized or not hasattr(self.estimator, "predict_proba"):
            return None
        return self.estimator.predict_proba(self.preprocessor.transform(frame))[:, 1]

    def save(self, path: Path, metadata: Dict[str, Any]) -> Path:
        if not self.initialized:
            raise RuntimeError("Cannot save an uninitialized detector")
        import joblib
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "preprocessor": self.preprocessor,
            "estimator": self.estimator,
            "model_family": self.model_family,
            "feature_names": self.preprocessor.feature_names.tolist() if self.preprocessor.feature_names is not None else None,
            "pipeline_version": PIPELINE_VERSION,
            "random_state": self.random_state,
            "architecture_version": ARCHITECTURE_VERSION,
            "architecture_layers": ARCHITECTURE_LAYERS,
            "metadata": metadata,
        }
        joblib.dump(payload, path)
        return path


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, scores: Optional[np.ndarray]) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "rows": int(len(y_true)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist(),
    }
    if scores is not None and len(np.unique(y_true)) == 2:
        try:
            result["roc_auc"] = float(roc_auc_score(y_true, scores))
        except Exception:
            result["roc_auc"] = None
    else:
        result["roc_auc"] = None
    return result


def evaluate_global_and_per_dataset(model: ThreatDetectionModel, validation: pd.DataFrame) -> Dict[str, Any]:
    y_true = validation["anomaly"].astype(np.int64).to_numpy()
    y_pred = model.predict(validation)
    scores = model.probabilities(validation)
    metrics: Dict[str, Any] = {
        "global": compute_metrics(y_true, y_pred, scores),
        "per_dataset": {},
    }
    for dataset in sorted(validation["dataset"].unique()):
        mask = validation["dataset"] == dataset
        ds_true = y_true[mask.to_numpy()]
        ds_pred = y_pred[mask.to_numpy()]
        ds_scores = scores[mask.to_numpy()] if scores is not None else None
        metrics["per_dataset"][dataset] = compute_metrics(ds_true, ds_pred, ds_scores)
    return metrics


def evaluate_leave_one_dataset_out(
    pool: pd.DataFrame,
    *,
    random_state: int,
    model_family: str,
) -> Dict[str, Any]:
    """Train on four datasets and test on the fifth; this directly tests cross-dataset transfer."""
    results: Dict[str, Any] = {}
    datasets = sorted(pool["dataset"].unique())
    for held_out in datasets:
        train = pool[pool["dataset"] != held_out].copy()
        test = pool[pool["dataset"] == held_out].copy()
        model = ThreatDetectionModel(random_state=random_state, model_family=model_family)
        model.fit(train)
        y_true = test["anomaly"].astype(np.int64).to_numpy()
        y_pred = model.predict(test)
        scores = model.probabilities(test)
        results[held_out] = {
            "train_datasets": sorted(train["dataset"].unique().tolist()),
            "test_dataset": held_out,
            "metrics": compute_metrics(y_true, y_pred, scores),
        }
    return results


def evaluate_dataset_identity_risk(
    pool: pd.DataFrame,
    *,
    random_state: int,
) -> Dict[str, Any]:
    """Probe whether the representation makes dataset provenance trivially predictable."""
    probe = pool.copy()
    datasets = sorted(probe["dataset"].unique())
    if len(datasets) < 2:
        return {"available": False, "reason": "fewer than two datasets"}
    rng = np.random.default_rng(random_state)
    parts_train: List[pd.DataFrame] = []
    parts_test: List[pd.DataFrame] = []
    for dataset in datasets:
        subset = probe[probe["dataset"] == dataset].sample(frac=1.0, random_state=random_state + len(parts_train))
        cut = max(1, int(round(len(subset) * 0.2)))
        parts_test.append(subset.iloc[:cut])
        parts_train.append(subset.iloc[cut:])
    train = pd.concat(parts_train, ignore_index=True)
    test = pd.concat(parts_test, ignore_index=True)
    pre = BehavioralPreprocessor().fit(train)
    x_train = pre.transform(train)
    x_test = pre.transform(test)
    y_train = train["dataset"].to_numpy()
    y_test = test["dataset"].to_numpy()
    probe_model = LogisticRegression(max_iter=1000, random_state=random_state)
    probe_model.fit(x_train, y_train)
    pred = probe_model.predict(x_test)
    accuracy = float(accuracy_score(y_test, pred))
    return {
        "available": True,
        "accuracy": accuracy,
        "random_baseline": float(1.0 / len(datasets)),
        "warning": accuracy >= 0.70,
        "datasets": datasets,
        "interpretation": (
            "High dataset-identity accuracy means the current feature representation retains strong source-specific structure; "
            "it does not automatically invalidate the detector, but it reduces confidence in cross-source generalization."
        ),
    }


def compute_feature_importance(
    model: ThreatDetectionModel,
    validation: pd.DataFrame,
    *,
    random_state: int,
    repeats: int = 5,
    max_rows: int = 2000,
) -> Dict[str, Any]:
    subset = validation if len(validation) <= max_rows else validation.sample(n=max_rows, random_state=random_state)
    x = model.preprocessor.transform(subset)
    y = subset["anomaly"].astype(np.int64).to_numpy()
    result = permutation_importance(
        model.estimator,
        x,
        y,
        n_repeats=repeats,
        random_state=random_state,
        scoring="balanced_accuracy",
    )
    if model.preprocessor.feature_names is None:
        names = [f"feature_{i}" for i in range(x.shape[1])]
    else:
        names = model.preprocessor.feature_names.tolist()
    ranked = sorted(
        [
            {
                "feature": str(name),
                "importance_mean": float(mean),
                "importance_std": float(std),
            }
            for name, mean, std in zip(names, result.importances_mean, result.importances_std)
        ],
        key=lambda item: item["importance_mean"],
        reverse=True,
    )
    return {"rows_used": int(len(subset)), "repeats": repeats, "top_features": ranked[:25]}
# ---------------------------------------------------------------------------
# Layer 2 quality/audit helpers
# ---------------------------------------------------------------------------


def update_schema_and_label_stats(stats: DatasetStats, raw: pd.DataFrame, normalized: pd.DataFrame) -> None:
    audit = normalized.attrs.get("schema_audit", {})
    source_map = audit.get("feature_source_map", {})
    for feature, source_col in source_map.items():
        if source_col:
            stats.feature_source_map.setdefault(feature, str(source_col))
            present = int(safe_float_series(raw[source_col]).notna().sum()) if source_col in raw.columns else 0
        else:
            present = 0
        stats.feature_present_rows[feature] = stats.feature_present_rows.get(feature, 0) + present
        stats.feature_missing_rows[feature] = stats.feature_missing_rows.get(feature, 0) + int(len(raw) - present)

    for column in audit.get("unused_columns", []):
        stats.unused_raw_columns[column] = stats.unused_raw_columns.get(column, 0) + 1

    labels = normalized["label_raw"].astype(str).map(clean_string).str.lower()
    for value, count in labels.value_counts(dropna=False).items():
        token = str(value)
        stats.label_values[token] = stats.label_values.get(token, 0) + int(count)
        if normalized.loc[labels == token, "anomaly"].isna().any():
            stats.unknown_label_values[token] = stats.unknown_label_values.get(token, 0) + int(count)

    attacks = normalized["attack_type"].astype(str).map(clean_string).str.lower()
    for value, count in attacks.value_counts(dropna=False).items():
        token = str(value)
        stats.attack_type_values[token] = stats.attack_type_values.get(token, 0) + int(count)


def dedupe_and_split_pool(
    pool: pd.DataFrame,
    *,
    validation_fraction: float,
    random_state: int,
) -> Tuple[pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
    deduped, duplicate_audit = deduplicate_balanced_pool(pool)
    # Re-check dataset/class contribution after deduplication.
    counts = (
        deduped.groupby(["dataset", "anomaly"]).size().to_dict()
        if not deduped.empty else {}
    )
    for dataset in sorted(pool["dataset"].unique()):
        for class_value in (0, 1):
            if int(counts.get((dataset, class_value), 0)) < 2:
                raise RuntimeError(
                    f"Deduplication left too few rows for {DATASET_DISPLAY_NAMES[dataset]} class={class_value}."
                )
    train, validation = _grouped_stratified_split(
        deduped,
        validation_fraction=validation_fraction,
        random_state=random_state,
    )
    audit = {**duplicate_audit, "deduped_pool_rows": int(len(deduped)), "train_rows": int(len(train)), "validation_rows": int(len(validation))}
    return train, validation, audit


@dataclass
class LayeredPipeline:
    """Data-pipeline boundary that maps to the separately defined runtime architecture."""
    architecture_version: str = ARCHITECTURE_VERSION
    architecture: Dict[str, str] = field(default_factory=lambda: ARCHITECTURE_LAYERS.copy())


# ---------------------------------------------------------------------------
# Self-test fixtures
# ---------------------------------------------------------------------------


def build_self_test_files(root: Path, rows_per_dataset: int = 80) -> Dict[str, Path]:
    rng = np.random.default_rng(123)
    paths: Dict[str, Path] = {}

    for dataset in TARGET_DATASETS:
        rows: List[Dict[str, Any]] = []
        for i in range(rows_per_dataset):
            attack = int(i % 2)
            duration = float(rng.uniform(0.001, 5.0))
            if dataset == "unsw":
                rows.append({
                    "ts": 1710000000 + i,
                    "id.orig_h": "10.0.0.1",
                    "id.resp_h": "10.0.0.2",
                    "id.orig_p": 1000 + i,
                    "id.resp_p": 80,
                    "proto": "tcp",
                    "dur": duration,
                    "sbytes": 1000 + attack * 3000 + i,
                    "dbytes": 700 + i,
                    "spkts": 10 + i % 5,
                    "dpkts": 8 + i % 4,
                    "label": attack,
                    "attack_cat": "Normal" if not attack else "Generic",
                })
            elif dataset == "cic2017":
                rows.append({
                    "Timestamp": f"2017-07-07 12:{i % 60:02d}:00",
                    "Source IP": "10.0.0.1",
                    "Destination IP": "10.0.0.2",
                    "Source Port": 1000 + i,
                    "Destination Port": 80,
                    "Protocol": 6,
                    "Flow Duration": duration * 1_000_000,
                    "Total Fwd Packets": 10 + i % 5,
                    "Total Backward Packets": 8 + i % 4,
                    "Total Length of Fwd Packets": 1000 + attack * 3000 + i,
                    "Total Length of Bwd Packets": 700 + i,
                    "Label": "BENIGN" if not attack else "DoS Hulk",
                })
            elif dataset == "cic2018":
                rows.append({
                    "Timestamp": f"2018-02-14 12:{i % 60:02d}:00",
                    "Src IP": "10.0.0.1",
                    "Dst IP": "10.0.0.2",
                    "Src Port": 1000 + i,
                    "Dst Port": 80,
                    "Protocol": 6,
                    "Flow Duration": duration * 1_000_000,
                    "Tot Fwd Pkts": 10 + i % 5,
                    "Tot Bwd Pkts": 8 + i % 4,
                    "TotLen Fwd Pkts": 1000 + attack * 3000 + i,
                    "TotLen Bwd Pkts": 700 + i,
                    "Label": "BENIGN" if not attack else "Bot",
                })
            elif dataset == "toniot":
                rows.append({
                    "ts": 1_700_000_000 + i,
                    "src_ip": "10.0.0.1",
                    "dst_ip": "10.0.0.2",
                    "src_port": 1000 + i,
                    "dst_port": 80,
                    "proto": "tcp",
                    "duration": duration,
                    "src_bytes": 1000 + attack * 3000 + i,
                    "dst_bytes": 700 + i,
                    "src_pkts": 10 + i % 5,
                    "dst_pkts": 8 + i % 4,
                    "label": attack,
                    "type": "normal" if not attack else "ransomware",
                })
            else:
                rows.append({
                    "stime": 1500000000 + i,
                    "saddr": "10.0.0.1",
                    "daddr": "10.0.0.2",
                    "sport": 1000 + i,
                    "dport": 80,
                    "proto": "tcp",
                    "dur": duration,
                    "sbytes": 1000 + attack * 3000 + i,
                    "dbytes": 700 + i,
                    "spkts": 10 + i % 5,
                    "dpkts": 8 + i % 4,
                    "attack": attack,
                    "category": "Normal" if not attack else "DDoS",
                    "subcategory": "Normal" if not attack else "UDP Flooding",
                })
        path = root / f"{dataset}_selftest.csv"
        pd.DataFrame(rows).to_csv(path, index=False)
        paths[dataset] = path
    return paths


def run_self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="hunterseeker_selftest_") as temp:
        root = Path(temp)
        files = build_self_test_files(root)
        bank = BalancedReservoirBank(
            TARGET_DATASETS,
            capacity_per_class=20,
            random_state=DEFAULT_RANDOM_STATE,
        )
        stats_map: Dict[str, DatasetStats] = {}
        for dataset in TARGET_DATASETS:
            stats = DatasetStats(dataset=dataset, source_provider="self-test", source_reference=str(files[dataset]))
            stats_map[dataset] = stats
            stream = stream_local_path(files[dataset], chunk_size=17, source_name=str(files[dataset]))
            ingest_to_reservoir(dataset, stream, bank, stats)

        counts = bank.counts()
        ensure_all_five_datasets_contributed(TARGET_DATASETS, counts)
        pool = bank.balanced_frame(TARGET_DATASETS, random_state=DEFAULT_RANDOM_STATE)
        train, validation, duplicate_audit = dedupe_and_split_pool(
            pool,
            validation_fraction=0.25,
            random_state=DEFAULT_RANDOM_STATE,
        )
        trainer = ThreatDetectionModel(model_family="hist_gradient_boosting")
        trainer.fit(train, batch_size=32)
        metrics = evaluate_global_and_per_dataset(trainer, validation)

        assert len(pool) == 200, f"Expected 200 balanced rows, got {len(pool)}"
        assert set(train["dataset"]) == set(TARGET_DATASETS)
        assert set(validation["dataset"]) == set(TARGET_DATASETS)
        assert all(counts[d]["benign"] == 20 and counts[d]["attack"] == 20 for d in TARGET_DATASETS)
        assert metrics["global"]["rows"] == 50
        print("[SELF-TEST] PASS")
        print(json.dumps({
            "reservoir_counts": counts,
            "pool_rows": len(pool),
            "train_rows": len(train),
            "validation_rows": len(validation),
            "global_metrics": metrics["global"],
        }, indent=2, default=str))


# ---------------------------------------------------------------------------
# CLI / orchestration
# ---------------------------------------------------------------------------


def parse_input_mapping(values: Sequence[str]) -> Dict[str, List[Path]]:
    mapping: Dict[str, List[Path]] = {dataset: [] for dataset in TARGET_DATASETS}
    for value in values:
        if "=" not in value:
            raise ValueError(
                f"Invalid --input value {value!r}. Use DATASET=PATH, e.g. unsw=/data/UNSW.csv"
            )
        dataset, path_text = value.split("=", 1)
        dataset = normalize_name(dataset)
        # Allow friendly names in addition to canonical short names.
        aliases = {
            "unsw_nb15": "unsw",
            "unswnb15": "unsw",
            "cic_ids2017": "cic2017",
            "cicids2017": "cic2017",
            "cic_ids_2017": "cic2017",
            "cse_cic_ids2018": "cic2018",
            "csecicids2018": "cic2018",
            "cicids2018": "cic2018",
            "ton_iot": "toniot",
            "toniot_network": "toniot",
            "bot_iot": "botiot",
            "botiot": "botiot",
        }
        dataset = aliases.get(dataset, dataset)
        if dataset not in TARGET_DATASETS:
            raise ValueError(f"Unknown dataset in --input: {dataset}")
        mapping[dataset].append(Path(path_text).expanduser())
    return mapping


def parse_dataset_list(values: Sequence[str]) -> List[str]:
    if not values:
        return list(TARGET_DATASETS)
    output: List[str] = []
    aliases = {
        "unsw_nb15": "unsw",
        "unswnb15": "unsw",
        "cic_ids2017": "cic2017",
        "cicids2017": "cic2017",
        "cse_cic_ids2018": "cic2018",
        "csecicids2018": "cic2018",
        "cicids2018": "cic2018",
        "ton_iot": "toniot",
        "bot_iot": "botiot",
        "botiot": "botiot",
    }
    for raw in values:
        for token in raw.split(","):
            dataset = aliases.get(normalize_name(token), normalize_name(token))
            if dataset not in TARGET_DATASETS:
                raise ValueError(
                    f"Unknown dataset {token!r}. Supported: {', '.join(TARGET_DATASETS)}"
                )
            if dataset not in output:
                output.append(dataset)
    return output


def print_summary(
    datasets: Sequence[str],
    stats_map: Dict[str, DatasetStats],
    counts: Dict[str, Dict[str, int]],
) -> None:
    print("\n=== DATASET INGESTION SUMMARY ===")
    print(f"{'Dataset':<22}{'Rows Seen':>12}{'Labeled':>12}{'Benign':>12}{'Attack':>12}{'Reservoir B/A':>20}")
    print("-" * 90)
    for dataset in datasets:
        stats = stats_map[dataset]
        c = counts[dataset]
        print(
            f"{DATASET_DISPLAY_NAMES[dataset]:<22}"
            f"{stats.rows_seen:>12,}"
            f"{stats.rows_labeled:>12,}"
            f"{stats.benign_seen:>12,}"
            f"{stats.attack_seen:>12,}"
            f"{c['benign']:>9,} / {c['attack']:<9,}"
        )


def make_manifest(
    *,
    args: argparse.Namespace,
    datasets: Sequence[str],
    stats_map: Dict[str, DatasetStats],
    source_map: Dict[str, SourceInfo],
    counts: Dict[str, Dict[str, int]],
    train: Optional[pd.DataFrame],
    validation: Optional[pd.DataFrame],
    metrics: Optional[Dict[str, Any]],
    model_path: Optional[Path],
    duplicate_audit: Optional[Dict[str, Any]] = None,
    identity_audit: Optional[Dict[str, Any]] = None,
    cross_dataset_audit: Optional[Dict[str, Any]] = None,
    feature_importance: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    feature_audit = {}
    for dataset in datasets:
        stats = stats_map[dataset]
        feature_audit[dataset] = {
            "source_map": stats.feature_source_map,
            "present_rows": stats.feature_present_rows,
            "missing_rows": stats.feature_missing_rows,
            "coverage_fraction": {
                feature: (
                    stats.feature_present_rows.get(feature, 0) / stats.rows_seen
                    if stats.rows_seen else 0.0
                )
                for feature in CANONICAL_FEATURES
            },
            "unused_raw_columns": sorted(stats.unused_raw_columns),
            "label_values_top": dict(sorted(stats.label_values.items(), key=lambda kv: kv[1], reverse=True)[:25]),
            "unknown_label_values_top": dict(sorted(stats.unknown_label_values.items(), key=lambda kv: kv[1], reverse=True)[:25]),
            "attack_type_values_top": dict(sorted(stats.attack_type_values.items(), key=lambda kv: kv[1], reverse=True)[:25]),
        }

    return {
        "pipeline_version": PIPELINE_VERSION,
        "created_at_utc": pd.Timestamp.now("UTC").isoformat(),
        "requested_datasets": list(datasets),
        "dataset_display_names": DATASET_DISPLAY_NAMES,
        "architecture_version": ARCHITECTURE_VERSION,
        "architecture_layers": ARCHITECTURE_LAYERS,
        "source_mode": args.source_mode,
        "botiot_full": bool(args.botiot_full),
        "balancing": {
            "reservoir_capacity_per_dataset_class": args.sample_per_dataset_class,
            "dataset_balancing": "equal usable rows per dataset",
            "class_balancing": "equal benign and attack rows per dataset",
            "validation_fraction": args.validation_fraction,
            "random_state": args.random_state,
        },
        "features": {
            "canonical_numeric": CANONICAL_FEATURES,
            "derived_numeric": DERIVED_NUMERIC_FEATURES,
            "categorical": CATEGORICAL_MODEL_FEATURES,
            "model_numeric": MODEL_NUMERIC_FEATURES,
            "excluded_identity_fields": ["source", "destination", "timestamp", "label_raw", "attack_type", "dataset", "row_id"],
            "categorical_encoding": "train-only one-hot, handle_unknown=ignore",
            "numeric_missing_handling": "train-only median imputation + explicit missing indicators",
            "numeric_scaling": "train-only RobustScaler",
            "heavy_tail_transform": "log1p on selected nonnegative behavioral features",
        },
        "feature_audit": feature_audit,
        "sources": {dataset: asdict(source_map[dataset]) for dataset in datasets if dataset in source_map},
        "datasets": {dataset: {**asdict(stats_map[dataset]), "reservoir": counts.get(dataset, {})} for dataset in datasets},
        "training": {
            "requested": bool(args.train),
            "performed": train is not None,
            "model_family": args.model_family,
            "train_rows": int(len(train)) if train is not None else 0,
            "validation_rows": int(len(validation)) if validation is not None else 0,
            "train_dataset_counts": (train.groupby(["dataset", "anomaly"]).size().unstack(fill_value=0).to_dict() if train is not None else {}),
            "validation_dataset_counts": (validation.groupby(["dataset", "anomaly"]).size().unstack(fill_value=0).to_dict() if validation is not None else {}),
        },
        "quality_gates": {
            "label_unknowns_are_not_automatically_attack": True,
            "exact_duplicate_group_leakage_checked": True,
            "train_only_preprocessing_fit": True,
            "dataset_identity_probe_enabled": True,
            "cross_dataset_holdout_enabled": True,
        },
        "duplicate_audit": duplicate_audit,
        "dataset_identity_audit": identity_audit,
        "cross_dataset_audit": cross_dataset_audit,
        "feature_importance": feature_importance,
        "metrics": metrics,
        "model_path": str(model_path) if model_path else None,
    }


def write_manifest(manifest: Dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(manifest, indent=2, default=str),
        encoding="utf-8",
    )
    print(f"[MANIFEST] {path}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="HunterSeekerAI five-dataset ingestion/training orchestrator"
    )
    parser.add_argument(
        "--source-mode",
        choices=("auto", "official", "public"),
        default="auto",
        help="Source selection. auto=official then public mirror fallback; public=public mirrors; official=official only.",
    )
    parser.add_argument(
        "--datasets",
        nargs="+",
        default=list(TARGET_DATASETS),
        help="Datasets to process. Default is all five target datasets.",
    )
    parser.add_argument(
        "--input",
        action="append",
        default=[],
        metavar="DATASET=PATH",
        help="Local file/archive input. Repeat for multiple files per dataset.",
    )
    parser.add_argument(
        "--train",
        action="store_true",
        help="Train after all requested datasets have contributed to the balanced reservoir.",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Print ingestion/training statistics.",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        help=f"Pandas/Parquet batch size. Default {DEFAULT_CHUNK_SIZE}.",
    )
    parser.add_argument(
        "--sample-per-dataset-class",
        type=int,
        default=DEFAULT_SAMPLE_PER_DATASET_CLASS,
        help=f"Bounded reservoir size for each dataset/class. Default {DEFAULT_SAMPLE_PER_DATASET_CLASS}.",
    )
    parser.add_argument(
        "--validation-fraction",
        type=float,
        default=DEFAULT_VALIDATION_FRACTION,
        help=f"Validation fraction per dataset/class. Default {DEFAULT_VALIDATION_FRACTION}.",
    )
    parser.add_argument(
        "--train-batch-size",
        type=int,
        default=DEFAULT_TRAIN_BATCH_SIZE,
        help="Compatibility option retained for the previous incremental trainer; batch size is not required by the batch detector.",
    )
    parser.add_argument(
        "--model-family",
        choices=("hist_gradient_boosting", "logistic"),
        default="hist_gradient_boosting",
        help="Detection model. Default is nonlinear HistGradientBoosting for the canonical behavioral feature space.",
    )
    parser.add_argument(
        "--importance-repeats",
        type=int,
        default=5,
        help="Permutation-importance repeats. Set 0 to disable feature importance.",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=DEFAULT_RANDOM_STATE,
        help=f"Deterministic random seed. Default {DEFAULT_RANDOM_STATE}.",
    )
    parser.add_argument(
        "--model-path",
        type=Path,
        default=DEFAULT_MODEL_PATH,
        help=f"Output model path. Default {DEFAULT_MODEL_PATH}.",
    )
    parser.add_argument(
        "--manifest-path",
        type=Path,
        default=DEFAULT_MANIFEST_PATH,
        help=f"Output manifest path. Default {DEFAULT_MANIFEST_PATH}.",
    )
    parser.add_argument(
        "--botiot-full",
        action="store_true",
        help="Use the public full BoT-IoT mirror instead of the default public 5%% distribution.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run an offline schema/balancing/training self-test and exit.",
    )
    return parser


def main() -> int:
    signal.signal(signal.SIGINT, request_stop)
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.self_test:
        run_self_test()
        return 0

    if args.chunk_size < 1:
        parser.error("--chunk-size must be >= 1")
    if args.sample_per_dataset_class < 2:
        parser.error("--sample-per-dataset-class must be >= 2")
    if not (0.0 < args.validation_fraction < 1.0):
        parser.error("--validation-fraction must be between 0 and 1")
    if args.train_batch_size < 1:
        parser.error("--train-batch-size must be >= 1")

    try:
        datasets = parse_dataset_list(args.datasets)
        input_map = parse_input_mapping(args.input)
    except ValueError as exc:
        parser.error(str(exc))
        return 2

    if not datasets:
        parser.error("At least one dataset must be requested")
        return 2

    # If --input was supplied for any dataset, that dataset is sourced locally;
    # remaining requested datasets still use the selected remote source mode.
    session = make_session()
    bank = BalancedReservoirBank(
        datasets,
        capacity_per_class=args.sample_per_dataset_class,
        random_state=args.random_state,
    )
    stats_map: Dict[str, DatasetStats] = {}
    source_map: Dict[str, SourceInfo] = {}

    try:
        for dataset in datasets:
            check_stop()
            stats = DatasetStats(dataset=dataset)
            stats_map[dataset] = stats

            local_inputs = input_map.get(dataset, [])
            if local_inputs:
                source_map[dataset] = SourceInfo(
                    dataset=dataset,
                    mode="local",
                    provider="local filesystem",
                    reference=", ".join(str(p) for p in local_inputs),
                    scope="user-supplied local input",
                    files=[str(p) for p in local_inputs],
                )
                stats.source_provider = "local filesystem"
                stats.source_reference = source_map[dataset].reference
                stats.source_scope = source_map[dataset].scope
                for path in local_inputs:
                    print(f"\n[DATASET] {DATASET_DISPLAY_NAMES[dataset]} <= {path}")
                    stream = stream_local_path(
                        path,
                        chunk_size=args.chunk_size,
                        source_name=str(path),
                    )
                    ingest_to_reservoir(dataset, stream, bank, stats)
            else:
                print(f"\n[DATASET] acquiring {DATASET_DISPLAY_NAMES[dataset]}")
                stream, info = acquire_dataset(
                    dataset,
                    source_mode=args.source_mode,
                    session=session,
                    chunk_size=args.chunk_size,
                    botiot_full=args.botiot_full,
                )
                source_map[dataset] = info
                stats.source_provider = info.provider
                stats.source_reference = info.reference
                stats.source_scope = info.scope
                try:
                    ingest_to_reservoir(dataset, stream, bank, stats)
                except Exception as exc:
                    stats.errors.append(str(exc))
                    raise

            counts = bank.counts()[dataset]
            stats.reservoir_benign = counts["benign"]
            stats.reservoir_attack = counts["attack"]
            print(
                f"[RESERVOIR] {DATASET_DISPLAY_NAMES[dataset]}: "
                f"benign={counts['benign']:,}, attack={counts['attack']:,}"
            )

        counts = bank.counts()
        print_summary(datasets, stats_map, counts)

        # A balanced pool is constructed even without --train so that --stats
        # can verify that each requested dataset is actually usable.
        ensure_all_five_datasets_contributed(datasets, counts)
        pool = bank.balanced_frame(datasets, random_state=args.random_state)

        train: Optional[pd.DataFrame] = None
        validation: Optional[pd.DataFrame] = None
        metrics: Optional[Dict[str, Any]] = None
        model_path: Optional[Path] = None

        duplicate_audit = None
        identity_audit = None
        cross_dataset_audit = None
        feature_importance = None

        if args.train:
            train, validation, duplicate_audit = dedupe_and_split_pool(
                pool,
                validation_fraction=args.validation_fraction,
                random_state=args.random_state,
            )
            print(
                f"\n[TRAINING] sampled_pool={len(pool):,}; "
                f"exact_dedup_removed={duplicate_audit['exact_duplicate_rows_removed']:,}; "
                f"deduped_pool={duplicate_audit['deduped_pool_rows']:,}; "
                f"train={len(train):,}; validation={len(validation):,}"
            )
            if duplicate_audit["near_duplicate_rows_flagged"]:
                print(
                    f"[DUPLICATES] near-duplicate rows flagged={duplicate_audit['near_duplicate_rows_flagged']:,} "
                    f"({duplicate_audit['near_duplicate_rate_among_unique']:.2%} of unique pool)"
                )

            for dataset in datasets:
                train_ds = train[train["dataset"] == dataset]
                val_ds = validation[validation["dataset"] == dataset]
                stats = stats_map[dataset]
                stats.train_benign = int((train_ds["anomaly"] == 0).sum())
                stats.train_attack = int((train_ds["anomaly"] == 1).sum())
                stats.validation_benign = int((val_ds["anomaly"] == 0).sum())
                stats.validation_attack = int((val_ds["anomaly"] == 1).sum())
                stats.exact_duplicate_rows_in_pool = int(duplicate_audit["exact_duplicate_rows_removed"])
                stats.near_duplicate_rows_in_pool = int(duplicate_audit["near_duplicate_rows_flagged"])

            print("[LAYER 2] canonical behavioral representation ready")
            print("[LAYER 3] fitting threat detector on training data only")
            trainer = ThreatDetectionModel(random_state=args.random_state, model_family=args.model_family)
            trainer.fit(train, batch_size=args.train_batch_size)
            metrics = evaluate_global_and_per_dataset(trainer, validation)

            deduped_eval_pool, _ = deduplicate_balanced_pool(pool)
            identity_audit = evaluate_dataset_identity_risk(deduped_eval_pool, random_state=args.random_state)
            if identity_audit.get("available"):
                print(
                    f"[IDENTITY PROBE] accuracy={identity_audit['accuracy']:.4f}; "
                    f"random_baseline={identity_audit['random_baseline']:.4f}; "
                    f"warning={identity_audit['warning']}"
                )

            print("[CROSS-DATASET] leave-one-dataset-out transfer evaluation")
            cross_dataset_audit = evaluate_leave_one_dataset_out(
                deduped_eval_pool,
                random_state=args.random_state,
                model_family=args.model_family,
            )

            if args.importance_repeats > 0:
                feature_importance = compute_feature_importance(
                    trainer, validation, random_state=args.random_state, repeats=args.importance_repeats
                )
                print("[FEATURE IMPORTANCE] top features:")
                for item in feature_importance["top_features"][:10]:
                    print(
                        f"  {item['feature']:<55} "
                        f"mean={item['importance_mean']:.6f} std={item['importance_std']:.6f}"
                    )

            model_path = trainer.save(
                args.model_path,
                metadata={
                    "datasets": list(datasets),
                    "balanced_sample_per_dataset_class": args.sample_per_dataset_class,
                    "validation_fraction": args.validation_fraction,
                    "source_mode": args.source_mode,
                    "botiot_full": bool(args.botiot_full),
                    "model_family": args.model_family,
                },
            )
            print(f"[MODEL] {model_path}")
            print(
                "[VALIDATION] "
                f"accuracy={metrics['global']['accuracy']:.4f}, "
                f"balanced_accuracy={metrics['global']['balanced_accuracy']:.4f}, "
                f"precision={metrics['global']['precision']:.4f}, "
                f"recall={metrics['global']['recall']:.4f}, "
                f"f1={metrics['global']['f1']:.4f}, "
                f"roc_auc={metrics['global']['roc_auc']}"
            )

            print("\n=== PER-DATASET VALIDATION ===")
            for dataset in datasets:
                m = metrics["per_dataset"][dataset]
                print(
                    f"{DATASET_DISPLAY_NAMES[dataset]:<22} "
                    f"n={m['rows']:>6} "
                    f"bal_acc={m['balanced_accuracy']:.4f} "
                    f"f1={m['f1']:.4f} "
                    f"roc_auc={m['roc_auc']}"
                )

            print("\n=== LEAVE-ONE-DATASET-OUT ===")
            for held_out, report in cross_dataset_audit.items():
                m = report["metrics"]
                print(
                    f"{DATASET_DISPLAY_NAMES[held_out]:<22} "
                    f"bal_acc={m['balanced_accuracy']:.4f} "
                    f"f1={m['f1']:.4f} "
                    f"roc_auc={m['roc_auc']}"
                )
        else:
            print(
                f"\n[CHECK] Balanced usable pool contains {len(pool):,} rows "
                "across every requested dataset and both classes."
            )

        manifest = make_manifest(
            args=args,
            datasets=datasets,
            stats_map=stats_map,
            source_map=source_map,
            counts=counts,
            train=train,
            validation=validation,
            metrics=metrics,
            model_path=model_path,
            duplicate_audit=duplicate_audit,
            identity_audit=identity_audit,
            cross_dataset_audit=cross_dataset_audit,
            feature_importance=feature_importance,
        )
        write_manifest(manifest, args.manifest_path)

        if args.stats:
            print("\n=== SOURCE PROVENANCE ===")
            for dataset in datasets:
                info = source_map[dataset]
                print(
                    f"{DATASET_DISPLAY_NAMES[dataset]}: provider={info.provider}; "
                    f"scope={info.scope}; reference={info.reference}"
                )

        return 0

    except PipelineInterrupted:
        print("[STOP] Pipeline stopped at a safe boundary.")
        return 130
    except KeyboardInterrupt:
        print("[STOP] Pipeline interrupted.")
        return 130
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        if os.environ.get("HUNTERSEEKER_TRACEBACK") == "1":
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
