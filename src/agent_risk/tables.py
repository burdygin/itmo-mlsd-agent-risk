"""Write dataclass rows as gzip CSV and describe a dataset version in a manifest."""

import csv
import gzip
import hashlib
import io
import json
from collections.abc import Sequence
from dataclasses import astuple, fields, is_dataclass
from pathlib import Path
from typing import TypeAlias

from agent_risk.gateway import CallFeatures

Scalar: TypeAlias = str | int | float | bool | None


def _cell(value: Scalar) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value)


def write_rows(path: Path, rows: Sequence[object], row_type: type) -> str:
    """Write rows of one dataclass type; return sha256 of the file bytes.

    The gzip header carries no file name and a zero timestamp, so equal rows give
    equal bytes and the hash identifies the content.
    """
    if not is_dataclass(row_type):
        raise TypeError(row_type)
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow([f.name for f in fields(row_type)])
    for row in rows:
        if not isinstance(row, row_type) or not is_dataclass(row):
            raise TypeError(row)
        values: tuple[Scalar, ...] = astuple(row)
        writer.writerow([_cell(v) for v in values])
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
        gz.write(buffer.getvalue().encode("utf-8"))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_rows(path: Path) -> list[dict[str, str]]:
    """Read a gzip CSV written by :func:`write_rows`."""
    with gzip.open(path, "rt", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _flag(value: str) -> bool:
    if value not in ("0", "1"):
        raise ValueError(f"expected 0 or 1, got {value!r}")
    return value == "1"


def call_features_from_row(row: dict[str, str]) -> CallFeatures:
    """Validate one ``calls`` row read from CSV and return the typed feature record."""
    return CallFeatures(
        call_id=row["call_id"],
        run_id=row["run_id"],
        task_kind=row["task_kind"],
        context_level=row["context_level"],
        tool=row["tool"],
        effect=row["effect"],
        effect_in_task=_flag(row["effect_in_task"]),
        target_class=row["target_class"],
        destination_scope=row["destination_scope"],
        payload_kb=float(row["payload_kb"]),
        object_matches_task=row["object_matches_task"],
        recipient_matches_task=row["recipient_matches_task"],
        payload_class=row["payload_class"],
        payload_class_allowed=row["payload_class_allowed"],
        n_prev_calls=int(row["n_prev_calls"]),
        max_read_class_before=row["max_read_class_before"],
        sensitive_read_before=_flag(row["sensitive_read_before"]),
        external_send_before=_flag(row["external_send_before"]),
        untrusted_input_before=_flag(row["untrusted_input_before"]),
        recipient_changed=_flag(row["recipient_changed"]),
        retry_after_unknown=_flag(row["retry_after_unknown"]),
        ambiguous_lookup=_flag(row["ambiguous_lookup"]),
    )


def write_manifest(path: Path, manifest: dict[str, object]) -> None:
    """Pretty JSON with a trailing newline (pre-commit friendly)."""
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
