"""Bounded, isolated batch scans with stable IDs and duplicate reuse per run."""

from __future__ import annotations

import csv
import hashlib
import io
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy

from qr_input.decoder import MAX_IMAGE_BYTES
from scan_runner import scan

MAX_BATCH_ITEMS = 50
MAX_BATCH_BYTES = 64 * 1024 * 1024


def parse_url_csv(payload: bytes) -> list[dict]:
    if len(payload) > 1024 * 1024:
        raise ValueError("URL CSV must be 1 MiB or smaller")
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("CSV must use UTF-8 encoding") from exc
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or "url" not in reader.fieldnames:
        raise ValueError("CSV needs a column named url; name is optional")
    items = []
    for row in reader:
        if len(items) >= MAX_BATCH_ITEMS:
            raise ValueError(f"A batch can contain at most {MAX_BATCH_ITEMS} URLs")
        if row.get("url") is None:
            raise ValueError("Every CSV row needs a URL field")
        items.append(
            {
                "kind": "url",
                "payload": row["url"],
                "name": row.get("name") or f"Row {len(items) + 1}",
            }
        )
    if not items:
        raise ValueError("The CSV contains no URL rows")
    return items


def analyze_batch(
    items: list[dict], *, workers: int = 2, progress=None, scanner=None, **options
) -> list[dict]:
    if not items or len(items) > MAX_BATCH_ITEMS:
        raise ValueError(f"Choose between 1 and {MAX_BATCH_ITEMS} inputs")
    if type(workers) is not int or not 1 <= workers <= 4:
        raise ValueError("Use between one and four workers")
    total = 0
    for item in items:
        payload = item["payload"]
        if item["kind"] not in {"image", "url", "demo"}:
            raise ValueError("Unsupported batch input")
        if item["kind"] == "image" and (
            not isinstance(payload, bytes) or len(payload) > MAX_IMAGE_BYTES
        ):
            raise ValueError("Each image must be bytes and at most 8 MiB")
        total += len(payload if isinstance(payload, bytes) else payload.encode())
    if total > MAX_BATCH_BYTES:
        raise ValueError("A batch must be at most 64 MiB in total")
    scanner = scanner or scan
    groups = {}
    for index, item in enumerate(items):
        raw = item["payload"] if isinstance(item["payload"], bytes) else item["payload"].encode()
        key = (item["kind"], hashlib.sha256(raw).hexdigest())
        groups.setdefault(key, []).append(index)
    results = [None] * len(items)
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        pending = {
            executor.submit(
                scanner, items[indices[0]]["kind"], items[indices[0]]["payload"], **options
            ): indices
            for indices in groups.values()
        }
        for future in as_completed(pending):
            indices = pending[future]
            try:
                report = future.result()
            except Exception:
                from pipeline import _base_report, _finish
                from shared.contracts import error_record

                report = _base_report(
                    items[indices[0]]["kind"], "live" if options.get("live") else "offline"
                )
                report["errors"].append(
                    error_record(
                        "BATCH_ITEM_FAILED",
                        "This item could not finish; other results remain available.",
                    )
                )
                report = _finish(report, use_network=False)
            for position, index in enumerate(indices):
                results[index] = {
                    "id": index + 1,
                    "name": items[index].get("name", f"Input {index + 1}"),
                    "reused_duplicate": position > 0,
                    "report": deepcopy(report),
                }
                done += 1
            if progress:
                progress(done, len(items))
    return results
