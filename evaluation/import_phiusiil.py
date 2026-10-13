"""Prepare a reproducible domain-disjoint URL-only sample from UCI dataset 967.

No URL in the dataset is visited. Original labels are inverted: UCI 1=benign,
0=phishing; this project uses 1=phishing. Only URL and label columns are used.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import zipfile
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

from url_analysis import normalize_url, registered_domain

SOURCE = "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset"


def prepare(archive: Path, *, per_class: int = 6000) -> tuple[list[dict], dict]:
    if not 1 <= per_class <= 150000:
        raise ValueError("per_class must be between 1 and 150000")
    with zipfile.ZipFile(archive) as bundle:
        members = [
            name for name in bundle.namelist() if name.endswith("PhiUSIIL_Phishing_URL_Dataset.csv")
        ]
        if len(members) != 1 or bundle.getinfo(members[0]).file_size > 100_000_000:
            raise ValueError("Expected one bounded PhiUSIIL CSV")
        with bundle.open(members[0]) as stream:
            reader = csv.DictReader(io.TextIOWrapper(stream, encoding="utf-8-sig"))
            if not {"URL", "label"} <= set(reader.fieldnames or []):
                raise ValueError("Dataset is missing URL or label")
            # Keep smallest hashes rather than the first rows: source ordering
            # cannot silently decide which examples are sampled.
            by_class = {0: [], 1: []}
            skipped, seen = Counter(), set()
            for source_row in reader:
                raw = source_row["URL"]
                try:
                    url = normalize_url(raw)
                    original_label = int(source_row["label"])
                    if original_label not in {0, 1}:
                        raise ValueError("invalid label")
                except ValueError:
                    skipped["unsupported_or_invalid"] += 1
                    continue
                if url in seen:
                    skipped["duplicate_url"] += 1
                    continue
                seen.add(url)
                label = 1 - original_label
                domain = registered_domain(urlsplit(url).hostname)
                digest = hashlib.sha256(("qr-shield-v1:" + url).encode()).hexdigest()
                bucket = (
                    int(
                        hashlib.sha256(("qr-shield-split-v1:" + domain).encode()).hexdigest()[:8],
                        16,
                    )
                    % 100
                )
                split = "train" if bucket < 60 else "validation" if bucket < 80 else "test"
                by_class[label].append(
                    {"id": digest[:20], "url": url, "label": label, "split": split, "group": domain}
                )
    rows = sorted(
        (
            row
            for values in by_class.values()
            for row in sorted(values, key=lambda item: item["id"])[:per_class]
        ),
        key=lambda item: item["id"],
    )
    metadata = {
        "source": SOURCE,
        "citation": "Prasad, A. & Chandra, S. (2024). PhiUSIIL Phishing URL (Website). UCI Machine Learning Repository. DOI: 10.1016/j.cose.2023.103545",
        "license": "CC BY 4.0",
        "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "sample_rows": len(rows),
        "per_class_requested": per_class,
        "label_mapping": "project label = 1 - original UCI label",
        "sample_method": "smallest seeded URL SHA-256 values per class after validation/deduplication",
        "split_method": "seeded registered-domain SHA-256 bucket: 60% train, 20% validation, 20% test",
        "counts": dict(Counter(f"{row['split']}/label-{row['label']}" for row in rows)),
        "skipped": dict(skipped),
        "limitations": [
            "Historical URL dataset; distribution may differ from current QR phishing.",
            "Balanced sample prevalence is artificial; precision is not a deployment estimate.",
            "Only URL text is used; no supplied page-derived or label-derived features are used.",
            "Does not evaluate live DNS/TLS/ASN evidence or the four-layer composite.",
        ],
    }
    return rows, metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--per-class", type=int, default=6000)
    args = parser.parse_args()
    rows, metadata = prepare(args.archive, per_class=args.per_class)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["id", "url", "label", "split", "group"])
        writer.writeheader()
        writer.writerows(rows)
    args.output.with_suffix(".metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"Prepared {len(rows)} offline URL examples")


if __name__ == "__main__":
    main()
