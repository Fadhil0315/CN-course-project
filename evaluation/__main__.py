"""Run: python -m evaluation {benchmark,robustness,calibrate,train}."""

import argparse
import csv
import json
from pathlib import Path

from .benchmark import calibrate, run_benchmark
from .fixtures import fixture_cases
from .lexical_model import train
from .robustness import run_robustness


def main():
    parser = argparse.ArgumentParser(description="Offline evaluation; no URLs are visited")
    parser.add_argument("command", choices=["benchmark", "robustness", "calibrate", "train"])
    parser.add_argument(
        "--manifest", type=Path, help="JSON manifest with saved reports, binary labels and splits"
    )
    parser.add_argument("--csv", type=Path, help="Training CSV: id,url,label,split,group")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "benchmark":
            result = run_benchmark(args.manifest)
        elif args.command == "robustness":
            result = run_robustness()
        elif args.command == "calibrate":
            result = calibrate(args.manifest)
        else:
            if args.csv:
                with args.csv.open(newline="", encoding="utf-8-sig") as stream:
                    rows = list(csv.DictReader(stream))
                for row in rows:
                    row["label"] = int(row["label"])
                source = f"User-supplied CSV: {args.csv.name}"
            else:
                rows = fixture_cases()
                source = "Synthetic teaching fixtures; NOT a production-trained classifier"
            result = train(rows, source=source)
            if args.csv and args.csv.with_suffix(".metadata.json").exists():
                result["dataset_metadata"] = json.loads(
                    args.csv.with_suffix(".metadata.json").read_text()
                )
                result["training_source"] = result["dataset_metadata"].get("source", source)
        serialized = json.dumps(result, indent=2, allow_nan=False)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(serialized + "\n")
            print(f"Saved {args.command} result to {args.output}")
        else:
            print(serialized)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
