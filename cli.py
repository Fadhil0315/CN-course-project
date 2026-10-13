"""Command-line single and batch scans with bounded execution."""

import argparse
import json
from pathlib import Path

from batch import analyze_batch, parse_url_csv
from demo_cases import DEMO_CASES
from pipeline import DEFAULT_APPROVED_HOSTS
from report_export import export_csv, export_json
from scan_runner import scan


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inspect QR URLs; offline unless --live is supplied."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--url")
    source.add_argument("--image", type=Path)
    source.add_argument("--demo", choices=list(DEMO_CASES))
    source.add_argument("--batch-csv", type=Path)
    source.add_argument("--batch-images", type=Path, nargs="+")
    source.add_argument("--demo-batch", action="store_true")
    parser.add_argument(
        "--live",
        action="store_true",
        help="Request headers and network evidence from approved public hosts.",
    )
    parser.add_argument(
        "--approved-host",
        action="append",
        help="Exact hostname; repeat per destination. Replaces defaults.",
    )
    parser.add_argument("--expected-domain", help="Expected final registered domain.")
    parser.add_argument(
        "--geolocation",
        action="store_true",
        help="Optional approximate IP location through ipwho.is.",
    )
    parser.add_argument("--expected-asn", type=int, action="append")
    parser.add_argument("--expected-country", action="append")
    parser.add_argument("--model", type=Path, help="Optional experimental lexical model JSON.")
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--format", choices=["json", "csv"], default="json")
    args = parser.parse_args()
    if (args.demo or args.demo_batch) and args.live:
        parser.error("Demo cases are always offline; omit --live.")
    if args.geolocation and not args.live:
        parser.error("--geolocation requires --live")
    if args.expected_country and not args.geolocation:
        parser.error("--expected-country requires --geolocation")
    if any(number <= 0 or number > 4294967295 for number in args.expected_asn or []):
        parser.error("Expected ASNs must be positive 32-bit numbers")
    if any(len(value) != 2 or not value.isalpha() for value in args.expected_country or []):
        parser.error("Country codes must contain two letters")
    options = {
        "live": args.live,
        "approved_hosts": tuple(args.approved_host or DEFAULT_APPROVED_HOSTS),
        "expected_domain": args.expected_domain,
        "include_geolocation": args.geolocation,
        "expected_asns": tuple(args.expected_asn or ()),
        "expected_countries": tuple(value.upper() for value in args.expected_country or ()),
        "timeout": args.timeout,
    }
    try:
        if args.model:
            from evaluation.lexical_model import validate_model

            options["lexical_model"] = json.loads(args.model.read_text())
            validate_model(options["lexical_model"])
        if args.demo_batch:
            items = [
                {"kind": "demo", "payload": key, "name": value["title"]}
                for key, value in DEMO_CASES.items()
            ]
        elif args.batch_csv:
            items = parse_url_csv(args.batch_csv.read_bytes())
        elif args.batch_images:
            items = [
                {"kind": "image", "payload": path.read_bytes(), "name": path.name}
                for path in args.batch_images
            ]
        else:
            items = None
        if items is not None:
            result = analyze_batch(items, workers=args.workers, **options)
            rows = result
        else:
            kind = "demo" if args.demo else "image" if args.image else "url"
            payload = args.demo or (args.image.read_bytes() if args.image else args.url)
            result = scan(kind, payload, **options)
            rows = [
                {
                    "id": 1,
                    "name": args.image.name if args.image else args.demo or "URL",
                    "report": result,
                }
            ]
        serialized = export_csv(rows) if args.format == "csv" else export_json(result)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(serialized + "\n", encoding="utf-8")
            print(f"Saved report to {args.output}")
        else:
            print(serialized)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
