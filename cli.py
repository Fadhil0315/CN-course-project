"""Command-line entry point for repeatable Review 2 evidence."""

import argparse
import json
from pathlib import Path

from pipeline import DEFAULT_APPROVED_HOSTS, analyze_image, analyze_url_input, run_demo


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inspect QR URLs; offline unless --live is supplied."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--url")
    source.add_argument("--image", type=Path)
    source.add_argument("--demo", choices=["ordinary", "suspicious", "loop"])
    parser.add_argument(
        "--live", action="store_true", help="Make bounded requests to approved public hosts."
    )
    parser.add_argument(
        "--approved-host",
        action="append",
        help="Exact hostname, repeated for each approved destination; replaces defaults.",
    )
    args = parser.parse_args()
    if args.demo and args.live:
        parser.error("Demo cases are always offline; omit --live.")
    options = {
        "live": args.live,
        "approved_hosts": tuple(args.approved_host or DEFAULT_APPROVED_HOSTS),
    }
    if args.demo:
        result = run_demo(args.demo)
    elif args.image:
        try:
            payload = args.image.read_bytes()
        except OSError as exc:
            parser.error(str(exc))
        result = analyze_image(payload, **options)
    else:
        result = analyze_url_input(args.url, **options)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
