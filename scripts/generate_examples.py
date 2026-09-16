"""Regenerate non-malicious QR inputs used by the review demonstration."""

from pathlib import Path

from demo_cases import DEMO_CASES, qr_bytes


def main() -> None:
    destination = Path(__file__).resolve().parents[1] / "examples"
    destination.mkdir(exist_ok=True)
    for key, case in DEMO_CASES.items():
        (destination / f"{key}.png").write_bytes(qr_bytes(case["url"]))
    (destination / "non_url.png").write_bytes(qr_bytes("This QR contains text, not a website."))


if __name__ == "__main__":
    main()
