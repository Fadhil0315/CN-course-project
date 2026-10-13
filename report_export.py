"""JSON evidence and spreadsheet-safe CSV summaries."""

import csv
import io
import json


def summary_rows(results: list[dict]) -> list[dict]:
    rows = []
    for item in results:
        report = item["report"]
        risk = report["risk"]
        rows.append(
            {
                "id": item["id"],
                "name": item["name"],
                "url": report["input"].get("url") or "",
                "score": risk["score"],
                "verdict": risk["verdict"],
                "assessment": risk["assessment_status"],
                "coverage": risk["completed_weight"],
                "mode": report["mode"],
                "errors": "; ".join(e["code"] for e in report["errors"]),
                "seconds": report.get("elapsed_seconds"),
                "duplicate": item.get("reused_duplicate", False),
            }
        )
    return sorted(rows, key=lambda row: (row["score"] is not None, row["score"] or 0), reverse=True)


def export_json(value) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False)


def export_csv(results: list[dict]) -> str:
    rows = summary_rows(results)
    if not rows:
        return ""
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=list(rows[0]))
    writer.writeheader()
    for row in rows:
        # Untrusted names and URL evidence must not become spreadsheet formulas.
        writer.writerow(
            {
                key: "'" + value
                if isinstance(value, str)
                and value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r"))
                else value
                for key, value in row.items()
            }
        )
    return output.getvalue()
