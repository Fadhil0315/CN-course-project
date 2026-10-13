"""Local dashboard for QR Phishing Shield.

Analysis is explicitly triggered by a button. Keeping the returned report in
session state prevents widget interactions from repeating network requests.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import streamlit as st

from batch import analyze_batch, parse_url_csv
from demo_cases import qr_bytes
from pipeline import (
    DEFAULT_APPROVED_HOSTS,
    list_demo_cases,
    run_demo,
)
from report_export import export_csv, export_json, summary_rows
from scan_runner import scan

LOGGER = logging.getLogger(__name__)
REPORT_KEY = "analysis_report"
PREVIEW_KEY = "analysis_qr_preview"
BATCH_KEY = "batch_results"

STYLES = """
<style>
    .stApp { background: #f5f7fa; }
    .block-container { max-width: 1200px; padding-top: 2.8rem; padding-bottom: 4rem; }
    h1, h2, h3 { color: #13243a; letter-spacing: -0.025em; }
    h1 { font-weight: 750 !important; }
    [data-testid="stMetric"] { background: white; border: 1px solid #e2e8ee;
        border-radius: 12px; padding: 1.15rem; }
    [data-testid="stMetricValue"] { color: #13243a; }
    [data-testid="stVerticalBlockBorderWrapper"] > div {
        border-color: #e2e8ee !important; border-radius: 12px !important;
    }
    [data-testid="stFileUploader"] { border-radius: 10px; }
    button[data-baseweb="tab"] { padding-top: .75rem; padding-bottom: .75rem; }
    [data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] p {
        color: #34485e !important; opacity: 1 !important;
    }
    [data-testid="stCode"] { border: 1px solid #e2e8ee; border-radius: 10px; }
    hr { border-color: #e2e8ee; }
    ::selection { background: #c5e9e6; color: #13243a; }
    input, textarea { caret-color: #0b827d; }
    button:focus-visible, input:focus-visible { outline: 2px solid #0b827d; outline-offset: 3px; }
    [data-testid="stMetricValue"] { font-variant-numeric: tabular-nums; }
    @media (max-width: 640px) {
        .block-container { padding-top: 1.5rem; }
        h1 { font-size: 2.1rem !important; }
    }
</style>
"""


def _score_text(layer: dict[str, Any]) -> str:
    """Format a layer score without turning missing evidence into zero."""
    score = layer.get("score")
    return "Unavailable" if score is None else f"{score * 100:.0f} / 100"


def _label(value: str) -> str:
    return value.replace("_", " ").capitalize()


def _render_errors(errors: list[dict[str, Any]]) -> None:
    for error in errors:
        # st.text keeps external error text from becoming Markdown or a link.
        st.text(f"{error.get('code', 'ERROR')}: {error.get('message', 'Unknown error')}")


def _render_findings(layers: dict[str, Any]) -> None:
    observed = False
    for key, name in (
        ("lexical", "URL analysis"),
        ("redirect", "Redirect analysis"),
        ("network", "Network analysis"),
        ("qr_structure", "QR structure"),
    ):
        layer = layers.get(key, {})
        findings = layer.get("findings", [])
        if findings:
            observed = True
            st.subheader(name)
            for finding in findings:
                with st.container(border=True):
                    severity = _label(str(finding.get("severity", "info")))
                    st.caption(f"{severity.upper()} · {finding.get('code', 'OBSERVATION')}")
                    st.text(str(finding.get("message", "")))
                    if finding.get("details"):
                        with st.expander("Supporting details"):
                            st.json(finding["details"])
    if not observed:
        st.info(
            "No rule findings were returned by the available checks. This does not establish that the destination is safe."
        )


def _render_redirects(layer: dict[str, Any]) -> None:
    hops = layer.get("observations", {}).get("hops", [])
    if not hops:
        st.info(
            "No redirect chain is available for this analysis. Enable live redirects for an approved destination, or open a demo scenario."
        )
    else:
        source = layer.get("evidence_source", "live")
        st.caption(f"{len(hops)} recorded destination(s) · {_label(source)} evidence")
        rows = [
            {
                "Hop": hop.get("index", 0),
                "HTTP status": str(hop.get("status_code") or "—"),
                "Host": hop.get("hostname", ""),
                "URL": hop.get("url", ""),
                "Next URL": hop.get("next_url") or "—",
            }
            for hop in hops
        ]
        st.dataframe(rows, hide_index=True, width="stretch")
        st.caption("URLs are displayed as evidence. The table does not open destinations.")
    if layer.get("errors"):
        st.caption("Redirect check errors")
        _render_errors(layer["errors"])


def _render_network(layer: dict[str, Any]) -> None:
    st.caption(f"Status: {_label(layer.get('status', 'unavailable'))}")
    hops = layer.get("observations", {}).get("hops", [])
    if not hops:
        st.info("Use a demo or enable live checks to collect DNS, TLS and ASN evidence.")
    for hop in hops:
        with st.expander(f"Hop {hop['hop_index']} · {hop['hostname']}", expanded=len(hops) == 1):
            st.write("DNS records")
            if hop["dns"].get("records"):
                st.dataframe(hop["dns"]["records"], hide_index=True, width="stretch")
            else:
                st.json(hop["dns"])
            st.write("TLS identity and connection")
            st.json(hop["tls"], expanded=False)
            st.write("ASN and hosting organization")
            st.json(hop["asn"], expanded=False)
            if hop.get("geolocation", {}).get("status") != "not_requested":
                st.write("Approximate IP location")
                st.json(hop.get("geolocation", {}), expanded=False)
    _render_errors(layer.get("errors", []))


def render_report(report: dict[str, Any]) -> None:
    """Render an existing report without triggering any analysis."""
    layers = report.get("layers", {})
    risk = report.get("risk", {})
    mode = report.get("mode", "offline")
    redirect = layers.get("redirect", {})

    st.divider()
    heading, download = st.columns([3, 1], vertical_alignment="center")
    with heading:
        st.header("Analysis report")
        st.caption("This report stays available until you analyze another input or reset it.")
        if report.get("created_at"):
            st.caption(f"Generated: {report['created_at']}")
    with download:
        st.download_button(
            "Download evidence JSON",
            json.dumps(report, indent=2, ensure_ascii=False),
            file_name="qr-phishing-shield-report.json",
            mime="application/json",
            width="stretch",
        )

    if mode == "synthetic":
        st.info(
            "Demo evidence · The QR is decoded locally. Redirect responses are synthetic fixtures; no live destination is contacted."
        )
    elif mode == "offline":
        st.info(
            "Offline analysis · The URL is checked locally. No live redirect or network requests are made."
        )
    else:
        st.info(
            "Live analysis · HTTP requests use the approved destination list. Inspect each layer’s status below for available evidence."
        )

    url = report.get("input", {}).get("url")
    if PREVIEW_KEY in st.session_state:
        st.image(st.session_state[PREVIEW_KEY], width=150, caption="Analyzed QR image")
    if url:
        st.caption("DECODED OR PROVIDED URL")
        st.code(url, language=None)
    _render_errors(report.get("errors", []))

    final_score = risk.get("score")
    provisional = final_score is not None and risk.get("assessment_status") == "incomplete"
    if provisional:
        st.warning(
            "Assessment incomplete · One or more core checks are incomplete. This provisional score reflects available evidence, not a completed assessment."
        )
    metrics = st.columns(3)
    with metrics[0]:
        st.metric(
            "Provisional risk score" if provisional else "Final risk score",
            "Unavailable" if final_score is None else f"{final_score:.0f} / 100",
        )
        st.caption(
            "Insufficient evidence"
            if final_score is None
            else _label(risk.get("verdict", "insufficient_evidence"))
        )
    with metrics[1]:
        st.metric("Evidence coverage", f"{risk.get('completed_weight', 0):.0%}")
        st.caption("Weight of fully completed checks; not confidence")
    with metrics[2]:
        st.metric("Observed destinations", len(redirect.get("observations", {}).get("hops", [])))
        st.caption(f"{_label(redirect.get('status', 'unavailable'))} redirect trace")

    st.caption(
        "Sub-scores summarize triggered rules. They are not probabilities of phishing and do not establish safety."
    )
    tabs = st.tabs(
        ["Findings", "Redirect chain", "Network evidence", "QR structure", "Score breakdown"]
    )
    with tabs[0]:
        _render_findings(layers)
    with tabs[1]:
        _render_redirects(redirect)
    with tabs[2]:
        _render_network(layers.get("network", {}))
    with tabs[3]:
        structure = layers.get("qr_structure", {})
        st.caption("Experimental integrity checks · 5% weight")
        if structure.get("status") == "complete":
            data = structure["observations"]
            st.write(
                f"Version {data['version']} · {data['module_count']} × {data['module_count']} modules · ECC {data['format']['ecc'] or 'unknown'}"
            )
            st.json(data, expanded=False)
        else:
            st.info("QR structure is available when a readable QR image is supplied.")
    with tabs[4]:
        st.subheader("Check coverage")
        st.dataframe(
            [
                {
                    "Layer": name,
                    "Status": _label(layers.get(key, {}).get("status", "unavailable")),
                    "Weight": weight,
                    "Sub-score": _score_text(layers.get(key, {})),
                    "Points": risk.get("layer_contributions", {}).get(key, {}).get("points"),
                }
                for key, name, weight in (
                    ("lexical", "URL analysis", "20%"),
                    ("redirect", "Redirect analysis", "25%"),
                    ("network", "DNS / TLS / ASN", "50%"),
                    ("qr_structure", "QR structure", "5%"),
                )
            ],
            hide_index=True,
            width="stretch",
        )
        st.caption(
            "Weights are 20% URL, 25% redirects, 50% network and 5% QR structure. Available weights are renormalized when evidence is absent."
        )
        if risk.get("limitations"):
            st.subheader("Assessment limitations")
            for limitation in risk["limitations"]:
                st.text(str(limitation))
        with st.expander("Full report · schema version 1"):
            st.json(report)
        if report.get("experimental_ml"):
            st.subheader("Experimental lexical classifier")
            st.json(report["experimental_ml"])


def render_batch(results: list[dict]) -> None:
    st.divider()
    st.header("Batch results")
    st.caption(
        "Ranked by observed score. Incomplete assessments remain marked; a high provisional score does not make the evidence complete."
    )
    rows = summary_rows(results)
    st.dataframe(rows, hide_index=True, width="stretch")
    left, right = st.columns(2)
    left.download_button(
        "Download batch JSON",
        export_json(results),
        "qr-batch.json",
        "application/json",
        width="stretch",
    )
    right.download_button(
        "Download summary CSV", export_csv(results), "qr-batch.csv", "text/csv", width="stretch"
    )
    by_id = {item["id"]: item for item in results}
    selection = st.selectbox(
        "Inspect a batch item",
        [row["id"] for row in rows],
        format_func=lambda value: f"{value} · {by_id[value]['name']}",
        key="batch_selection",
    )
    render_report(by_id[selection]["report"])


def _options() -> dict:
    live = st.toggle("Enable live network checks", value=False, key="live_tracing")
    options = {"live": live, "approved_hosts": tuple(DEFAULT_APPROVED_HOSTS)}
    if live:
        hosts = st.text_input(
            "Approved destination hosts",
            value=", ".join(DEFAULT_APPROVED_HOSTS),
            help="Exact hostnames, separated by commas. Every redirect destination must be listed; private addresses remain blocked.",
            key="approved_hosts",
        )
        options["approved_hosts"] = tuple(
            host.strip().lower() for host in hosts.split(",") if host.strip()
        )
        st.caption(
            "Sends HTTP headers requests and TLS handshakes to approved public destinations. ASN lookups use Team Cymru through DNS. Each scan stops after 60 seconds."
        )
    else:
        st.caption("Offline: image and URL checks only. Network evidence stays unavailable.")
    with st.expander("Expected destination and optional checks"):
        expected = st.text_input(
            "Expected domain (optional)", placeholder="paypal.com", key="expected_domain"
        )
        options["expected_domain"] = expected.strip() or None
        if live:
            options["include_geolocation"] = st.checkbox(
                "Include approximate IP geolocation",
                help="Sends resolved public IP addresses to ipwho.is. URLs and QR images are not sent to this provider.",
            )
            asns = st.text_input(
                "Expected final hosting ASNs (optional)", placeholder="13335, 15169"
            )
            countries = st.text_input(
                "Expected country codes (optional)",
                placeholder="IN, US",
                disabled=not options["include_geolocation"],
            )
            if asns.strip():
                try:
                    options["expected_asns"] = tuple(
                        int(item.strip().removeprefix("AS")) for item in asns.upper().split(",")
                    )
                    if any(
                        number <= 0 or number > 4294967295 for number in options["expected_asns"]
                    ):
                        raise ValueError
                except ValueError:
                    options["invalid"] = "Use comma-separated positive ASN numbers."
            options["expected_countries"] = (
                tuple(item.strip().upper() for item in countries.split(",") if item.strip())
                if options["include_geolocation"]
                else ()
            )
            if any(len(code) != 2 or not code.isalpha() for code in options["expected_countries"]):
                options["invalid"] = "Use two-letter country codes, such as IN or US."
        if st.checkbox("Use bundled experimental lexical classifier", key="use_bundled_model"):
            model_path = Path(__file__).resolve().parent / "models" / "lexical-phiusiil.json"
            try:
                options["lexical_model"] = json.loads(model_path.read_text())
                st.caption(
                    "Trained on a domain-separated sample of the historical UCI PhiUSIIL URL dataset. Its output is separate from the four-layer score."
                )
            except (OSError, ValueError):
                options["invalid"] = (
                    "The bundled model is unavailable. Train it using the README instructions."
                )
        model = st.file_uploader(
            "Optional lexical model JSON",
            type=["json"],
            help="A model created by the included training command. This experimental signal is shown separately from the four-layer score.",
        )
        if model:
            try:
                from evaluation.lexical_model import validate_model

                options["lexical_model"] = json.loads(model.getvalue())
                validate_model(options["lexical_model"])
            except (ValueError, KeyError, TypeError):
                options["invalid"] = "The lexical model JSON is invalid."
    return options


def main() -> None:
    st.set_page_config(page_title="QR Phishing Shield", layout="wide")
    st.markdown(STYLES, unsafe_allow_html=True)
    st.title("QR Phishing Shield")
    st.write(
        "Inspect a QR destination, trace its redirects, and see the evidence behind its risk score."
    )
    source = st.radio(
        "Input method",
        [
            "Demo scenarios",
            "Upload QR image",
            "Paste URL",
            "Camera",
            "Batch images",
            "Batch CSV",
            "Evaluation",
        ],
        horizontal=True,
        key="input_method",
    )
    if source == "Evaluation":
        st.subheader("Reproducible evaluation")
        st.write(
            "Run the bundled labelled synthetic scenarios, compare the four layers, and measure QR decoding under image transformations."
        )
        st.caption(
            "These fixtures test behavior. Their metrics do not establish real-world phishing accuracy."
        )
        if st.button("Run fixture benchmark", key="evaluate"):
            from evaluation.benchmark import run_benchmark

            with st.spinner("Evaluating labelled fixtures…"):
                st.session_state["evaluation"] = run_benchmark()
        if st.button("Run image robustness checks", key="robustness"):
            from evaluation.robustness import run_robustness

            with st.spinner("Measuring image decoding…"):
                st.session_state["robustness_results"] = run_robustness()
        for key, title in (
            ("evaluation", "Fixture benchmark"),
            ("robustness_results", "Image robustness"),
        ):
            if key in st.session_state:
                st.subheader(title)
                st.json(st.session_state[key], expanded=False)
                st.download_button(
                    f"Download {title.lower()}",
                    export_json(st.session_state[key]),
                    f"{key}.json",
                    "application/json",
                )
        return

    input_column, context_column = st.columns([1.8, 1], gap="large")
    with input_column:
        demo_id, uploaded, pasted_url, captured, files, csv_file = None, None, "", None, [], None
        options = {}
        if source == "Demo scenarios":
            cases = {case["id"]: case for case in list_demo_cases()}
            demo_id = st.selectbox(
                "Choose a scenario",
                list(cases),
                format_func=lambda key: cases[key]["title"],
                key="demo_case",
            )
            st.caption(cases[demo_id]["description"])
            st.caption(
                "Actual QR decoding and scoring, with labelled synthetic DNS, TLS, ASN and HTTP fixtures. No external requests."
            )
        elif source == "Upload QR image":
            uploaded = st.file_uploader(
                "Choose a QR image", type=["png", "jpg", "jpeg", "webp"], key="qr_upload"
            )
            st.caption("One QR per image · PNG, JPEG or WebP · up to 8 MiB and 16 megapixels")
        elif source == "Paste URL":
            pasted_url = st.text_input(
                "Destination URL", placeholder="https://example.com", key="url_input"
            )
        elif source == "Camera":
            st.caption(
                "Take a photo, then choose Analyze destination. Retaking or changing settings does not start a scan."
            )
            captured = st.camera_input("Capture one QR code", key="camera_capture")
            st.caption(
                "If camera access is unavailable in this browser, use Chrome/Safari on localhost or upload a photo."
            )
        elif source == "Batch images":
            files = st.file_uploader(
                "Choose QR images",
                type=["png", "jpg", "jpeg", "webp"],
                accept_multiple_files=True,
                key="batch_images",
            )
            st.caption("Up to 50 images · 8 MiB per image · 64 MiB total · two scans at a time")
        else:
            csv_file = st.file_uploader("Choose a URL CSV", type=["csv"], key="batch_csv")
            st.caption("UTF-8 CSV with a url column and optional name column · up to 50 rows")
            st.download_button(
                "Download CSV template",
                "name,url\nExample,https://example.com/\n",
                "qr-urls-template.csv",
                "text/csv",
            )
        if source != "Demo scenarios":
            options = _options()
        action, reset = st.columns([2, 1])
        analyze = action.button(
            "Analyze batch" if source.startswith("Batch") else "Analyze destination",
            type="primary",
            width="stretch",
            key="analyze",
        )
        if reset.button("Reset report", width="stretch", key="reset_report"):
            for key in (REPORT_KEY, PREVIEW_KEY, BATCH_KEY, "batch_selection"):
                st.session_state.pop(key, None)

        if analyze:
            error = options.pop("invalid", None)
            if source == "Upload QR image" and uploaded is None:
                error = "Choose a QR image before analyzing."
            elif source == "Paste URL" and not pasted_url.strip():
                error = "Enter a destination URL before analyzing."
            elif source == "Camera" and captured is None:
                error = "Take a photo before analyzing."
            elif source == "Batch images" and not files:
                error = "Choose at least one QR image."
            elif source == "Batch CSV" and csv_file is None:
                error = "Choose a CSV file before analyzing."
            elif options.get("live") and not options["approved_hosts"]:
                error = "Provide at least one approved hostname for live checks."
            if error:
                st.warning(error)
            else:
                try:
                    if source.startswith("Batch"):
                        items = (
                            parse_url_csv(csv_file.getvalue())
                            if source == "Batch CSV"
                            else [
                                {"kind": "image", "payload": file.getvalue(), "name": file.name}
                                for file in files
                            ]
                        )
                        progress = st.progress(0, text="Preparing batch…")
                        with st.spinner("Inspecting batch inputs…"):
                            results = analyze_batch(
                                items,
                                progress=lambda done, total: progress.progress(
                                    done / total, text=f"Completed {done} of {total}"
                                ),
                                **options,
                            )
                        st.session_state[BATCH_KEY] = results
                        for key in (REPORT_KEY, PREVIEW_KEY, "batch_selection"):
                            st.session_state.pop(key, None)
                    else:
                        with st.spinner("Inspecting the destination…"):
                            if source == "Demo scenarios":
                                report = run_demo(demo_id)
                            elif source in {"Upload QR image", "Camera"}:
                                file = captured if source == "Camera" else uploaded
                                report = scan(
                                    "camera" if source == "Camera" else "image",
                                    file.getvalue(),
                                    **options,
                                )
                                report["input"]["filename"] = file.name
                            else:
                                report = scan("url", pasted_url, **options)
                        st.session_state[REPORT_KEY] = report
                        st.session_state.pop(BATCH_KEY, None)
                        st.session_state.pop(PREVIEW_KEY, None)
                        if report.get("qr"):
                            st.session_state[PREVIEW_KEY] = (
                                qr_bytes(report["qr"]["payload"])
                                if source == "Demo scenarios"
                                else file.getvalue()
                            )
                except ValueError as exc:
                    st.error(str(exc))
                except Exception as exc:
                    LOGGER.error("Analysis failed: %s", type(exc).__name__)
                    st.error(
                        "The scan could not finish. Try another input or restart the local app."
                    )

    with context_column:
        st.subheader("Four layers of evidence")
        st.write(
            "URL rules reveal misleading names. Redirect tracing shows where the link leads. DNS, TLS and ASN checks explain the destination's network posture. QR structure adds a small experimental integrity signal."
        )
        st.caption("20% URL · 25% redirects · 50% network · 5% QR structure")
        st.divider()
        st.write(
            "Results stay in this session until you reset them. Downloads can contain full URLs and query strings."
        )
        st.caption(
            "A low observed risk score is not a guarantee of safety. Unknown or failed checks remain visible."
        )

    if BATCH_KEY in st.session_state:
        render_batch(st.session_state[BATCH_KEY])
    elif REPORT_KEY in st.session_state:
        render_report(st.session_state[REPORT_KEY])
    else:
        st.divider()
        st.write(
            "Start with a demo to explore a complete evidence report, or choose your own input above."
        )


if __name__ == "__main__":
    main()
