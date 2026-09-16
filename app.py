"""Streamlit interface for Fadhil's QR Phishing Shield implementation.

Analysis is explicitly triggered by a button. Keeping the returned report in
session state prevents widget interactions from repeating network requests.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import streamlit as st

from demo_cases import qr_bytes
from pipeline import (
    DEFAULT_APPROVED_HOSTS,
    analyze_image,
    analyze_url_input,
    list_demo_cases,
    run_demo,
)

LOGGER = logging.getLogger(__name__)
REPORT_KEY = "analysis_report"
PREVIEW_KEY = "analysis_qr_preview"

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
    [data-testid="stCaptionContainer"] { color: #53657a; }
    [data-testid="stCode"] { border: 1px solid #e2e8ee; border-radius: 10px; }
    hr { border-color: #e2e8ee; }
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
    if layer.get("status") == "not_implemented":
        st.info("Awaiting Charan’s module")
        st.write(
            "DNS records and TTLs, TLS certificate checks, and IP-to-ASN evidence will appear here after integration."
        )
        st.caption("This panel does not fabricate network measurements or a final risk score.")
    else:
        st.caption(f"Status: {_label(layer.get('status', 'unavailable'))}")
        st.json(layer.get("observations", {}))
        _render_errors(layer.get("errors", []))


def render_report(report: dict[str, Any]) -> None:
    """Render an existing report without triggering any analysis."""
    layers = report.get("layers", {})
    risk = report.get("risk", {})
    mode = report.get("mode", "offline")
    lexical = layers.get("lexical", {})
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
    provisional = final_score is not None and risk.get("assessment_status") != "complete_for_r2"
    if provisional:
        st.warning(
            "Assessment incomplete · One or more core checks are incomplete. This provisional score reflects available evidence, not a completed assessment."
        )
    metrics = st.columns(3)
    with metrics[0]:
        st.metric(
            "Provisional risk score" if provisional else "Final risk score",
            "Pending" if final_score is None else f"{final_score:.0f} / 100",
        )
        st.caption(
            "Requires Charan’s network and scoring modules"
            if final_score is None
            else _label(risk.get("verdict", "insufficient_evidence"))
        )
    with metrics[1]:
        st.metric("URL sub-score", _score_text(lexical))
        st.caption(f"{_label(lexical.get('status', 'unavailable'))} · provisional heuristics")
    with metrics[2]:
        st.metric("Redirect sub-score", _score_text(redirect))
        st.caption(f"{_label(redirect.get('status', 'unavailable'))} · provisional heuristics")

    st.caption(
        "Sub-scores summarize triggered rules. They are not probabilities of phishing and do not establish safety."
    )
    tabs = st.tabs(["Findings", "Redirect chain", "Network evidence", "Technical details"])
    with tabs[0]:
        _render_findings(layers)
    with tabs[1]:
        _render_redirects(redirect)
    with tabs[2]:
        _render_network(layers.get("network", {}))
    with tabs[3]:
        st.subheader("Check coverage")
        st.dataframe(
            [
                {
                    "Layer": name,
                    "Status": _label(layers.get(key, {}).get("status", "unavailable")),
                    "Planned weight": weight,
                }
                for key, name, weight in (
                    ("lexical", "URL analysis", "20%"),
                    ("redirect", "Redirect analysis", "25%"),
                    ("network", "DNS / TLS / ASN", "50%"),
                    ("qr_structure", "QR structure · Review 3", "5%"),
                )
            ],
            hide_index=True,
            width="stretch",
        )
        st.caption(
            "Weights and rules are provisional project choices. QR structural analysis is experimental and planned for Review 3."
        )
        if risk.get("limitations"):
            st.subheader("Assessment limitations")
            for limitation in risk["limitations"]:
                st.text(str(limitation))
        with st.expander("Full report · schema version 1"):
            st.json(report)


def main() -> None:
    st.set_page_config(page_title="QR Phishing Shield", page_icon="◈", layout="wide")
    st.markdown(STYLES, unsafe_allow_html=True)
    st.caption("QR PHISHING SHIELD  /  COMPUTER NETWORKS PROJECT")
    st.title("Look past the QR.")
    st.write(
        "Decode the destination, inspect the URL, and follow the evidence behind each redirect."
    )
    st.caption("Review 2 · Fadhil’s input, URL analysis, redirect tracing, and dashboard modules")

    input_column, context_column = st.columns([1.65, 1], gap="large")
    with input_column:
        with st.container(border=True):
            st.subheader("Start an analysis")
            source = st.radio(
                "Input method",
                ["Demo scenarios", "Upload QR image", "Paste URL"],
                horizontal=True,
                key="input_method",
            )
            demo_id = None
            uploaded_file = None
            pasted_url = ""
            live = False
            approved_hosts = tuple(DEFAULT_APPROVED_HOSTS)

            if source == "Demo scenarios":
                cases = list_demo_cases()
                by_id = {case["id"]: case for case in cases}
                demo_id = st.selectbox(
                    "Choose a scenario",
                    list(by_id),
                    format_func=lambda key: by_id[key]["title"],
                    key="demo_case",
                )
                if demo_id:
                    st.caption(by_id[demo_id]["description"])
                st.caption("Real local QR decoding + clearly labelled synthetic redirect evidence.")
            elif source == "Upload QR image":
                uploaded_file = st.file_uploader(
                    "Choose a QR image", type=["png", "jpg", "jpeg", "webp"], key="qr_upload"
                )
                st.caption(
                    "PNG, JPEG, or WebP · up to 8 MiB and 16 megapixels · one QR code containing an HTTP or HTTPS URL."
                )
            else:
                pasted_url = st.text_input(
                    "Destination URL", placeholder="https://example.com", key="url_input"
                )

            if source != "Demo scenarios":
                live = st.toggle("Enable live redirect tracing", value=False, key="live_tracing")
                if live:
                    host_text = st.text_input(
                        "Approved destination hosts",
                        value=", ".join(DEFAULT_APPROVED_HOSTS),
                        help="Exact hostnames only, separated by commas. Every redirect destination must be approved. Private and local addresses remain blocked.",
                        key="approved_hosts",
                    )
                    approved_hosts = tuple(
                        host.strip().lower() for host in host_text.split(",") if host.strip()
                    )
                    st.caption(
                        "Live mode sends bounded HTTP requests to approved public hosts. Adding a domain does not establish that it is safe."
                    )
                else:
                    st.caption(
                        "Offline by default: decode and inspect the URL without contacting its destination."
                    )

            action, reset = st.columns([2, 1])
            with action:
                analyze = st.button(
                    "Analyze destination", type="primary", width="stretch", key="analyze"
                )
            with reset:
                if st.button("Reset report", width="stretch", key="reset_report"):
                    st.session_state.pop(REPORT_KEY, None)
                    st.session_state.pop(PREVIEW_KEY, None)

            if analyze:
                if source == "Upload QR image" and uploaded_file is None:
                    st.warning("Choose a QR image before analyzing.")
                elif source == "Paste URL" and not pasted_url.strip():
                    st.warning("Enter a destination URL before analyzing.")
                elif live and not approved_hosts:
                    st.warning("Provide at least one approved hostname for live tracing.")
                else:
                    try:
                        with st.spinner("Inspecting the destination…"):
                            if source == "Demo scenarios":
                                report = run_demo(demo_id)
                            elif source == "Upload QR image":
                                report = analyze_image(
                                    uploaded_file.getvalue(),
                                    live=live,
                                    approved_hosts=approved_hosts,
                                )
                                report["input"]["filename"] = uploaded_file.name
                            else:
                                report = analyze_url_input(
                                    pasted_url, live=live, approved_hosts=approved_hosts
                                )
                        st.session_state[REPORT_KEY] = report
                        st.session_state.pop(PREVIEW_KEY, None)
                        if report.get("qr"):
                            if source == "Demo scenarios":
                                st.session_state[PREVIEW_KEY] = qr_bytes(report["qr"]["payload"])
                            elif source == "Upload QR image":
                                st.session_state[PREVIEW_KEY] = uploaded_file.getvalue()
                    except Exception:
                        LOGGER.exception("Analysis failed unexpectedly")
                        st.error(
                            "The analysis could not finish. Check the local application logs for details and try another input."
                        )

    with context_column:
        st.subheader("Follow the evidence")
        st.markdown("**01 · Decode**  \nRead a QR image or provide its destination URL.")
        st.markdown("**02 · Inspect**  \nExplain unusual URL features and examine redirect hops.")
        st.markdown(
            "**03 · Understand**  \nReview the observations, missing checks, and limitations."
        )
        st.divider()
        st.caption("CURRENT BUILD")
        st.write(
            "QR input, URL analysis, and redirect tracing are available. Charan’s DNS, TLS, ASN, and final scoring modules connect through a shared interface."
        )
        st.caption(
            "A low sub-score is not a safety guarantee. Avoid opening unfamiliar destinations from QR codes."
        )

    if REPORT_KEY in st.session_state:
        render_report(st.session_state[REPORT_KEY])
    else:
        st.divider()
        st.caption("READY WHEN YOU ARE")
        st.write("Start with a demo scenario to explore a complete input-to-evidence walkthrough.")


if __name__ == "__main__":
    main()
