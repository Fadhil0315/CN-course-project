"""Exercise the dashboard as a user without making network requests."""

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

APP = Path(__file__).resolve().parents[1] / "app.py"


def test_demo_analysis_and_reset():
    app = AppTest.from_file(str(APP)).run(timeout=20)
    assert not app.exception

    app.button(key="analyze").click().run(timeout=20)
    assert not app.exception
    assert app.session_state["analysis_report"]["mode"] == "synthetic"
    assert app.session_state["analysis_report"]["risk"]["score"] == 0
    assert any(
        metric.label == "Final risk score" and metric.value == "0 / 100" for metric in app.metric
    )

    app.button(key="reset_report").click().run()
    assert not app.exception
    assert "analysis_report" not in app.session_state


def test_invalid_pasted_url_is_reported_without_a_final_score():
    app = AppTest.from_file(str(APP)).run(timeout=20)
    app.radio(key="input_method").set_value("Paste URL").run()
    app.text_input(key="url_input").set_value("javascript:alert(1)")
    app.button(key="analyze").click().run(timeout=20)

    assert not app.exception
    report = app.session_state["analysis_report"]
    assert report["mode"] == "offline"
    assert report["errors"]
    assert report["risk"]["score"] is None


def test_changing_inputs_preserves_report_without_running_analysis(monkeypatch):
    import pipeline

    app = AppTest.from_file(str(APP)).run(timeout=20)
    app.button(key="analyze").click().run(timeout=20)
    saved_report = app.session_state["analysis_report"]

    def unexpected_analysis(*args, **kwargs):
        raise AssertionError("A widget interaction must not trigger analysis")

    monkeypatch.setattr(pipeline, "run_demo", unexpected_analysis)
    monkeypatch.setattr(pipeline, "analyze_url_input", unexpected_analysis)
    app.radio(key="input_method").set_value("Paste URL").run()
    app.text_input(key="url_input").set_value("https://example.com").run()

    assert not app.exception
    assert not app.error
    assert app.session_state["analysis_report"] == saved_report


def test_incomplete_numeric_score_is_explicitly_provisional(monkeypatch):
    import pipeline

    report = pipeline.run_demo(pipeline.list_demo_cases()[0]["id"])
    report["risk"].update(
        score=23.0,
        verdict="insufficient_evidence",
        assessment_status="incomplete",
    )
    monkeypatch.setattr(pipeline, "run_demo", lambda case_id: report)

    app = AppTest.from_file(str(APP)).run(timeout=20)
    app.button(key="analyze").click().run(timeout=20)

    assert not app.exception
    assert any(
        metric.label == "Provisional risk score" and metric.value == "23 / 100"
        for metric in app.metric
    )
    assert not any(metric.label == "Final risk score" for metric in app.metric)
    assert any("core checks are incomplete" in warning.value for warning in app.warning)


def test_camera_empty_input_and_evaluation_controls():
    app = AppTest.from_file(str(APP)).run(timeout=20)
    app.radio(key="input_method").set_value("Camera").run()
    app.button(key="analyze").click().run()
    assert any("Take a photo" in warning.value for warning in app.warning)
    assert "analysis_report" not in app.session_state
    app.radio(key="input_method").set_value("Evaluation").run()
    app.button(key="evaluate").click().run(timeout=20)
    assert not app.exception
    assert app.session_state["evaluation"]["splits"]["test"]["all_layers"]["total"] == 10


def test_batch_drilldown_rerenders_saved_evidence_without_rescan(monkeypatch):
    from pipeline import run_demo

    app = AppTest.from_file(str(APP)).run(timeout=20)
    app.session_state["batch_results"] = [
        {"id": str(i), "name": case, "report": run_demo(case)}
        for i, case in enumerate(("ordinary", "suspicious"), start=1)
    ]

    def unexpected_scan(*args, **kwargs):
        raise AssertionError("Selecting a saved result must not scan again")

    monkeypatch.setattr("scan_runner.scan", unexpected_scan)
    app.run()
    app.selectbox(key="batch_selection").set_value("1").run()
    assert not app.exception
    assert any(metric.value == "0 / 100" for metric in app.metric)
    app.selectbox(key="batch_selection").set_value("2").run()
    assert not app.exception
    assert any(metric.value == "46 / 100" for metric in app.metric)


@pytest.mark.parametrize("method", ["Upload QR image", "Batch images", "Batch CSV"])
def test_uploaded_inputs_reach_real_scan_and_report_workflows(monkeypatch, method):
    from io import BytesIO

    import streamlit

    from demo_cases import qr_bytes

    ordinary = BytesIO(qr_bytes("https://example.com/"))
    ordinary.name = "ordinary.png"
    suspicious = BytesIO(qr_bytes("https://paypal.com.account-check.test/start"))
    suspicious.name = "suspicious.png"
    csv_file = BytesIO(b"name,url\nExample,https://example.com/\nInvalid,javascript:alert(1)\n")
    csv_file.name = "urls.csv"

    def uploaded_files(label, **kwargs):
        return {
            "qr_upload": ordinary,
            "batch_images": [ordinary, suspicious],
            "batch_csv": csv_file,
        }.get(kwargs.get("key"))

    # The browser file chooser is the only substituted boundary. The dashboard,
    # isolated scanner, parser, batch workers and report renderer execute normally.
    monkeypatch.setattr(streamlit, "file_uploader", uploaded_files)
    app = AppTest.from_file(str(APP)).run(timeout=20)
    app.radio(key="input_method").set_value(method).run()
    app.button(key="analyze").click().run(timeout=20)
    assert not app.exception and not app.error
    if method == "Upload QR image":
        report = app.session_state["analysis_report"]
        assert report["input"]["filename"] == "ordinary.png"
        assert report["layers"]["qr_structure"]["status"] == "complete"
    else:
        results = app.session_state["batch_results"]
        assert len(results) == 2
        assert results[0]["report"]["input"]["url"] == "https://example.com/"
        if method == "Batch CSV":
            assert results[1]["report"]["errors"]
        assert app.selectbox(key="batch_selection")


def test_bundled_model_is_available_in_dashboard():
    app = AppTest.from_file(str(APP)).run(timeout=20)
    app.radio(key="input_method").set_value("Paste URL").run()
    app.checkbox(key="use_bundled_model").set_value(True).run()
    app.text_input(key="url_input").set_value("https://example.com/")
    app.button(key="analyze").click().run(timeout=20)
    assert not app.exception and not app.error
    assert "experimental_ml" in app.session_state["analysis_report"]
