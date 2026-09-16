"""Exercise the dashboard as a user without making network requests."""

from pathlib import Path

from streamlit.testing.v1 import AppTest

APP = Path(__file__).resolve().parents[1] / "app.py"


def test_demo_analysis_and_reset():
    app = AppTest.from_file(str(APP)).run(timeout=20)
    assert not app.exception

    app.button(key="analyze").click().run(timeout=20)
    assert not app.exception
    assert app.session_state["analysis_report"]["mode"] == "synthetic"
    assert app.session_state["analysis_report"]["risk"]["score"] is None
    assert any(
        metric.label == "Final risk score" and metric.value == "Pending" for metric in app.metric
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
