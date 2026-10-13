import csv
import io
import json
import multiprocessing
import zipfile

import pytest

from batch import analyze_batch, parse_url_csv
from evaluation.benchmark import calibrate, run_benchmark, validate_splits
from evaluation.fixtures import fixture_cases
from evaluation.import_phiusiil import prepare
from evaluation.lexical_model import predict, train, validate_model
from evaluation.metrics import classification_metrics
from pipeline import analyze_url_input, run_demo
from report_export import export_csv
from scan_runner import scan


def test_csv_header_encoding_and_limits():
    assert parse_url_csv(b"\xef\xbb\xbfname,url\nTest,https://example.com\n")[0]["name"] == "Test"
    with pytest.raises(ValueError):
        parse_url_csv(b"link\nhttps://example.com\n")
    with pytest.raises(ValueError):
        parse_url_csv(b"url\n" + b"https://example.com\n" * 51)


def test_batch_reuses_duplicates_and_isolates_item_failures():
    calls = []
    progress = []

    def scanner(kind, value, **options):
        calls.append(value)
        if value == "bad":
            raise ValueError("bad input")
        return analyze_url_input(value)

    items = [
        {"kind": "url", "payload": value, "name": value}
        for value in ("https://example.com", "bad", "https://example.com")
    ]
    results = analyze_batch(items, scanner=scanner, progress=lambda n, total: progress.append(n))
    assert len(calls) == 2 and progress[-1] == 3
    assert results[2]["reused_duplicate"] is True
    assert results[1]["report"]["errors"][0]["code"] == "BATCH_ITEM_FAILED"
    results[0]["report"]["input"]["url"] = "changed"
    assert results[2]["report"]["input"]["url"] != "changed"


def test_csv_export_neutralizes_untrusted_formulas():
    row = {"id": 1, "name": "=HYPERLINK(1)", "report": analyze_url_input("https://example.com")}
    decoded = list(csv.DictReader(io.StringIO(export_csv([row]))))
    assert decoded[0]["name"].startswith("'=")


def test_bounded_worker_returns_report_and_leaves_no_child():
    result = scan("url", "https://example.com/", timeout=10)
    assert result["input"]["url"] == "https://example.com/"
    result = scan("url", "https://example.com/", timeout=0.001)
    assert result["errors"][0]["code"] == "SCAN_TIMEOUT"
    assert not multiprocessing.active_children()


def test_metrics_abstentions_and_zero_denominators():
    metrics = classification_metrics([1, 1, 0, 0], [True, None, True, False])
    assert metrics["precision"] == 0.5
    assert metrics["recall_on_assessed"] == 1
    assert metrics["recall_all_positives"] == 0.5
    assert metrics["coverage"] == 0.75
    assert classification_metrics([0], [False])["precision"] is None


def test_fixture_benchmark_and_validation_only_calibration():
    result = run_benchmark()
    assert result["splits"]["test"]["all_layers"]["total"] == 10
    assert result["splits"]["test"]["all_layers"]["abstained"] > 0
    assert result["splits"]["test"]["all_layers"]["false_negative"] > 0
    chosen = calibrate()
    assert chosen["selected_using"] == "validation split only"
    assert chosen["applied_to_application"] is False
    assert chosen["weights"]["qr_structure"] == 0.05


def test_domain_and_group_leakage_rejected():
    rows = [
        {"id": "1", "group": "a", "split": "train", "label": 0, "url": "https://example.com/"},
        {"id": "2", "group": "b", "split": "test", "label": 1, "url": "https://www.example.com/a"},
    ]
    with pytest.raises(ValueError, match="leaks"):
        validate_splits(rows)


def test_optional_classifier_is_serializable_and_not_in_composite_score():
    model = train(fixture_cases(), source="synthetic test only")
    validate_model(json.loads(json.dumps(model)))
    prediction = predict(model, "https://example.com/")
    assert 0 <= prediction["model_output"] <= 1
    ordinary = analyze_url_input("https://example.com/", lexical_model=model)
    assert "experimental_ml" in ordinary
    assert ordinary["risk"]["score"] == 0
    model["weights"][0] = float("nan")
    with pytest.raises(ValueError):
        validate_model(model)


def test_landing_url_is_in_lexical_findings_and_expected_domain_is_checked():
    report = run_demo("stacked")
    assert any(
        f["code"] == "BRAND_IN_SUBDOMAIN" and f["hop_index"] == 3
        for f in report["layers"]["lexical"]["findings"]
    )
    assert any(
        f["code"] == "EXPECTED_DOMAIN_MISMATCH" for f in report["layers"]["redirect"]["findings"]
    )
    assert report["risk"]["verdict"] == "suspicious"


def test_invalid_certificate_demo_abstains_with_explained_network_risk():
    report = run_demo("invalid_tls")
    assert report["layers"]["redirect"]["status"] == "unavailable"
    assert report["layers"]["network"]["score"] == 0.85
    assert report["risk"]["verdict"] == "insufficient_evidence"


def test_camera_bytes_use_image_pipeline_and_preserve_input_kind():
    from demo_cases import qr_bytes

    report = scan("camera", qr_bytes("https://example.com/"), timeout=10)
    assert report["input"]["kind"] == "camera"
    assert report["input"]["url"] == "https://example.com/"
    assert report["layers"]["qr_structure"]["status"] == "complete"
    assert report["layers"]["network"]["status"] == "unavailable"


def test_dataset_import_inverts_labels_and_keeps_domains_together(tmp_path):
    archive = tmp_path / "dataset.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(
            "PhiUSIIL_Phishing_URL_Dataset.csv",
            "URL,label\nhttps://example.com/,1\nhttps://example.com/,1\n"
            "https://www.example.com/path,1\nhttps://phish.test/,0\n"
            "javascript:alert(1),0\n",
        )
    rows, metadata = prepare(archive)
    assert len(rows) == 3
    assert next(row for row in rows if "phish.test" in row["url"])["label"] == 1
    benign = [row for row in rows if row["label"] == 0]
    assert len(benign) == 2 and len({row["split"] for row in benign}) == 1
    assert metadata["skipped"] == {"duplicate_url": 1, "unsupported_or_invalid": 1}
    assert rows == prepare(archive)[0]
