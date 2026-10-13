# Public interfaces and report contract

The application is organized by module. All results contain JSON-compatible primitives; finite scores and nested values are validated by `shared/contracts.py`.

## Entry points

```python
scan_runner.scan(kind, payload, *, timeout=60, **options) -> dict
batch.analyze_batch(items, *, workers=2, progress=None, **options) -> list[dict]
pipeline.analyze_url_input(url, *, live=False, approved_hosts=..., **options) -> dict
pipeline.analyze_image(image_bytes, *, live=False, approved_hosts=..., **options) -> dict
pipeline.run_demo(case_id) -> dict
```

Use `scan` for untrusted interactive input: it isolates work in a spawned process and terminates it after the deadline. Input kinds: url, image, camera, demo. Options: expected_domain, include_geolocation, expected_asns, expected_countries, lexical_model. The direct pipeline functions are useful for injected-dependency testing.

Batch items contain kind, payload and name. Results contain stable id, name, reused_duplicate and report. Exceptions affect only that item. The progress callback receives completed count and total. Batch results retain input order; export/UI summaries sort by score without changing IDs.

## Analysis modules

```python
qr_input.decode_qr(image_bytes: bytes) -> dict
url_analysis.normalize_url(value: str) -> str
url_analysis.analyze_url(url: str) -> dict
redirect_analysis.trace_redirects(url, *, policy=None, resolver=None, transport=None) -> dict
network_analysis.analyzer.analyze_network(hops, **collector_options) -> dict
qr_structure.analyze_structure(metadata) -> dict
scoring.engine.calculate_risk(layers) -> dict
```

No module launches the UI or contacts networks at import time. Offline/synthetic execution never calls live collectors. Invalid or failing network/scoring results are converted into explicit errors.

## Redirect hop

Fields: index (nonnegative integer), normalized url, scheme, hostname, port, status_code (integer or null), next_url (string or null), error (ErrorRecord or null), network_eligible (boolean).

The tracer records even blocked/failed destinations so the report can explain where it stopped. Only network_eligible hops reach network analysis, preserving indices. The marker is set after exact-host/port and **all-address** DNS checks. The collector independently validates fresh DNS answers before any connection and does not follow next_url.

## LayerResult

Every layer returns:

```json
{
  "status": "complete",
  "score": 0.25,
  "evidence_source": "live",
  "findings": [
    {"code": "EXAMPLE", "severity": "warning", "message": "Explanation",
     "hop_index": 0, "details": {"score_contribution": 0.25}}
  ],
  "observations": {},
  "errors": []
}
```

Status is complete, partial, unavailable, or legacy not_implemented. A complete layer needs a finite 0–1 score; unavailable/not_implemented must use null. Evidence source is live, recorded or synthetic. Locally calculated URL/QR measurements use live as current input evidence, even when report mode is offline. Report mode always identifies whether network requests were enabled.

Findings need code/message, severity info/warning/high, hop_index null or nonnegative integer, and details. ErrorRecord is `{"code": "...", "message": "...", "hop_index": null}`. Observations contain measurements independently of rule explanations.

Network observations contain hops, each with hop_index, hostname, dns, tls, asn and geolocation. Each check reports its own status and errors. DNS includes addresses and A/AAAA records with observed TTL. TLS includes validation outcome and available certificate/connection metadata; HTTP is not_applicable. ASN includes per-IP mappings with provider provenance and registry country. Optional geolocation is approximate and explicitly separate from registry country. Failed requested geolocation makes network coverage partial.

QR metadata includes structural and quality measurements from the decoder's rectified matrix. Coordinates refer to the declared preprocessing frame, which can differ from original image dimensions/orientation. Images themselves are never embedded in JSON.

## Risk result

Input keys: lexical, redirect, network, qr_structure. Weights: .20, .25, .50, .05.

Required output fields: score (null or 0–100), verdict, assessment_status, completed_weight, excluded_layers, layer_contributions, explanations and limitations. Additional weights and thresholds document the calculation.

- Any incomplete core lexical/redirect/network layer yields insufficient_evidence and incomplete.
- All core layers plus QR structure complete yields complete.
- All core layers complete with structure absent/partial yields complete_for_url, with the structure status/exclusion preserved.
- A malformed/non-URL input has no risk score.
- Available scores are renormalized by their available weight sum. Partial layer scores may contribute only to a provisional assessment.
- completed_weight sums original weights of complete layers; it is coverage, not probability.
- Low observed risk: score <35; suspicious: 35–<70; high risk: >=70.
- Contributions contain original weight, normalized weight, sub-score, points and layer status.

Legacy complete_for_r2 is still accepted at the validation boundary for old test/provider contracts; current scoring does not emit it.

## Outer report

schema_version (1), created_at (UTC ISO), input (kind/url and optional filename/expected_domain), mode (offline/live/synthetic), qr metadata or null, layers, risk and errors. Isolated scans add elapsed_seconds. Demos add id/title/description. An optional experimental_ml result is separate from the weighted risk calculation.

Export uses strict finite JSON. CSV summaries escape leading spreadsheet formula characters in untrusted string cells. No raw image/camera bytes or executable model objects are exported.
