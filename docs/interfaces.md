# Integration contract — version 1

This document and `shared/contracts.py` define the boundary between Fadhil and Charan. Results contain only JSON-compatible primitives. Extra observation fields may be added; changing required fields or signatures requires agreement by both owners.

## Public functions

```python
# Fadhil
qr_input.decode_qr(image_bytes: bytes) -> dict
url_analysis.normalize_url(value: str) -> str
url_analysis.analyze_url(url: str) -> dict
redirect_analysis.trace_redirects(url: str, *, policy=None, resolver=None, transport=None) -> dict

# Charan supplies these exact import paths
network_analysis.analyzer.analyze_network(hops: list[dict]) -> dict
scoring.engine.calculate_risk(layers: dict[str, dict]) -> dict
```

No UI imports, printing-only outputs, application launch, or network calls at module-import time. The pipeline discovers Charan's functions via these import paths. Missing modules produce explicit pending results; malformed or failing modules produce unavailable/error results. Offline and synthetic modes never call the network provider.

## Redirect hop

```json
{
  "index": 0,
  "url": "https://example.com/start",
  "scheme": "https",
  "hostname": "example.com",
  "port": 443,
  "status_code": 302,
  "next_url": "https://example.com/end",
  "error": null,
  "network_eligible": true
}
```

`status_code` and `next_url` may be null. `error` is null or an ErrorRecord. The tracer returns the hop list inside `observations.hops`. Partial chains remain usable evidence; they are not complete assessments. Charan receives the discovered chain without repeating HTTP redirect discovery.

`network_eligible` is true only after exact-host/port policy and all DNS-address checks pass. The pipeline passes only those hops to Charan, preserving original indices. This includes a vetted host whose TLS connection failed before HTTP headers arrived, but excludes blocked/unrequested targets. Charan inspects each supplied `url`/`hostname`, never follows `next_url`, and must independently revalidate fresh DNS answers before connecting. The flag is not a permanent authorization. Incomplete redirect coverage still forces an incomplete final assessment.

## LayerResult

```json
{
  "status": "complete",
  "score": 0.25,
  "evidence_source": "live",
  "findings": [
    {
      "code": "EXAMPLE_RULE",
      "severity": "warning",
      "message": "A human-readable explanation",
      "hop_index": 0,
      "details": {}
    }
  ],
  "observations": {},
  "errors": []
}
```

- Status: `complete`, `partial`, `unavailable`, `not_implemented`.
- Score: finite 0–1; null when unavailable/not implemented. A complete layer must have a score.
- Evidence source: `live`, `recorded`, `synthetic`. For lexical analysis, `live` means calculated from the current input; it does **not** mean a network request occurred. Report `mode` records offline/live/synthetic execution.
- Finding severity: `info`, `warning`, `high`.
- ErrorRecord: `{"code": "TIMEOUT", "message": "...", "hop_index": 0}`. Non-hop-specific indices are null.
- Observations hold raw measurements, not just rule explanations. Unknown values are null.

Network observations must contain `hops`, each with `hop_index`, `hostname`, `dns`, `tls`, and `asn`. Each section includes its own status and available measurements. DNS: addresses, record types, observed TTLs. TLS: issuer, validity dates, hostname match, validation outcome. ASN: IP-to-ASN/organization mapping and lookup source. TLS is `not_applicable` for HTTP. This per-check status is distinct from the overall LayerResult status.

## Composite scoring input and output

Input keys: `lexical`, `redirect`, `network`, `qr_structure`, each holding a LayerResult.

Provisional weights: 0.20, 0.25, 0.50, 0.05 respectively. QR structure is not implemented in Review 2. Never give absent evidence a zero-risk score.

Output requires:

```json
{
  "score": null,
  "verdict": "insufficient_evidence",
  "assessment_status": "incomplete",
  "completed_weight": 0.45,
  "excluded_layers": ["network", "qr_structure"],
  "layer_contributions": {},
  "explanations": [],
  "limitations": ["Network analysis and scoring are pending."]
}
```

- `score`: null or finite 0–100.
- `completed_weight`: sum of original weights for complete layers only; not confidence or probability.
- If any of lexical/redirect/network is not complete, verdict must be `insufficient_evidence` and assessment_status must be `incomplete`, even if a provisional score can be calculated.
- When all three core layers are complete, assessment_status may be `complete_for_r2`; QR structure remains listed as excluded.
- Normalize the weighted sum by the weights of layers with non-null scores. With three complete core layers and QR structure absent, divide by 0.95. List partial layers in limitations.
- Bands for complete core evidence: score <35 `low_observed_risk`, 35–<70 `suspicious`, >=70 `high_risk`.
- Include per-layer weights/sub-scores/contributions and explain exclusions. These are provisional heuristics, not detection probabilities.

## Outer report (Fadhil)

Contains schema_version, created_at (UTC ISO timestamp), input (kind/url), mode, qr decoder metadata or null, layers, risk, and top-level errors. Demo reports also contain demo metadata. No raw image bytes appear in JSON. The UI stores this report in session state; rerendering the UI does not repeat network analysis.
