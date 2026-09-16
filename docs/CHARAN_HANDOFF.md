# Charan's implementation brief

## Context

QR Phishing Shield is a two-person Computer Networks course project. Fadhil implements QR input, URL rules, redirect discovery, application orchestration, and the Streamlit dashboard. You implement **network evidence and composite scoring**. This is an implementation project with no novelty or proven-accuracy claim.

Read `interfaces.md` first. It defines the exact signatures and shapes Fadhil's code already expects. You do not need to redesign the UI or redirect tracer.

## Deliverables

1. `network_analysis/dns_checks.py`: DNS address records, types, observed TTLs, and explicit failures. Use finite DNS lifetime and per-scan caching.
2. `network_analysis/tls_checks.py`: for HTTPS, issuer, certificate validity dates, trust and hostname validation. HTTP has no applicable TLS check. Certificate verification failures must not be silently retried with verification disabled and presented as successful validation.
3. `network_analysis/asn_lookup.py`: public-IP ASN and organization information with lookup source and timeouts. Document chosen provider, service constraints, and optional credential configuration. Missing provider data remains missing evidence.
4. `network_analysis/analyzer.py`: export `analyze_network(hops: list[dict]) -> dict`; collect evidence for the supplied chain, produce an explainable network sub-score, and preserve each hop association.
5. `scoring/config.py` and `scoring/engine.py`: export `calculate_risk(layers: dict[str, dict]) -> dict` with documented weights, exclusions, provisional score bands, and explanations.
6. Tests, sample outputs, dependency notes, and your actual issue/contribution log.

Fadhil's implementation has no replacement network/scoring backend. Until your modules arrive the final score is null and network analysis is pending. Synthetic redirect demos do not call your live network analyzer.

## Implementation order

1. Create both packages with `__init__.py`, and match the interface with deterministic test fixtures.
2. Implement DNS, TLS, and ASN collectors separately. Unit tests should inject external dependencies and remain offline.
3. Combine collectors in analyze_network; validate its output with `shared.contracts.validate_layer_result`.
4. Implement scoring and verify it with hand-calculated examples, including partial/missing layers.
5. Test an approved benign live destination separately from the offline test suite. Do not visit live phishing infrastructure for the demo.
6. Run the shared app and integration tests after installing your modules and dependencies.

## Network and interpretation rules

- Only analyze the supplied public HTTP(S) destinations. Revalidate resolved addresses immediately before connecting; block private/loopback/link-local/reserved destinations, and pin vetted addresses for sockets to avoid a second unvalidated resolution. These checks must also exist in your collector; previous tracer checks do not protect a later fresh DNS lookup.
- Bound DNS, sockets, provider lookups, and retries. Cache repeated host/IP observations within an analysis; preserve evidence per hop. Document any total-runtime limits.
- Do not fetch page bodies, execute scripts, follow redirects again, or import Streamlit into your modules.
- Low observed DNS TTLs, certificate recency, and provider identity are context, not proof of phishing. Do not penalize a legitimate CA merely for being free. Do not equate certificate dates with domain registration dates.
- ASN lookup is infrastructure context; avoid invented malicious-provider lists. No brand/ASN mismatch claim without a maintained reference mapping.
- Errors are missing evidence. All failed checks must not produce a complete low-risk result. Expired/untrusted/mismatched TLS is a security finding, but does not prove phishing.
- Keep observations and rule explanations separate. Record why each scored rule fired.

## Scoring contract

Use the shared provisional weights: lexical 20%, redirects 25%, network 50%, QR structure 5%. QR structure is experimental and pending Review 3; you do not implement it now. Exclude absent scores and normalize by available weight, explicitly listing exclusions. Complete R2 core evidence normalizes by 0.95. A partial/missing core layer forces an incomplete/insufficient_evidence verdict. Include completed_weight as coverage, not confidence. Exact fields and score bands are in interfaces.md.

## Tests required

- DNS success, no answer, timeout, mixed public/private answers, and cache reuse.
- Valid HTTPS, expired/untrusted/hostname-mismatched certificate, timeout, and HTTP-not-applicable.
- ASN success and provider unavailable.
- Mixed successful and failed hops retain evidence and remain partial as appropriate.
- Zero/all/missing/partial scores, bounded output, exclusions, normalization, and thresholds.
- Returned results pass the shared validator and render in Fadhil's dashboard.

## Integration and ownership

Your files: network_analysis/, scoring/, their tests, and network/scoring fixtures/docs. Coordinate any changes to shared/contracts.py, docs/interfaces.md, or root dependency files. Tell Fadhil your new dependencies; do not replace his pyproject.toml or lock wholesale.

From the project directory, the pipeline imports your functions automatically at the exact paths above. Offline inspection never calls analyze_network. Live tracing forwards only hops whose network_eligible flag is true after host/port/public-address checks, including vetted TLS-failure destinations; original hop indices are preserved. Inspect supplied hostnames only, never follow next_url. Independently revalidate fresh DNS answers immediately before your own connections. When no hop qualifies, analysis is explicitly skipped. An incomplete redirect layer still forces an incomplete final assessment.

Use https://github.com/Fadhil0315/CN-qr-phishing. Start from Fadhil's `fadhil/input-redirect-ui` implementation branch, create `charan/network-scoring`, and commit under your own account. Agree on an integration branch with Fadhil before opening the merge PR. Preserve real local history if you have it; do not backdate or manufacture history. Document AI assistance and demonstrate your understanding according to course rules. Fadhil reviews your interface and you review his chain output; both run the integrated demo.

## Definition of done

Both functions import without UI side effects; all offline tests pass; one approved live example yields real evidence or explicit failures; missing evidence cannot yield a reassuring verdict; the dashboard displays your observations and score; installation notes and limitations are accurate.
