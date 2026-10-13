# QR Phishing Shield

A complete local Computer Networks course application for explainable QR destination inspection. Built by Fadhil with Codex assistance. Four analysis layers combine URL rules, HTTP redirect behavior, DNS/TLS/ASN evidence, and low-weight QR structure checks. No novelty or validated real-world detection claim is made.

## Start

From this directory, with Python **3.12 or newer**:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-lock.txt
python -m pip install --no-deps -e .
./run.sh
```

The existing environment is already installed. On this Mac, `./run.sh` is enough. Streamlit binds to localhost. If port 8501 is occupied, use `./run.sh --server.port 8502`.

## Workflows

- **Demo scenarios:** actual QR decoding and production scoring with explicitly synthetic HTTP, DNS, TLS, ASN and location fixtures. Ordinary, misleading destination, stacked shorteners, redirect loop and failed certificate cases work offline.
- **Upload QR image:** PNG/JPEG/WebP, up to 8 MiB and 16 megapixels, one QR per image.
- **Paste URL:** HTTP(S) URLs, normalized IDNA and public-suffix-aware domain analysis.
- **Camera:** take a browser photo, then explicitly analyze it. Retakes and settings changes do not trigger network requests. Use a browser with camera support on localhost; upload is the fallback.
- **Batch images / CSV:** up to 50 inputs, 64 MiB aggregate, two concurrent isolated workers by default, per-item errors, duplicate reuse within a run, ranked table, detail selector, JSON and spreadsheet-safe CSV export.
- **Evaluation:** bundled labelled fixtures, layer comparisons, actual image transformation checks and downloadable measurements.

Offline input analysis never contacts destinations. **Live network checks** require exact approved hostnames, including each redirect destination. DNS answers must all be public before a connection is pinned to a validated address. HTTPS preserves hostname verification and SNI. There is no page rendering, cookie jar, browser execution or analysis of destination page bodies.

The optional expected domain compares the final registered domain with what the QR was supposed to represent. Optional ASN/country baselines compare the last inspected destination with a supplied reference; they are not automatic brand ownership databases.

## Command line

```bash
python cli.py --demo suspicious
python cli.py --demo-batch --output reports/demos.json
python cli.py --image examples/ordinary.png
python cli.py --url https://example.com/ --live --approved-host example.com
python cli.py --url https://example.com/ --live --geolocation
python cli.py --batch-csv examples/urls.csv --format csv --output reports/batch.csv
python cli.py --batch-images examples/ordinary.png examples/suspicious.png --output reports/images.json
```

Options include `--expected-domain`, repeated `--expected-asn` and `--expected-country`, `--workers 1..4`, `--timeout 1..120`, and `--model path/to/model.json`. The default scan deadline is 60 seconds. Installed entry points are `qr-phishing-shield` and `qr-shield-evaluate`.

## Scores and evidence

| Layer | Weight | Behavior |
| --- | ---: | --- |
| URL | 20% | Checks every observed hop for misleading brand subdomains, limited homoglyph references, one-edit lookalikes, raw IPs and unusual depth/length |
| Redirects | 25% | Records headers, domain changes, stacked shorteners, downgrade, loops, limits and expected-domain mismatch |
| Network | 50% | A/AAAA/TTL, certificate issuer/dates/trust/hostname, TLS protocol/cipher/ALPN/certificate fingerprint, IP-to-ASN/organization; optional approximate location |
| QR structure | 5% | Version/modules, two format copies/ECC/mask, finder/timing/alignment patterns, density, reference capacity, quiet zone, contrast, sharpness and geometry |

The score is a heuristic weighted sum on 0–100, renormalized over available layer scores. Bands are **below 35 low observed risk**, **35–below 70 suspicious**, **70 and above high risk**. Any incomplete core URL/redirect/network layer forces **insufficient evidence**, even with a numeric provisional score. Coverage is the original weight of completed checks, not confidence.

Short TTL, certificate recency, a free CA, a hosting provider, a country, a valid ECC choice or a larger valid QR version do not by themselves prove phishing. Image quality findings do not add risk points. QR pattern/format inconsistencies are explicitly experimental and can arise from damage or decoding.

## Evaluation and optional ML

```bash
python -m evaluation benchmark --output reports/benchmark.json
python -m evaluation robustness --output reports/robustness.json
python -m evaluation calibrate --output reports/calibration.json
python -m evaluation train --csv data/urls.csv --output reports/lexical-model.json
python cli.py --url https://example.com/ --model reports/lexical-model.json
```

Without `--csv`, training uses the **synthetic teaching fixtures**, clearly labelled in the model. A user model is an optional, separately displayed lexical signal; it does not silently change the four-layer score. Model files are validated JSON, not executable pickle.

The repository includes a trained historical UCI model at `models/lexical-phiusiil.json`. Select **Use bundled experimental lexical classifier** in the dashboard's optional checks, or pass that path with `--model`. Its dataset attribution and held-out results are recorded in [the model notes](models/README.md).

See [evaluation methodology](docs/evaluation.md) for external labelled data, split rules, UCI dataset preparation and saved-report manifests. Calibration selects candidates on validation data and evaluates once on the test split; it does not automatically replace application defaults.

## Verify

```bash
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m pip check
```

Tests use injected network dependencies and do not visit phishing infrastructure. See [verification](docs/verification.md) for actual runs and remaining practical limitations.

## Architecture and documentation

- [Architecture, algorithms and request limits](docs/architecture.md)
- [Interfaces and report schema](docs/interfaces.md)
- [Evaluation and data provenance](docs/evaluation.md)
- [Current verification evidence](docs/verification.md)

## Providers, privacy and practical limits

ASN mapping uses [Team Cymru's DNS service](https://www.team-cymru.com/ip-asn-mapping); its registry country is not geolocation. Optional approximate IP location uses [ipwho.is](https://ipwhois.io/documentation), whose current free endpoint allows 1,000 requests/day per client IP with no SLA. No account or API key is needed. Only public IPs are sent to enrichment providers; QR images and full URLs are not sent to those providers.

Live destinations necessarily see the HTTP URL path/query and your network address; configured DNS resolvers see queried names. The app keeps reports in session memory and writes them only when you choose a CLI output or download. Reports include full URL evidence and should be reviewed before sharing. No raw camera/photo bytes are included in JSON.

The app inspects HTTP Location redirects only. JavaScript/meta-refresh, webpage intent, domain registration history, passive capture, browser/mobile extensions and email gateway deployment are outside this local application's scope. TLS server posture and certificate fingerprint are available; **JA3 is a client fingerprint**, not falsely presented as a fingerprint of the destination.

Provider outages, blocked redirects and malformed inputs remain visible. The local scanner has defensive bounds but is not designed to be exposed as an untrusted public scanning service. The brand list and bundled Public Suffix List have finite coverage. A low score cannot guarantee safety; historical or synthetic evaluation does not establish current real-world QR phishing accuracy.
