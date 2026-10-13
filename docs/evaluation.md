# Evaluation and reproducibility

There are three distinct evidence sets. They must not be combined into a single accuracy claim.

1. **Synthetic integration fixtures:** 30 constructed scenarios with explicit benign/phishing intent, ten each in train/validation/test. They include clean-looking phishing, legitimate redirects, invalid TLS and loops. Domain/group separation is checked; scenario templates recur across splits, so these validate mechanics rather than generalization.
2. **Image robustness:** actual decoding of two generated QR images under clean, right-angle/arbitrary rotation, 100-pixel resize, blur, reduced contrast, perspective and low-quality JPEG transformations. Records successful matching payloads, errors and elapsed time.
3. **External URL corpus:** optional URL-only training/evaluation using user labels or the public UCI PhiUSIIL dataset. This does not validate the network layers or composite score.

## Commands

```bash
python -m evaluation benchmark --output reports/benchmark.json
python -m evaluation robustness --output reports/robustness.json
python -m evaluation calibrate --output reports/calibration.json
python -m evaluation train --csv data/urls.csv --output reports/lexical-model.json
```

Calibration tries network weights .40/.50/.60 with structure fixed at .05 and the remaining weight divided 4:5 between URL/redirect. Threshold candidates are 10–70 in steps of five. Selection uses validation F1, then fewer false positives and closeness to 35. The held-out test split is evaluated after selection. Defaults are not automatically changed. Synthetic tuning provides no basis for claiming optimal production weights.

Metrics include TP/FP/TN/FN, precision, assessed-only recall/F1/accuracy, coverage, abstentions and recall across all positives including abstentions. Empty denominators are null. Report coverage beside accuracy. Incomplete required evidence makes an approach abstain. Ablations use the same threshold with normalized subsets; this comparison is exploratory, not a controlled proof of superiority.

## External saved-report manifest

Supply a JSON list via `--manifest path.json` to benchmark or calibrate:

```json
[
  {"id": "case-001", "group": "organization-a", "split": "test", "label": 1,
   "report_path": "reports/case-001.json"}
]
```

Paths resolve relative to the manifest. `report` may instead embed the complete report. Labels use **1=phishing, 0=benign**. Use unique IDs and non-empty group values. Groups and registered domains must not cross splits. Labels require a recorded external provenance; a heuristic score is never a ground-truth label. Stored evidence can be evaluated without revisiting destinations. All required layers are schema-validated.

## UCI URL data preparation

Source: Prasad, A. & Chandra, S. (2024), [PhiUSIIL Phishing URL (Website)](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset), UCI Machine Learning Repository, [DOI](https://doi.org/10.1016/j.cose.2023.103545), licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

Download the ZIP from that official page, then:

```bash
python -m evaluation.import_phiusiil /path/to/dataset.zip --output data/phiusiil-sample.csv
python -m evaluation train --csv data/phiusiil-sample.csv --output models/lexical-phiusiil.json
python cli.py --url https://example.com/ --model models/lexical-phiusiil.json
```

Preparation selects 6,000 validated unique URLs per class using a deterministic hash ordering, then assigns registered-domain groups to 60/20/20 splits by a separate seeded hash. It records archive SHA-256, filtering counts, split counts and provenance. **Original UCI labels are inverted:** UCI 1=legitimate becomes project 0; UCI 0=phishing becomes project 1. Only URL text and labels are consumed. The provided webpage features and target-derived statistics are not training inputs. No dataset URL is fetched, resolved or opened.

The optional eight-feature logistic classifier uses URL length, digits, hyphens, subdomain depth, raw IP, the existing lexical score, punycode and HTTP. L2-regularized full-batch gradient descent is deterministic. Its decision threshold is selected on validation data; test metrics are held separate. Model JSON contains feature names, coefficients, threshold, source and test metrics. It is explicitly an uncalibrated experimental signal shown alongside the four-layer report, with no extra hidden composite weight.

Historical labels, artificial balanced sampling, a small feature set and dataset-specific patterns limit generalization. Do not present URL-only test metrics as QR phishing, network-analysis or end-to-end detection accuracy. Failed or invalid URLs are counted as exclusions in preparation metadata; examine these before comparing with other research.
