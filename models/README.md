# Experimental lexical model

`lexical-phiusiil.json` is a deterministic eight-feature logistic classifier trained on 7,201 URL examples from a 12,000-row balanced sample of UCI PhiUSIIL. A separate 2,354-row validation split selected the threshold; 2,445 examples were held out for testing. Registered domains do not cross splits. The model is optional and does not change the four-layer heuristic score.

Dataset: Prasad, A. & Chandra, S. (2024), [PhiUSIIL Phishing URL (Website)](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset), [DOI 10.1016/j.cose.2023.103545](https://doi.org/10.1016/j.cose.2023.103545). Dataset license: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Changes: deterministic sampling, normalization, deduplication, inverted labels and training of a new URL-only model. Attribution and archive checksum are embedded in the model metadata. No webpage-derived dataset features were used and no dataset URL was contacted.

This run measured 1,017 true positives, 11 false positives, 1,230 true negatives and 187 false negatives on the held-out sample (91.90% accuracy, 98.93% precision, 84.47% recall). These figures concern this historical, artificially balanced URL sample only. They are not QR phishing or end-to-end scanner accuracy. The large HTTP coefficient reflects a dataset-specific pattern and is a reason to avoid treating its output as a calibrated probability.

Reproduce the importer and training commands in `docs/evaluation.md`. Default synthetic model training remains available for teaching but is separately labelled and is not this bundled model.
