"""Binary detection metrics with explicit abstentions; no divide-by-zero magic."""


def classification_metrics(labels: list[int], predictions: list[bool | None]) -> dict:
    if len(labels) != len(predictions) or any(
        type(label) is not int or label not in (0, 1) for label in labels
    ):
        raise ValueError("Labels must be binary integers with one prediction each")
    if any(value is not None and type(value) is not bool for value in predictions):
        raise ValueError("Predictions must be booleans or null (abstention)")
    tp = fp = tn = fn = abstained = 0
    for label, prediction in zip(labels, predictions, strict=True):
        if prediction is None:
            abstained += 1
        elif prediction and label:
            tp += 1
        elif prediction:
            fp += 1
        elif label:
            fn += 1
        else:
            tn += 1
    assessed = tp + fp + tn + fn
    return {
        "total": len(labels),
        "assessed": assessed,
        "abstained": abstained,
        "coverage": assessed / len(labels) if labels else 0,
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall_on_assessed": tp / (tp + fn) if tp + fn else None,
        "recall_all_positives": tp / sum(labels) if sum(labels) else None,
        "f1_on_assessed": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
        "accuracy_on_assessed": (tp + tn) / assessed if assessed else None,
    }
