"""Evaluate PhishGuard on the labelled dataset and write results.md.

  python evaluate.py                 # rules only (no API key needed)
  python evaluate.py --mode llm      # LLM only (needs ANTHROPIC_API_KEY)
  python evaluate.py --mode hybrid   # flag if either method flags
"""

import argparse
import csv
from phishguard.heuristics import analyze


def metrics(pairs):
    tp = sum(1 for y, p in pairs if y == "phishing" and p == "phishing")
    tn = sum(1 for y, p in pairs if y == "legitimate" and p == "legitimate")
    fp = sum(1 for y, p in pairs if y == "legitimate" and p == "phishing")
    fn = sum(1 for y, p in pairs if y == "phishing" and p == "legitimate")
    acc = (tp + tn) / len(pairs)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return dict(tp=tp, tn=tn, fp=fp, fn=fn, accuracy=acc, precision=prec, recall=rec, f1=f1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["heuristic", "llm", "hybrid"], default="heuristic")
    ap.add_argument("--data", default="data/emails.csv")
    ap.add_argument("--out", default="results.md")
    a = ap.parse_args()

    rows = list(csv.DictReader(open(a.data, encoding="utf-8")))
    pairs, mistakes = [], []
    for r in rows:
        h = analyze(r["sender"], r["subject"], r["body"], r["brand"])
        pred = h.label
        if a.mode in ("llm", "hybrid"):
            from phishguard.llm import classify
            llm_label = classify(r["sender"], r["subject"], r["body"])["label"]
            pred = llm_label if a.mode == "llm" else ("phishing" if "phishing" in (h.label, llm_label) else "legitimate")
        pairs.append((r["label"], pred))
        if pred != r["label"]:
            mistakes.append((r["id"], r["label"], pred, r["subject"], h.score))

    m = metrics(pairs)
    lines = [
        f"# PhishGuard results ({a.mode} mode, {len(rows)} emails)", "",
        "| Metric | Value |", "|---|---|",
        f"| Accuracy | {m['accuracy']:.1%} |", f"| Precision | {m['precision']:.1%} |",
        f"| Recall | {m['recall']:.1%} |", f"| F1 score | {m['f1']:.2f} |", "",
        "| | Predicted phishing | Predicted legitimate |", "|---|---|---|",
        f"| **Actually phishing** | {m['tp']} | {m['fn']} |",
        f"| **Actually legitimate** | {m['fp']} | {m['tn']} |", "",
        "## Misclassified emails", "",
    ]
    lines += [f"- #{i} \"{s}\": expected **{y}**, got **{p}** (rule score {sc})" for i, y, p, s, sc in mistakes] or ["- none"]
    report = "\n".join(lines) + "\n"
    open(a.out, "w", encoding="utf-8").write(report)
    print(report)


if __name__ == "__main__":
    main()
