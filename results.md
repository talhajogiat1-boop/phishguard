# PhishGuard results (heuristic mode, 40 emails)

| Metric | Value |
|---|---|
| Accuracy | 92.5% |
| Precision | 100.0% |
| Recall | 85.0% |
| F1 score | 0.92 |

| | Predicted phishing | Predicted legitimate |
|---|---|---|
| **Actually phishing** | 17 | 3 |
| **Actually legitimate** | 0 | 20 |

## Misclassified emails

- #9 "You have won!": expected **phishing**, got **legitimate** (rule score 2)
- #19 "Stuck abroad": expected **phishing**, got **legitimate** (rule score 2)
- #20 "Remote job offer": expected **phishing**, got **legitimate** (rule score 2)
