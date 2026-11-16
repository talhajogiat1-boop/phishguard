"""Check a single email from the command line.

Examples:
  python detect.py --sender "alerts@paypa1-secure.com" --subject "Account locked" --body "Verify now: http://192.168.4.20/login"
  python detect.py --file sample_email.txt --mode hybrid
"""

import argparse
from phishguard.heuristics import analyze


def read_email_file(path: str):
    """File format: first line 'From: ...', second line 'Subject: ...', blank line, then body."""
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    sender = lines[0].split(":", 1)[1].strip()
    subject = lines[1].split(":", 1)[1].strip()
    body = "\n".join(lines[3:])
    return sender, subject, body


def main():
    ap = argparse.ArgumentParser(description="PhishGuard email checker")
    ap.add_argument("--sender"); ap.add_argument("--subject", default=""); ap.add_argument("--body", default="")
    ap.add_argument("--file", help="email text file (From/Subject/blank/body)")
    ap.add_argument("--brand", default="", help="domain the email claims to come from, e.g. rbc.com")
    ap.add_argument("--mode", choices=["heuristic", "llm", "hybrid"], default="heuristic")
    a = ap.parse_args()

    sender, subject, body = read_email_file(a.file) if a.file else (a.sender or "", a.subject, a.body)

    h = analyze(sender, subject, body, a.brand)
    if a.mode in ("heuristic", "hybrid"):
        print(f"[rules] {h.label.upper()}  (score {h.score})")
        for reason in h.reasons:
            print("   ", reason)
    if a.mode in ("llm", "hybrid"):
        from phishguard.llm import classify
        res = classify(sender, subject, body)
        print(f"[llm]   {res['label'].upper()}  (confidence {res['confidence']:.2f})")
        for flag in res["red_flags"]:
            print("    -", flag)
        if a.mode == "hybrid":
            verdict = "PHISHING" if (h.label == "phishing" or res["label"] == "phishing") else "LEGITIMATE"
            print(f"[final] {verdict}  (flagged if either method flags it)")


if __name__ == "__main__":
    main()
