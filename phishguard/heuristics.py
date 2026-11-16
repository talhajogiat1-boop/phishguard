"""Rule-based phishing signals.

Each rule looks for one well-known phishing pattern and adds points to a risk
score. The rules are deliberately simple and explainable, so every score comes
with a list of human-readable reasons.
"""

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

URGENCY_WORDS = [
    "urgent", "immediately", "within 24 hours", "account will be suspended",
    "final notice", "act now", "verify now", "unusual activity", "locked",
    "expires today", "last warning",
]
CREDENTIAL_WORDS = [
    "password", "login", "log in", "sign in", "verify your account",
    "confirm your identity", "social insurance number", "sin number",
    "credit card number", "security question", "one-time code",
]
MONEY_WORDS = ["gift card", "wire transfer", "bitcoin", "refund", "you have won", "prize", "claim your"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly"}
URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)
IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


@dataclass
class HeuristicResult:
    score: int = 0
    reasons: list = field(default_factory=list)

    def add(self, points: int, reason: str) -> None:
        self.score += points
        self.reasons.append(f"+{points}: {reason}")

    @property
    def label(self) -> str:
        return "phishing" if self.score >= THRESHOLD else "legitimate"


THRESHOLD = 4


def _domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].strip().lower().rstrip(">") if "@" in address else ""


def _root(host: str) -> str:
    parts = host.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def analyze(sender: str, subject: str, body: str, claimed_brand_domain: str = "") -> HeuristicResult:
    """Score one email. Higher score = more likely phishing."""
    r = HeuristicResult()
    text = f"{subject}\n{body}".lower()

    hits = [w for w in URGENCY_WORDS if w in text]
    if hits:
        r.add(2, f"urgent or threatening language ({', '.join(hits[:3])})")

    hits = [w for w in CREDENTIAL_WORDS if w in text]
    if hits:
        r.add(2, f"asks for credentials or personal data ({', '.join(hits[:3])})")

    hits = [w for w in MONEY_WORDS if w in text]
    if hits:
        r.add(2, f"money, prize or gift card bait ({', '.join(hits[:3])})")

    sender_root = _root(_domain(sender))
    for url in URL_RE.findall(body):
        host = (urlparse(url).hostname or "").lower()
        if IP_HOST_RE.match(host):
            r.add(3, f"link points to a raw IP address ({host})")
        elif host in SHORTENERS:
            r.add(2, f"link uses a URL shortener that hides the destination ({host})")
        elif sender_root and _root(host) != sender_root:
            r.add(2, f"link domain ({host}) does not match sender domain ({sender_root})")
        if host.count("-") >= 2 or any(t in host for t in ("secure-", "verify", "login-", "-update")):
            r.add(1, f"suspicious-looking link host ({host})")

    if claimed_brand_domain and sender_root and sender_root != _root(claimed_brand_domain):
        r.add(3, f"claims to be {claimed_brand_domain} but was sent from {sender_root}")

    if re.search(r"dear (customer|user|client|account holder)", text):
        r.add(1, "generic greeting instead of your name")

    if re.search(r"\.(exe|scr|js|zip|html?)\b", text) and "attach" in text:
        r.add(2, "mentions a risky attachment type")

    return r
