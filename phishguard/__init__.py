"""PhishGuard: explainable phishing email detection (rules + LLM)."""

from .heuristics import analyze, THRESHOLD

__all__ = ["analyze", "THRESHOLD"]
