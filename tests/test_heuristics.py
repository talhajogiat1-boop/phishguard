import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phishguard.heuristics import analyze
from phishguard.llm import parse_response


def test_obvious_phish_is_flagged():
    r = analyze("alerts@paypa1-secure.com", "Account locked",
                "Dear customer, verify your account immediately: http://192.168.4.20/login", "paypal.com")
    assert r.label == "phishing"
    assert any("raw IP" in reason for reason in r.reasons)


def test_normal_email_is_clean():
    r = analyze("prof@torontomu.ca", "Lecture notes", "Hi Talha, the slides for week 9 are posted on D2L.")
    assert r.label == "legitimate"
    assert r.score == 0


def test_brand_spoof_detected():
    r = analyze("help@rbc-support.net", "Statement", "Your statement is ready.", "rbc.com")
    assert any("claims to be rbc.com" in reason for reason in r.reasons)


def test_shortener_detected():
    r = analyze("x@shop.com", "Deal", "See this: http://bit.ly/abc", "")
    assert any("shortener" in reason for reason in r.reasons)


def test_llm_parser_handles_extra_text():
    out = parse_response('Sure! {"label": "Phishing", "confidence": 0.9, "red_flags": ["fake link"]}')
    assert out["label"] == "phishing" and out["confidence"] == 0.9


def test_llm_parser_handles_garbage():
    assert parse_response("no json here")["label"] == "legitimate"
