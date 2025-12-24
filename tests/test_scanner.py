import pytest
from sentinel.scanner import scan_text

def test_detects_aws_key():
    text = "AWS_KEY = AKIA1234567890ABCDE"
    results = scan_text(text)
    assert any("AWS Access Key" in r["type"] for r in results)

def test_detects_high_entropy_string():
    text = "token = asd98asdj!@#as9d8as9d8as9d8"
    results = scan_text(text)
    assert any(r["type"] == "High entropy string" for r in results)

def test_no_false_positive():
    text = "username = admin"
    results = scan_text(text)
    assert len(results) == 0
