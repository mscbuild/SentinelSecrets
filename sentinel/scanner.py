import re
from sentinel.entropy import shannon_entropy
from sentinel.ignore import IgnoreRules

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "JWT": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "Generic API Key": r"(?i)(api_key|secret|token)[\"']?\s*[:=]\s*[\"'][^\"']+"
}
ENTROPY_THRESHOLD = 4.5

def scan_text(text: str, file_path: str = "") -> list:
    raw_findings = []

    # Regex scanning
    for name, pattern in SECRET_PATTERNS.items():
        for match in re.finditer(pattern, text):
            raw_findings.append({
                "type": name,
                "value": match.group(),
                "entropy": shannon_entropy(match.group()),
                "file": file_path
            })

    # High-entropy scanning
    for word in text.split():
        if shannon_entropy(word) > ENTROPY_THRESHOLD and len(word) > 20:
            raw_findings.append({
                "type": "High entropy string",
                "value": word,
                "entropy": shannon_entropy(word),
                "file": file_path
            })

    # Apply ignore rules
    ignore = IgnoreRules()
    return ignore.filter(raw_findings)

