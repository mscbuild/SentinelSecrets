import re
from pathlib import Path
from typing import List, Dict

class IgnoreRules:
    def __init__(self, ignore_file=".sentinelignore"):
        self.types = set()
        self.paths = set()
        self.values = set()
        self.regexes = []
        self._load(ignore_file)

    def _load(self, ignore_file):
        if not Path(ignore_file).exists():
            return
        with open(ignore_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                key, _, value = line.partition(":")
                value = value.strip()
                if key == "type":
                    self.types.add(value)
                elif key == "path":
                    self.paths.add(value)
                elif key == "value":
                    self.values.add(value)
                elif key == "regex":
                    self.regexes.append(re.compile(value))

    def is_ignored(self, finding: Dict) -> bool:
        if finding["type"] in self.types:
            return True
        if any(v in finding["value"] for v in self.values):
            return True
        if any(r.search(finding["value"]) for r in self.regexes):
            return True
        file_path = finding.get("file", "")
        if any(file_path.startswith(p) for p in self.paths):
            return True
        return False

    def filter(self, findings: List[Dict]) -> List[Dict]:
        return [f for f in findings if not self.is_ignored(f)]

