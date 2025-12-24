import json
from datetime import datetime
from typing import List, Dict

def generate_json_report(findings: List[Dict], output_path: str):
    report = {
        "generated_at": datetime.utcnow().isoformat(),
        "total_findings": len(findings),
        "findings": findings
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

def generate_markdown_report(findings: List[Dict], output_path: str):
    lines = [
        "# 🔐 SentinelSecrets Scan Report",
        f"**Total findings:** {len(findings)}",
        ""
    ]
    if not findings:
        lines.append("✅ No secrets detected.")
    else:
        for idx, f in enumerate(findings, 1):
            lines.extend([
                f"## Finding #{idx}",
                f"- **Type:** {f['type']}",
                f"- **Entropy:** {f.get('entropy', 'N/A')}",
                f"- **File:** {f.get('file', '')}",
                f"- **Value:** `{f['value'][:12]}...`",
                ""
            ])
    with open(output_path, "w") as f:
        f.write("\n".join(lines))

