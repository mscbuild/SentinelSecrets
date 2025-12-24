# main.py
import argparse
import sys
from sentinel.git_utils import get_staged_diff
from sentinel.scanner import scan_text
from sentinel.report import generate_json_report


def main():
    parser = argparse.ArgumentParser(description="SentinelSecrets Scanner")
    parser.add_argument("--pre-commit", action="store_true")
    parser.add_argument("--json", default="sentinel-report.json")
    args = parser.parse_args()

    if args.pre_commit:
        diff = get_staged_diff()
        findings = scan_text(diff)

        if findings:
            generate_json_report(findings, args.json)
            print("❌ Secrets detected! Commit blocked.")
            for f in findings:
                print(f"- {f['type']}: {f['value'][:6]}***")
            sys.exit(1)

        print("✅ No secrets found.")
        sys.exit(0)


if __name__ == "__main__":
    main()
