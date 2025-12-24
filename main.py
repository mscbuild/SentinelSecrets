import argparse
import sys
from sentinel.scanner import scan_text
from sentinel.git_utils import get_staged_diff
from sentinel.report import generate_json_report, generate_markdown_report

def main():
    parser = argparse.ArgumentParser(description="SentinelSecrets - Secret Scanner")
    parser.add_argument("--file", help="Scan a specific file")
    parser.add_argument("--stdin", help="Scan content from stdin")
    parser.add_argument("--pre-commit", action="store_true", help="Run as pre-commit hook")
    parser.add_argument("--json", default="sentinel-report.json", help="JSON report output")
    parser.add_argument("--md", default="sentinel-report.md", help="Markdown report output")
    args = parser.parse_args()

    if args.pre_commit:
        text = get_staged_diff()
        file_path = ""
    elif args.stdin:
        text = args.stdin
        file_path = ""
    elif args.file:
        with open(args.file) as f:
            text = f.read()
        file_path = args.file
    else:
        print("No input specified. Use --file, --stdin, or --pre-commit.")
        sys.exit(1)

    findings = scan_text(text, file_path=file_path)

    generate_json_report(findings, args.json)
    generate_markdown_report(findings, args.md)

    if findings:
        print("❌ Secrets detected!")
        for f in findings:
            value_preview = f['value'][:8] + "..." if len(f['value']) > 8 else f['value']
            print(f"- {f['type']} in {f.get('file', '')}: {value_preview}")
        if args.pre_commit:
            print("Commit blocked due to secrets.")
            sys.exit(1)
        else:
            sys.exit(0)
    else:
        print("✅ No secrets found.")
        sys.exit(0)

if __name__ == "__main__":
    main()

