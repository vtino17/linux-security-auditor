import argparse
import json
import sys
from lsa.auditor import run_all, summarize
from lsa.reporter import write_report


def main():
    parser = argparse.ArgumentParser(
        description='Linux Security Auditor - comprehensive security assessment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
  lsa                         run all checks, print summary
  lsa --json                  output results as JSON
  lsa --report report.html    generate HTML report
  lsa --checks kernel,ssh     run specific check categories''')
    parser.add_argument('--json', action='store_true', help='output results as JSON')
    parser.add_argument('--report', type=str, help='generate HTML report at path')
    parser.add_argument('--checks', type=str, help='comma-separated check categories')
    parser.add_argument('--quiet', action='store_true', help='suppress progress output')

    args = parser.parse_args()

    results = run_all()

    if args.checks:
        selected = set(c.strip().lower() for c in args.checks.split(','))
        results = {k: v for k, v in results.items() if k.lower() in selected or any(s in k.lower() for s in selected)}

    if args.json:
        output = {}
        for section, checks in results.items():
            output[section] = []
            for c in checks:
                output[section].append({
                    'name': c['name'],
                    'status': c['status'],
                    'details': c['details'][:500] if c['details'] else '',
                    'remediation': c['remediation'][:300] if c['remediation'] else '',
                })
        final = {'summary': summarize(results), 'results': output}
        print(json.dumps(final, indent=2))
        return

    if args.report:
        path = write_report(results, args.report)
        if not args.quiet:
            print(f'Report written to {path}')

    summary = summarize(results)
    if not args.quiet:
        print(f'Linux Security Auditor')
        print(f'Score: {summary["score"]}/100')
        print(f'  Pass: {summary["passed"]}  Fail: {summary["failed"]}  Warn: {summary["warned"]}  Info: {summary["info"]}')
        print()

    for section, checks in results.items():
        if not args.quiet:
            print(f'[{section}]')
        for c in checks:
            icon = {'pass': '\u2713', 'fail': '\u2717', 'warn': '?', 'info': 'i', 'error': '!'}.get(c['status'], '?')
            if not args.quiet:
                print(f'  {icon} {c["name"]}: {c["status"].upper()}  {c["details"][:120]}')
        if not args.quiet:
            print()

    if summary['failed'] > 0 and not args.quiet:
        print(f'{summary["failed"]} checks failed. Review remediation steps above.')

    return 1 if summary['failed'] > 0 else 0


if __name__ == '__main__':
    sys.exit(main())
