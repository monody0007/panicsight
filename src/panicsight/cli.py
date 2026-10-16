import argparse
import json
import sys

from panicsight import check as check_module
from panicsight import report as report_module


def build_parser():
    parser = argparse.ArgumentParser(
        prog="panicsight",
        description="Analyze macOS kernel panic reports and check file/vnode table headroom.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze = subparsers.add_parser(
        "analyze", help="classify a .panic file and rank suspect processes")
    analyze.add_argument("file", help="path to a panic-full-*.panic report")
    analyze.add_argument("--json", action="store_true",
                         help="print one JSON object instead of the text report")
    check = subparsers.add_parser(
        "check", help="check file and vnode table headroom via sysctl")
    check.add_argument("--json", action="store_true",
                       help="print one JSON object instead of the text report")
    return parser


def analyze_payload(result):
    return {
        "class": result["class"],
        "signal": result["signal"],
        "memory_pressure": result["memory_pressure"],
        "system_uninterruptible": result["system_uninterruptible"],
        "suspects": result["suspects"],
        "os_version": result["os_version"],
        "timestamp": result["timestamp"],
        "excerpt": result["excerpt"],
    }


def print_json(payload):
    print(json.dumps(payload, indent=2))


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.command == "analyze":
        return _cmd_analyze(args.json, args.file)
    return _cmd_check(args.json)


def _cmd_analyze(as_json, path):
    try:
        result = report_module.analyze(path)
    except report_module.NotPanicReport as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    if as_json:
        print_json(analyze_payload(result))
    else:
        print(report_module.render_text(result))
    return 0


def _cmd_check(as_json):
    code, text, evaluation = check_module.run_check()
    if code != 0:
        print("error: %s" % text, file=sys.stderr)
        return code
    if as_json:
        print_json(evaluation)
    else:
        print(text)
    return code


if __name__ == "__main__":
    sys.exit(main())