import argparse
import json
import sys

from panicsight import check as check_module
from panicsight import report as report_module
from panicsight import watch as watch_module


def _positive_int(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


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
    watch = subparsers.add_parser(
        "watch", help="continuously sample headroom and the top fd holders")
    watch.add_argument("--baseline-interval", type=_positive_int, default=900,
                       metavar="SECONDS", help="baseline sampling interval (integer >= 1; default 900)")
    watch.add_argument("--elevated-interval", type=_positive_int, default=30,
                       metavar="SECONDS", help="elevated interval (integer >= 1, <= baseline; default 30)")
    watch.add_argument("--log", metavar="PATH", help="append JSONL to PATH instead of text")
    watch.add_argument("--top", type=_positive_int, default=5, metavar="N",
                       help="record N top fd holders (default 5)")
    watch.add_argument("--max-bytes", type=_positive_int, default=5_000_000, metavar="N",
                       help="rotate the log above N bytes, keeping PATH.1 (default 5000000)")
    watch.add_argument("--count", type=_positive_int, metavar="N",
                       help="stop after N samples/records (default forever)")
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
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "analyze":
        return _cmd_analyze(args.json, args.file)
    if args.command == "watch":
        if args.elevated_interval > args.baseline_interval:
            parser.error("--elevated-interval must be <= --baseline-interval")
        try:
            return watch_module.run_watch(
                baseline_interval=args.baseline_interval,
                elevated_interval=args.elevated_interval, log=args.log,
                top=args.top, max_bytes=args.max_bytes, count=args.count)
        except OSError as exc:
            print("error: cannot write watch output (%s)" % exc.__class__.__name__,
                  file=sys.stderr)
            return 2
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
