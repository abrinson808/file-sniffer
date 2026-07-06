from filesniffer.scanner import scan_path
from filesniffer.reporter import print_report, export_json, export_csv
import argparse


def build_parser():
    parser = argparse.ArgumentParser(
        prog="filesniffer",
        description="File Sniffer — detect true file types via signature analysis"
    )
    parser.add_argument(
        "path",
        help="File or directory to scan"
    )
    parser.add_argument(
        "--recursive", "-r",
        action="store_true",
        help="Scan directories recursively"
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Export results to a JSON file"
    )
    parser.add_argument(
        "--csv",
        metavar="FILE",
        help="Export results to a CSV file"
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    results = scan_path(args.path, recursive=args.recursive)

    print_report(results)

    if args.json:
        export_json(results, args.json)
    if args.csv:
        export_csv(results, args.csv)


if __name__ == "__main__":
    main()