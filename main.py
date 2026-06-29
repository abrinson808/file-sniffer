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
    print(f"Scanning: {args.path}")
    print(f"Recursive: {args.recursive}")


if __name__ == "__main__":
    main()