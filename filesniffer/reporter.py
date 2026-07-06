import json
import csv
from pathlib import Path

# === ANSI color codes for console output ===
GREEN = "\033[92m" # high confidence matches
YELLOW = "\033[93m" # low confidence / info
RED = "\033[91m" # suspicious / unknown
RESET = "\033[0m" # always apply after a color to return to normal
BOLD = "\033[1m" # used for headers and table titles

def get_color(results):
    if results.note and "SUSPICIOUS" in results.note:
        return RED
    if results.confidence == "high":
        return GREEN
    if results.confidence == "ambiguous":
        return YELLOW
    return YELLOW #low confidence also gets yellow

def truncate(text, max_length=40):
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."

def print_report(results):
    print(f"\n{BOLD}File Sniffer - Scan Results{RESET}")
    print("─" * 70)
    print(f"{BOLD}{'File':<42}{'Type':<12}{'Confidence':<14}Note{RESET}")
    print("─" * 70)

    for result in results:
        color = get_color(result)
        filename = truncate(Path(result.filepath).name)
        types = ", ".join(result.possible_types)
        confidence = result.confidence.upper()
        note = result.note or ""

        print(f"{color}{filename:<42}{types:<12}{confidence:<14}{note}{RESET}")

    print("─" * 70)

    warnings = [r for r in results if r.note and "SUSPICIOUS" in r.note]
    print(f"\n{BOLD}{len(results)} file(s) scanned | {len(warnings)} warning(s){RESET}\n")


def export_json(results, output_path):
    data = []
    for result in results:
        data.append({
            "filepath": result.filepath,
            "possible_types": result.possible_types,
            "confidence": result.confidence,
            "note": result.note
        })
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"{GREEN}JSON report saved to: {output_path}{RESET}")


def export_csv(results, output_path):
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["filepath", "possible_types", "confidence", "note"])
        for result in results:
            writer.writerow([
                result.filepath,
                ", ".join(result.possible_types),
                result.confidence,
                result.note or "",
            ])
    print(f"{GREEN}CSV report saved to: {output_path}{RESET}")