# File Sniffer 🔍

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)
![Category](https://img.shields.io/badge/Category-Cybersecurity%20%7C%20Forensics-red)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

A cross-platform command-line forensics tool that identifies a file's **true type** by reading its binary signature — not by trusting its extension.

File extensions are just metadata. Anyone can rename `malware.exe` to `invoice.pdf`. File Sniffer reads the actual byte structure of a file to determine what it really is, flags mismatches between the claimed and actual type, and handles real-world ambiguity that naive scanners miss entirely.

---

## What makes this different

Most basic file type checkers stop at "does the magic byte match?" File Sniffer goes further:

**Two-tier container resolution** — RIFF-based files (WAV vs AVI) and EBML-based files (MKV vs WebM) share identical magic bytes at offset 0. Rather than guessing, File Sniffer performs a second-stage structural analysis to read deeper into the file and resolve the actual subtype correctly.

**Deep-offset signature handling** — ISO 9660 disk images hide their identifier (`CD001`) at byte offset 32,769. File Sniffer uses `seek()` to jump directly to the correct offset rather than reading thousands of bytes of irrelevant data just to get there.

**Unicode filename inspection** — including full Trojan Source detection. Bidirectional override characters like `U+202E` can visually reverse a filename in your file browser, making `malware.exe` display as `exe.erawlam`. File Sniffer scans every filename for these characters before the file is even opened.

**Intelligent false positive reduction** — macOS automatically inserts `U+202F` (narrow no-break space) into screenshot filenames. File Sniffer recognizes this known pattern and downgrades it to `INFO` rather than `SUSPICIOUS`, so real threats stand out instead of getting buried in noise.

**Text file heuristic detection** — plain text files have no binary magic bytes. File Sniffer identifies scripts by shebang line (`#!/usr/bin/env python3`), markup by opening patterns (`<?xml`, `<!DOCTYPE html>`), and falls back to a printability ratio check for everything else — the same approach used by the Unix `file` command under the hood.

---

## Demo

```
$ python3 main.py ~/Documents/suspicious --recursive

File Sniffer — Scan Results
──────────────────────────────────────────────────────────────────────
File                                      Type        Confidence    Note
──────────────────────────────────────────────────────────────────────
invoice.pdf                               .exe        HIGH
quarterly_report.docx                     .docx       HIGH
audio_sample.wav                          .wav        HIGH
setup.sh                                  .sh         HIGH
config.xml                                .xml        HIGH
README                                    likely text LOW           likely plain text file
suspicious file.pdf                       .pdf        HIGH          SUSPICIOUS Unicode: U+202E (RIGHT-TO-LEFT OVERRIDE)
Screenshot 2026-06-24 at 9.10.42 PM.png   .png        HIGH          INFO: Known macOS filename encoding: U+202F
──────────────────────────────────────────────────────────────────────
8 file(s) scanned | 1 warning(s)
```

Color coding in the actual terminal:

- 🟢 Green — high confidence, clean filename
- 🟡 Yellow — low confidence or ambiguous match
- 🔴 Red — suspicious Unicode detected in filename

---

## Features

- Magic byte signature detection across 40+ file types
- Two-tier container resolution for RIFF (WAV/AVI) and EBML (MKV/WebM)
- Deep-offset signature handling (ISO 9660 at offset 32,769)
- Unicode filename inspection with tiered severity (`SUSPICIOUS` vs `INFO`)
- Trojan Source bidirectional character detection (CVE-2021-42574)
- Text file heuristic detection via shebangs, opening patterns, and printability ratio
- Known benign filename whitelist (system files, dotfiles) to reduce noise
- Single file and batch directory scanning with recursive support
- Console output with ANSI color coding
- JSON and CSV report export
- Cross-platform: macOS, Linux, Windows
- Zero external dependencies — pure Python standard library

---

## Supported File Types

| Category         | Formats                                                  |
| ---------------- | -------------------------------------------------------- |
| Images           | JPG, PNG, GIF, BMP, TIFF, ICO                            |
| Audio            | MP3, WAV, FLAC, OGG                                      |
| Video            | MP4, MOV, AVI, MKV, WebM                                 |
| Documents        | PDF, DOCX, XLSX, PPTX                                    |
| Executables      | EXE (PE), ELF, Mach-O, DEX (Android)                     |
| Archives         | ZIP, TAR, GZ, BZ2, XZ, 7Z, RAR                           |
| Fonts            | TTF, OTF, WOFF, WOFF2                                    |
| Network Captures | PCAP, PCAPNG                                             |
| Forensic Images  | E01 (EnCase)                                             |
| Disk Images      | ISO 9660, VMDK, DMG                                      |
| Databases        | SQLite                                                   |
| Email            | PST, EML (heuristic)                                     |
| Scripts/Markup   | Python, Bash, JS, Ruby, Perl, XML, HTML, PHP (heuristic) |

---

## Installation

No external dependencies — File Sniffer uses only Python standard library modules.

```bash
git clone https://github.com/abrinson808/file-sniffer.git
cd file-sniffer
python3 main.py --help
```

Requires Python 3.8+.

---

## Usage

```bash
# Scan a single file
python3 main.py /path/to/file.pdf

# Scan a directory (non-recursive)
python3 main.py /path/to/directory

# Scan recursively
python3 main.py /path/to/directory --recursive

# Export results
python3 main.py /path/to/directory --json report.json --csv report.csv

# Combine flags
python3 main.py ~/Downloads --recursive --json report.json --csv report.csv
```

---

## Project Structure

```
file-sniffer/
├── filesniffer/
│   ├── __init__.py
│   ├── signatures.py      # magic byte database, container resolver tables,
│   │                      # text heuristics, benign filename whitelist
│   ├── detector.py        # core detection logic, Unicode inspection,
│   │                      # RIFF/EBML resolvers, text heuristic
│   ├── scanner.py         # single file and directory walking
│   └── reporter.py        # console output (ANSI color), JSON/CSV export
├── main.py                # CLI entry point (argparse)
├── requirements.txt
└── README.md
```

---

## How It Works

### Stage 1 — Simple signature matching

Read the first 64 bytes of the file and compare against a database of known magic byte signatures. Most files are identified here in a single pass.

### Stage 2 — Deep-offset signatures

For formats where the identifying bytes sit far from the start (ISO 9660 at offset 32,769), seek directly to the required position rather than reading the whole file.

### Stage 3 — Container resolution

When a magic byte matches an ambiguous container format, perform a second read to resolve the subtype:

- **RIFF**: read bytes 8–12 for the subtype tag (`WAVE` → `.wav`, `AVI ` → `.avi`)
- **EBML**: walk the element tree to find the `DocType` field (`matroska` → `.mkv`, `webm` → `.webm`)

### Stage 4 — Content heuristics

For formats with no binary signature (EML, plain text files), analyze the file content directly — email header markers, shebangs, opening patterns, printability ratio.

### Stage 5 — Unicode inspection

Every filename is scanned for suspicious Unicode characters before and after detection. Findings are tiered:

- `SUSPICIOUS` — characters with no legitimate filename use (zero-width spaces, bidirectional overrides, BOM)
- `INFO` — characters with known legitimate uses in specific contexts (macOS screenshot filenames)

---

## Technical Notes

**Trojan Source (CVE-2021-42574)** — disclosed in 2021, this attack embeds Unicode bidirectional control characters into filenames or source code to make the visual rendering differ from what's actually on disk. File Sniffer detects all 8 bidirectional control characters defined in the Unicode standard as `SUSPICIOUS` regardless of file type or confidence level.

**RIFF/EBML disambiguation** — the RIFF container format is used by both WAV and AVI. The EBML container is used by both MKV and WebM. Magic bytes alone cannot distinguish between them — File Sniffer reads the subtype tag at a fixed secondary offset (RIFF) or walks the EBML element tree to find the `DocType` field (EBML).

**Text detection threshold** — the printability ratio check (`TEXT_PRINTABLE_THRESHOLD = 0.85`) mirrors the heuristic used by the Unix `file` command. If 85% or more of the first 512 bytes are printable ASCII (including tab, newline, carriage return), the file is classified as `likely text` with low confidence.

---

## Roadmap

- [ ] Duplicate macOS screenshot regex fix (handle ` (2)`, ` (3)` filename variants)
- [ ] Extension mismatch flagging in report output
- [ ] Symlink detection (flag symlinks pointing outside the scanned directory)
- [ ] CSV/formula injection detection (flag cells starting with `=`, `+`, `-`, `@`)
- [ ] Homelab validation: spoofed test files (renamed executables, corrupted magic bytes, RIFF subtype tampering, Trojan Source filenames, macOS screenshot pattern exploitation)
- [ ] Additional signature coverage
- [ ] `--quiet` flag for warnings-only output

---

## Part of a Larger Portfolio

File Sniffer is the third tool in a self-directed cybersecurity learning roadmap, built alongside:

- [WiFi Sentinel](https://github.com/abrinson808/wifi-sentinel) — home network monitor with Flask dashboard, stealth mode, and email alerts
- [SSH Brute Force Detector](https://github.com/abrinson808/brute-force-detector) — cross-platform SSH log monitor with real-time alerting and launchd/systemd service integration

---

_[abrinson808](https://github.com/abrinson808) — building toward Security+ and beyond._
