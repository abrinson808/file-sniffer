SIGNATURES: dict[str, list[tuple[int, bytes]]] = {
    # === Images ===
    ".jpg":  [(0, b"\xff\xd8\xff")],
    ".jpeg": [(0, b"\xff\xd8\xff")],
    ".png":  [(0, b"\x89PNG\r\n\x1a\n")],
    ".gif":  [(0, b"GIF87a"), (0, b"GIF89a")],
    ".bmp":  [(0, b"BM")],
    ".tiff": [(0, b"II*\x00"), (0, b"MM\x00*")],
    ".tif":  [(0, b"II*\x00"), (0, b"MM\x00*")],
    ".ico":  [(0, b"\x00\x00\x01\x00")],
    # === Audio ===
    ".wav":  [(0, b"RIFF")],
    ".mp3":  [(0, b"ID3"), (0, b"\xff\xfb"), (0, b"\xff\xf3"), (0, b"\xff\xf2")],
    ".flac": [(0, b"fLaC")],
    ".ogg":  [(0, b"OggS")],
    # === Video ===
    ".mp4":  [(4, b"ftyp")],
    ".mov":  [(4, b"ftyp"), (4, b"moov")],
    ".avi":  [(0, b"RIFF"), (8, b"AVI ")],
    ".mkv":  [(0, b"\x1a\x45\xdf\xa3")],
    ".webm": [(0, b"\x1a\x45\xdf\xa3")],
    # === Fonts ===
    ".ttf":   [(0, b"\x00\x01\x00\x00")],
    ".otf":   [(0, b"OTTO")],
    ".woff":  [(0, b"wOFF")],
    ".woff2": [(0, b"wOF2")],
    # === Disk Images ===
    #".iso":    [(0x8001, b"CD001")],
    # === Databases ===
    ".sqlite": [(0, b"SQLite format 3\x00")],
    ".db":     [(0, b"SQLite format 3\x00")],
    # === Exexcutables ===
    ".exe": [(0, b"MZ")],
    ".elf": [(0, b"\x7fELF")],
    ".dex": [(0, b"dex\n035\x00"), (0, b"dex\n036\x00"), (0, b"dex\n037\x00")],
    ".macho":  [(0, b"\xfe\xed\xfa\xce"),  # big-endian 32-bit
                (0, b"\xfe\xed\xfa\xcf"),  # big-endian 64-bit
                (0, b"\xcf\xfa\xed\xfe"),  # little-endian (Apple Silicon/modern Intel)
                (0, b"\xce\xfa\xed\xfe")], # little-endian 32-bit
    ".machofat": [(0, b"\xca\xfe\xba\xbe")], # universal/fat binary

    # === Network Captures ===
    ".pcap":  [(0, b"\xd4\xc3\xb2\xa1"), 
            (0, b"\xa1\xb2\xc3\xd4")],
    ".pcapng": [(0, b"\x0a\x0d\x0d\x0a")],

    # === Forensics Images ===
    ".e01": [(0, b"EVF\x01")],

    # === Virtual Machine Disk ===
    ".vmdk": [(0, b"KDMV")],

    # === Additional Archives ===
    ".tar":  [(257, b"ustar")],
    ".gz":   [(0, b"\x1f\x8b")],
    ".bz2":  [(0, b"BZh")],
    ".xz":   [(0, b"\xfd7zXZ\x00")],
    ".7z":   [(0, b"7z\xbc\xaf\x27\x1c")],
    ".rar":  [(0, b"Rar!\x1a\x07\x00"), (0, b"Rar!\x1a\x07\x01\x00")],    
    # === Email ===
    ".pst": [(0, b"!BDN")],
}

# DMG's real signature ('koly') lives in a trailer at EOF, not the header.
# True detection requires reading the last 512 bytes and cannot be expressed
# as a standard offset/magic tuple. Handled separately in detector.py.
DMG_TRAILER_MAGIC = b"koly"
DMG_TRAILER_OFFSET = -512

# EML has no binary magic bytes — detection requires a content heuristic
# in detector.py (check_eml_heuristic), not a standard offset/magic lookup.
EML_HEADER_MARKERS = [
    b"Return-Path:",
    b"Received:",
    b"From:",
    b"Subject:",
    b"Date:",
    b"Message-ID:",
]
EML_HEURISTIC_THRESHOLD = 2

# === Tier 1: Container-level signatures ===
# These are ambiguous containers — multiple real formats share the
# same magic bytes at offset 0. A Tier 2 resolver (in detector.py)
# is required to determine the actual file type.
CONTAINER_SIGNATURES = {
    "RIFF": {
        "offset": 0,
        "magic": b"RIFF",
        "ambiguous": True,
        "resolver": "resolve_riff",
    },
    "EBML": {
        "offset": 0,
        "magic": b"\x1a\x45\xdf\xa3",
        "ambiguous": True,
        "resolver": "resolve_ebml",
    },
}

# === Tier 2: Resolver lookup tables ===
# Used by detector.py's resolve_riff() and resolve_ebml() functions
# to disambiguate a container into a specific file type.

# RIFF subtype sits at a fixed offset: bytes 8-12, right after the
# 4-byte "RIFF" tag and the 4-byte chunk size field.
RIFF_SUBTYPE_OFFSET = 8
RIFF_SUBTYPES = {
    b"WAVE": ".wav",
    b"AVI ": ".avi",  # trailing space is part of the real RIFF spec
}

# EBML DocType is a nested element, not a fixed offset — detector.py
# will walk the EBML structure to find this element ID, then look
# up its string value here.
EBML_DOCTYPE_ELEMENT_ID = b"\x42\x82"
EBML_DOCTYPES = {
    b"matroska": ".mkv",
    b"webm": ".webm",
}

# === Text file heuristics ===
# Plain text files have no binary magic bytes — detection requires
# reading the file as text and checking for known patterns.
# Handled by check_text_heuristic() in detector.py.

TEXT_SHEBANGS = {
    b"#!/usr/bin/env python":  ".py",
    b"#!/usr/bin/python":      ".py",
    b"#!/usr/bin/env node":    ".js",
    b"#!/usr/bin/env ruby":    ".rb",
    b"#!/usr/bin/env bash":    ".sh",
    b"#!/bin/bash":            ".sh",
    b"#!/bin/sh":              ".sh",
    b"#!/usr/bin/env perl":    ".pl",
}

TEXT_OPENING_PATTERNS = {
    b"<!DOCTYPE html>": ".html",
    b"<html>":          ".html",
    b"<?xml":           ".xml",
    b"{\n":    ".json",   # JSON object with newline (common formatting)
    b"[\n":    ".json",   # JSON array with newline
    b"{\r\n":  ".json",   # Windows line endings
    b"[\r\n":  ".json",   # Windows line endings
    b"<?php":          ".php",
    b"<!doctype html": ".html",
}

# If 85%+ of the first 512 bytes are printable ASCII,
# treat the file as plain text with low confidence.
TEXT_PRINTABLE_THRESHOLD = 0.85

# === Known benign filenames ===
# These files are expected to return .unknown and should not
# be flagged as suspicious — they are legitimate system files
# with no standard magic byte signature.
BENIGN_FILENAMES = {
    # Windows system files
    "desktop.ini",
    "thumbs.db",
    "ntldr",
    "bootmgr",
    # macOS system files
    ".ds_store",
    ".localized",
    # Linux/Unix dotfiles
    ".bashrc",
    ".zshrc",
    ".profile",
    ".bash_profile",
    ".bash_history",
    ".gitignore",
    ".gitconfig",
    ".editorconfig",
    # Common text config files with no extension
    "makefile",
    "dockerfile",
    "vagrantfile",
    "procfile",
}