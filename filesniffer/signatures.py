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
