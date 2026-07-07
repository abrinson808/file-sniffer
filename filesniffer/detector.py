import unicodedata
import re
from pathlib import Path
from filesniffer.signatures import (
    SIGNATURES,
    RIFF_SUBTYPE_OFFSET,
    RIFF_SUBTYPES,
    EBML_DOCTYPE_ELEMENT_ID,
    EBML_DOCTYPES,
    EML_HEADER_MARKERS,
    EML_HEURISTIC_THRESHOLD,
    DMG_TRAILER_MAGIC,
    DMG_TRAILER_OFFSET,
    TEXT_SHEBANGS,
    TEXT_OPENING_PATTERNS,
    TEXT_PRINTABLE_THRESHOLD,
    BENIGN_FILENAMES,
)

# Unicode characters that are visually similar to common ASCII chars
# but could be used to disguise filenames or evade scanners.
SUSPICIOUS_UNICODE_HIGH = {
    '\u200b', #zero-width space (completely invisible)
    '\u200c', #zero-width non-joiner
    '\u200d', #zero-width joiner
    '\u2060', #zero-width word joiner
    '\ufeff', #byte order mark (BOM)
    '\u2028', # line separator
    '\u2029', # paragraph separator
    '\u202e', # right-to-left override (can reverse text direction)
    '\u202d', # left-to-right override
    '\u202a', # left-to-right embedding
    '\u202b', # right-to-left embedding
    '\u2066', # left-to-right isolate
    '\u2067', # right-to-left isolate
    '\u2068', # first strong isolate
    '\u2069', # pop directional isolate
}

SUSPICIOUS_UNICODE_INFO = {
    '\u202f', # narrow no-break space (used in macOS screenshot filenames)
    '\u00a0', # regular no-break space
}

# macOS screenshot filename pattern:
# "Screenshot YYYY-MM-DD at H.MM.SS\u202fAM/PM.png"
MACOS_SCREENSHOT_PATTERN = re.compile(
    r"^Screenshot \d{4}-\d{2}-\d{2} at \d{1,2}\.\d{2}\.\d{2}\u202f(AM|PM)\.png$"
)

def read_header(filepath, num_bytes=64):
    """
    Read the first `num_bytes` of a file for signature matching.
    Returns the bytes read, or None if the file can't be read.
    """
    try:
        with open(filepath, "rb") as f:
            return f.read(num_bytes)
    except (OSError, IOError):
        return None
    
class DetectionResult:
    """
    Standardized result for a single file's detection.
    Always holds a list of possible types, even when there's
    only one — keeps calling code (scanner.py, reporter.py)
    consistent regardless of how ambiguous the match was.
    """

    def __init__(self, filepath, possible_types, confidence="high", note=None):
        self.filepath = filepath
        self.possible_types = possible_types   # list of extensions, e.g. [".wav"]
        self.confidence = confidence            # "high", "low", or "ambiguous"
        self.note = note                        # optional explanation string

    def __repr__(self):
        return (
            f"DetectionResult(filepath={self.filepath!r}, "
            f"possible_types={self.possible_types!r}, "
            f"confidence={self.confidence!r}, "
            f"note={self.note!r})"
        )
    
def check_simple_signatures(header, signature_db):
    """
    Check `header` bytes against the flat signature dict.
    Returns a list of matching extensions (usually 0 or 1, but
    could be more than one if multiple formats share a signature
    we haven't separated into a container family).
    """
    matches = []
    for extension, sig_list in signature_db.items():
        for offset, magic in sig_list:
            if header[offset:offset + len(magic)] == magic:
                matches.append(extension)
                break # no need to check other signatures for this same extension
    return matches

# Threshold above which a signature is considered "deep" and won't
# be caught by the standard read_header() scan.

DEEP_OFFSET_THRESHOLD = 64

DEEP_OFFSET_SIGNATURES = {
    ".iso": [(0x8001, b"CD001")],
}


def check_deep_signatures(filepath, signature_db=DEEP_OFFSET_SIGNATURES):
    """
    Check for signatures that sit beyond the normal header read range.
    Opens the file fresh and seeks directly to the required offset,
    rather than reading the whole file up to that point.
    """
    matches = []
    for extension, sig_list in signature_db.items():
        for offset, magic in sig_list:
            try:
                with open(filepath, "rb") as f:
                    f.seek(offset)
                    chunk = f.read(len(magic))
                    if chunk == magic:
                        matches.append(extension)
                        break
            except (OSError, IOError):
                continue
    return matches

def resolve_riff(header):
    subtype = header[RIFF_SUBTYPE_OFFSET:RIFF_SUBTYPE_OFFSET + 4]
    return RIFF_SUBTYPES.get(subtype, None)

def resolve_ebml(filepath):
    try:
        with open(filepath, "rb") as f:
            data = f.read(64)
        idx = data.find(EBML_DOCTYPE_ELEMENT_ID)
        if idx == -1:
            return None
        length = data[idx + 2]
        doctype = data[idx + 3:idx + 3 + length]
        return EBML_DOCTYPES.get(doctype, None)
    except (OSError, IOError):
        return None

def check_eml_heuristic(header):
    count = 0
    for marker in EML_HEADER_MARKERS:
        if marker in header:
            count += 1
    return count >= EML_HEURISTIC_THRESHOLD

def check_dmg_trailer(filepath):
    try:
        with open(filepath, "rb") as f:
            f.seek(DMG_TRAILER_OFFSET, 2)   #2 means "from end of file"
            chunk = f.read(4)
            return chunk == DMG_TRAILER_MAGIC
    except (OSError, IOError):
        return False

def check_text_heuristic(header):
    """
    Attempt to identify plain text files that have no binary magic bytes.
    Checks shebangs first, then opening patterns, then falls back to
    a printability ratio check.
    Returns a tuple of (extension_or_none, confidence)
    """
    for shebang, ext in TEXT_SHEBANGS.items():
        if header.startswith(shebang):
            return ext, "high"


    header_lower = header[:64].lower()   
    for pattern, ext in TEXT_OPENING_PATTERNS.items():
        if header_lower.startswith(pattern):
            return ext, "high"
        
    printable = sum(
        1 for byte in header
        if 32 <= byte <= 126 or byte in (9, 10, 13)
    )
    ratio = printable / len(header) if header else 0
    if ratio >= TEXT_PRINTABLE_THRESHOLD:
        return "likely text", "low"
    
    return None, None

def normalize_path(filepath):
    """
    Normalize a filepath before scanning:
    - Resolves ~ and relative paths to absolute
    - Normalizes Unicode to NFC form for consistent comparison
    - Detects and flags suspicious Unicode characters in the filename
    """
    path = Path(filepath).expanduser().resolve()
    filename = path.name

    # Normalize to NFC first
    normalized = unicodedata.normalize("NFC", str(path))

    # Check against known benign filenames before Unicode inspection
    if filename.lower() in BENIGN_FILENAMES:
        return normalized, None

    # Check for high-severity Unicode characters — always suspicious
    found_high = [ch for ch in filename if ch in SUSPICIOUS_UNICODE_HIGH]

    # Check for info-level Unicode characters
    found_info = [ch for ch in filename if ch in SUSPICIOUS_UNICODE_INFO]

    warnings = []

    if found_high:
        char_descriptions = ', '.join(
            f"U+{ord(ch):04X} ({unicodedata.name(ch, 'UNKNOWN')})"
            for ch in found_high
        )
        warnings.append(f"SUSPICIOUS Unicode in filename: {char_descriptions}")

    if found_info:
        # Check if this matches the known macOS screenshot pattern
        is_macos_screenshot = bool(MACOS_SCREENSHOT_PATTERN.match(filename))

        if is_macos_screenshot:
            # Only the expected \u202f is present — downgrade to info
            char_descriptions = ', '.join(
                f"U+{ord(ch):04X} ({unicodedata.name(ch, 'UNKNOWN')})"
                for ch in found_info
            )
            warnings.append(f"INFO: Known macOS filename encoding: {char_descriptions}")
        else:
            # Same character, but not in an expected pattern — flag it
            char_descriptions = ', '.join(
                f"U+{ord(ch):04X} ({unicodedata.name(ch, 'UNKNOWN')})"
                for ch in found_info
            )
            warnings.append(f"SUSPICIOUS Unicode in filename: {char_descriptions}")

    warning = ' | '.join(warnings) if warnings else None
    return normalized, warning

def detect_file(filepath):
    filepath, unicode_warning = normalize_path(filepath)

    header = read_header(filepath)
    if header is None:
        return DetectionResult(
            filepath, [".unknown"], 
            confidence="low", 
            note=f"unreadable{' | ' + unicode_warning if unicode_warning else ''}"
        )

    # 1. Try simple signatures first (fastest)
    matches = check_simple_signatures(header, SIGNATURES)
    if len(matches) == 1:
        return DetectionResult(filepath, matches, confidence="high", note=unicode_warning)
    if len(matches) > 1:
        return DetectionResult(filepath, matches, confidence="ambiguous", note=unicode_warning)

    # 2. Try deep signatures (files where magic bytes are far from the start)
    deep = check_deep_signatures(filepath)
    if deep:
        return DetectionResult(filepath, deep, confidence="high", note=unicode_warning)

    #3. Resolve RIFF containers (WAV vs AVI)
    if header[:4] == b"RIFF":
        ext = resolve_riff(header)
        if ext:
            return DetectionResult(filepath, [ext], confidence="high", note=unicode_warning)

    # 4. Resolve EBML containers (MKV vs WebM)
    if header[:4] == b"\x1a\x45\xdf\xa3":
        ext = resolve_ebml(filepath)
        if ext:
            return DetectionResult(filepath, [ext], confidence="high", note=unicode_warning)

    # 5. EML heuristic
    if check_eml_heuristic(header):
        return DetectionResult(
            filepath, [".eml"], confidence="low", 
            note=f"heuristic match{' | ' + unicode_warning if unicode_warning else ''}"
        )

    # 6. DMG trailer check
    if check_dmg_trailer(filepath):
        return DetectionResult(filepath, [".dmg"], confidence="high", note=unicode_warning)

    # 7. Text file heuristic
    text_ext, text_confidence = check_text_heuristic(header)
    if text_ext:
        note = unicode_warning
        if text_ext == "likely text":
            note = f"likely plain text file{' | ' + unicode_warning if unicode_warning else ''}"
        return DetectionResult(
            filepath, [text_ext],
            confidence=text_confidence,
            note=note
        )

    # 8. Nothing matched
    return DetectionResult(
        filepath, [".unknown"], confidence="low", 
        note=f"no signature matched{' | ' + unicode_warning if unicode_warning else ''}"
    )
