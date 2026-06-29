from filesniffer.signatures import(
    SIGNATURES,
    RIFF_SUBTYPE_OFFSET,
    RIFF_SUBTYPES,
    EBML_DOCTYPE_ELEMENT_ID,
    EBML_DOCTYPES,
    EML_HEADER_MARKERS,
    EML_HEURISTIC_THRESHOLD,
    DMG_TRAILER_MAGIC,
    DMG_TRAILER_OFFSET,
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
            f"confidence={self.confidence!r})"
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

def detect_file(filepath):
    header = read_header(filepath)
    if header is None:
        return DetectionResult(filepath, [".unknown"], confidence="low", note="unreadable")

    # 1. Try simple signatures first (fastest)
    matches = check_simple_signatures(header, SIGNATURES)
    if len(matches) == 1:
        return DetectionResult(filepath, matches, confidence="high")
    if len(matches) > 1:
        return DetectionResult(filepath, matches, confidence="ambiguous")

    # 2. Try deep signatures (files where magic bytes are far from the start)
    deep = check_deep_signatures(filepath)
    if deep:
        return DetectionResult(filepath, deep, confidence="high")

    #3. Resolve RIFF containers (WAV vs AVI)
    if header[:4] == b"RIFF":
        ext = resolve_riff(header)
        if ext:
            return DetectionResult(filepath, [ext], confidence="high")

    # 4. Resolve EBML containers (MKV vs WebM)
    if header[:4] == b"\x1a\x45\xdf\xa3":
        ext = resolve_ebml(filepath)
        if ext:
            return DetectionResult(filepath, [ext], confidence="high")

    # 5. EML heuristic
    if check_eml_heuristic(header):
        return DetectionResult(filepath, [".eml"], confidence="low", note="heuristic match")

    # 6. DMG trailer check
    if check_dmg_trailer(filepath):
        return DetectionResult(filepath, [".dmg"], confidence="high")
    
    # 7. Nothing matched
    return DetectionResult(filepath, [".unknown"], confidence="low", note="no signature matched")
