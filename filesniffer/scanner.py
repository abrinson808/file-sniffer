from pathlib import Path
from filesniffer.detector import detect_file, DetectionResult


def scan_path(path, recursive=False):
    """
    Scan a single file or directory and return a list of DetectionResults.
    - If path is a file: scan it directly
    - If path is a directory: scan all files inside it
    - recursive=True: walk all subdirectories as well
    - Inaccessible files are included in results with a note
    """
    target = Path(path).expanduser().resolve()
    results = []

    if not target.exists():
        # Path doesn't exist at all — return a single result noting this
        results.append(DetectionResult(
            str(target),
            [".unknown"],
            confidence="low",
            note="path does not exist"
        ))
        return results

    if target.is_file():
        # Single file — detect directly
        results.append(detect_file(str(target)))
        return results

    if target.is_dir():
        # Gather files based on recursive flag
        if recursive:
            files = target.rglob("*")   # rglob = recursive glob, walks all subdirs
        else:
            files = target.glob("*")    # glob = current directory only

        for file in files:
            if file.is_symlink() and not file.exists():
                # Broken symlink — note it but skip actual detection
                results.append(DetectionResult(
                    str(file),
                    [".unknown"],
                    confidence="low",
                    note="broken symlink"
                ))
                continue

            if not file.is_file():
                # Skip subdirectories themselves — only scan actual files
                continue

            try:
                results.append(detect_file(str(file)))
            except PermissionError:
                results.append(DetectionResult(
                    str(file),
                    [".unknown"],
                    confidence="low",
                    note="permission denied"
                ))

    return results