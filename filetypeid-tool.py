import os
import sys
import time
import argparse
from pathlib import Path
from datetime import datetime


# ─── ANSI Colors & Styles ──────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
MAGENTA= "\033[95m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

# ─── Terminal Width ────────────────────────────────────────
def term_width():
    try:
        return min(os.get_terminal_size().columns, 72)
    except:
        return 72

# ─── Magic Number Database ─────────────────────────────────
MAGIC_DB = {
    "JPEG":                  [(0, bytes([0xFF, 0xD8, 0xFF]))],
    "PNG":                   [(0, bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))],
    "GIF87":                 [(0, b"GIF87a")],
    "GIF89":                 [(0, b"GIF89a")],
    "BMP":                   [(0, bytes([0x42, 0x4D]))],
    "WEBP":                  [(0, b"RIFF"), (8, b"WEBP")],
    "TIFF_LE":               [(0, bytes([0x49, 0x49, 0x2A, 0x00]))],
    "TIFF_BE":               [(0, bytes([0x4D, 0x4D, 0x00, 0x2A]))],
    "PDF":                   [(0, b"%PDF")],
    "DOCX":                  [(0, bytes([0x50, 0x4B, 0x03, 0x04]))],
    "DOC":                   [(0, bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]))],
    "ZIP":                   [(0, bytes([0x50, 0x4B, 0x03, 0x04]))],
    "RAR":                   [(0, bytes([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]))],
    "7ZIP":                  [(0, bytes([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]))],
    "GZIP":                  [(0, bytes([0x1F, 0x8B]))],
    "TAR":                   [(257, b"ustar")],
    "EXE/DLL (Windows PE)":  [(0, bytes([0x4D, 0x5A]))],
    "ELF (Linux binary)":    [(0, bytes([0x7F, 0x45, 0x4C, 0x46]))],
    "MACHO (macOS binary)":  [(0, bytes([0xCF, 0xFA, 0xED, 0xFE]))],
    "MP3":                   [(0, bytes([0xFF, 0xFB]))],
    "MP4":                   [(4, b"ftyp")],
    "MKV":                   [(0, bytes([0x1A, 0x45, 0xDF, 0xA3]))],
    "FLAC":                  [(0, b"fLaC")],
    "SQLite DB":             [(0, b"SQLite format 3\x00")],
    "XML/HTML":              [(0, b"<?xml")],
    "CLASS (Java bytecode)": [(0, bytes([0xCA, 0xFE, 0xBA, 0xBE]))],
}

EXTENSION_MAP = {
    ".jpg": ["JPEG"],   ".jpeg": ["JPEG"],  ".png":  ["PNG"],
    ".gif": ["GIF87", "GIF89"],             ".bmp":  ["BMP"],
    ".tif": ["TIFF_LE","TIFF_BE"],          ".tiff": ["TIFF_LE","TIFF_BE"],
    ".pdf": ["PDF"],    ".docx": ["DOCX"],  ".xlsx": ["DOCX"],
    ".doc": ["DOC"],    ".zip":  ["ZIP","DOCX"], ".rar": ["RAR"],
    ".7z":  ["7ZIP"],   ".gz":   ["GZIP"],  ".tar":  ["TAR"],
    ".exe": ["EXE/DLL (Windows PE)"],       ".dll":  ["EXE/DLL (Windows PE)"],
    ".mp3": ["MP3"],    ".mp4":  ["MP4"],   ".mkv":  ["MKV"],
    ".flac":["FLAC"],   ".db":   ["SQLite DB"], ".sqlite":["SQLite DB"],
    ".xml": ["XML/HTML"],".html":["XML/HTML"],  ".class":["CLASS (Java bytecode)"],
}

# ─── ASCII UI Helpers ──────────────────────────────────────

def box_top(width, color=CYAN):
    return f"{color}╔{'═' * (width - 2)}╗{RESET}"

def box_mid(width, color=CYAN):
    return f"{color}╠{'═' * (width - 2)}╣{RESET}"

def box_bot(width, color=CYAN):
    return f"{color}╚{'═' * (width - 2)}╝{RESET}"

def box_sep(width, color=CYAN):
    return f"{color}╟{'─' * (width - 2)}╢{RESET}"

def box_row(text, width, color=CYAN, text_color=""):
    # Strip ANSI for length calculation
    import re
    clean = re.sub(r'\033\[[0-9;]*m', '', text)
    pad   = width - 2 - len(clean)
    pad   = max(pad, 0)
    return f"{color}║{RESET}{text_color}{text}{' ' * pad}{color}║{RESET}"

def box_row_center(text, width, color=CYAN, text_color=BOLD):
    import re
    clean = re.sub(r'\033\[[0-9;]*m', '', text)
    total_pad = width - 2 - len(clean)
    left  = total_pad // 2
    right = total_pad - left
    return f"{color}║{RESET}{' ' * left}{text_color}{text}{RESET}{' ' * right}{color}║{RESET}"

def print_banner():
    w = term_width()
    logo = [
        r"  ███╗   ███╗ █████╗  ██████╗ ██╗ ██████╗",
        r"  ████╗ ████║██╔══██╗██╔════╝ ██║██╔════╝",
        r"  ██╔████╔██║███████║██║  ███╗██║██║     ",
        r"  ██║╚██╔╝██║██╔══██║██║   ██║██║██║     ",
        r"  ██║ ╚═╝ ██║██║  ██║╚██████╔╝██║╚██████╗",
        r"  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝ ╚═════╝",
        r"       FILE SCANNER  ·  MAGIC NUMBERS     ",
    ]
    print()
    print(box_top(w))
    print(box_row("", w))
    for i, line in enumerate(logo):
        col = CYAN if i < 6 else (DIM)
        print(box_row_center(line, w, text_color=col))
    print(box_row("", w))
    now = datetime.now().strftime("  %Y-%m-%d  %H:%M:%S")
    version = "  v1.0  |  Cybersecurity Portfolio Project #1"
    print(box_row(version, w, text_color=DIM))
    print(box_row(now, w, text_color=DIM))
    print(box_row("", w))
    print(box_bot(w))
    print()

def print_section_header(title, color=CYAN):
    w = term_width()
    print(box_top(w, color))
    print(box_row_center(f"  {title}  ", w, color=color, text_color=BOLD))
    print(box_bot(w, color))

def animate_scan(filename, index, total):
    """Show a brief animated scan line per file."""
    spinner = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    w = term_width()
    name = filename[:35] + "..." if len(filename) > 35 else filename
    for i in range(3):
        frame = spinner[i % len(spinner)]
        bar_done = int((index / total) * 20)
        bar = f"[{'█' * bar_done}{'░' * (20 - bar_done)}]"
        line = f"  {CYAN}{frame}{RESET} Scanning {BOLD}{name}{RESET}  {DIM}{bar} {index}/{total}{RESET}"
        print(f"\r{line}", end="", flush=True)
        time.sleep(0.04)
    print(f"\r{' ' * (w - 1)}\r", end="", flush=True)

def print_file_result(result, index, total):
    w = term_width()
    status = result["status"]

    # Pick colors and icons based on status
    if status == "OK":
        border_color = GREEN
        icon  = f"{GREEN}[  OK  ]{RESET}"
        label = f"{GREEN}MATCH — File type verified{RESET}"
    elif status == "MISMATCH":
        border_color = RED
        icon  = f"{RED}[  !!  ]{RESET}"
        label = f"{RED}{BOLD}MISMATCH — POSSIBLE MALWARE DISGUISE{RESET}"
    elif status == "UNRECOGNIZED":
        border_color = YELLOW
        icon  = f"{YELLOW}[  ?   ]{RESET}"
        label = f"{YELLOW}UNRECOGNIZED FILE FORMAT{RESET}"
    elif status == "NO_EXTENSION_RULE":
        border_color = CYAN
        icon  = f"{CYAN}[  ~   ]{RESET}"
        label = f"{CYAN}NO RULE FOR THIS EXTENSION{RESET}"
    else:
        border_color = YELLOW
        icon  = f"{YELLOW}[ ERR  ]{RESET}"
        label = f"{YELLOW}{status}{RESET}"

    name = result["filename"]
    ext  = result["extension"] or "(no ext)"
    size = format_size(result["size_bytes"])

    import re
    def rlen(s): return len(re.sub(r'\033\[[0-9;]*m','',s))

    print(f"  {border_color}┌{'─'*(w-4)}┐{RESET}")

    # File name row
    file_row = f" {icon}  {BOLD}{name}{RESET}  {DIM}[{ext}]  {size}{RESET}"
    pad = w - 4 - rlen(file_row)
    print(f"  {border_color}│{RESET}{file_row}{' '*max(pad,0)}  {border_color}│{RESET}")

    print(f"  {border_color}├{'─'*(w-4)}┤{RESET}")

    # Status row
    status_row = f"  Status    {border_color}│{RESET} {label}"
    pad = w - 4 - rlen(status_row)
    print(f"  {border_color}│{RESET}{status_row}{' '*max(pad,0)}  {border_color}│{RESET}")

    # Detected types
    detected = ", ".join(result["detected_types"]) if result["detected_types"] else "(none matched)"
    det_col  = GREEN if result["detected_types"] else YELLOW
    det_row  = f"  Detected  {border_color}│{RESET} {det_col}{detected}{RESET}"
    pad = w - 4 - rlen(det_row)
    print(f"  {border_color}│{RESET}{det_row}{' '*max(pad,0)}  {border_color}│{RESET}")

    # Expected types
    if result["expected_types"]:
        exp_row = f"  Expected  {border_color}│{RESET} {DIM}{', '.join(result['expected_types'])}{RESET}"
        pad = w - 4 - rlen(exp_row)
        print(f"  {border_color}│{RESET}{exp_row}{' '*max(pad,0)}  {border_color}│{RESET}")

    # Header hex
    if result.get("header_hex"):
        hex_row = f"  Header    {border_color}│{RESET} {DIM}{result['header_hex']}{RESET}"
        pad = w - 4 - rlen(hex_row)
        print(f"  {border_color}│{RESET}{hex_row}{' '*max(pad,0)}  {border_color}│{RESET}")

    # Mismatch warning
    if result["mismatch"]:
        print(f"  {border_color}├{'─'*(w-4)}┤{RESET}")
        warn1 = f"  {RED}  /!\\  WARNING: Extension does not match real file content!{RESET}"
        warn2 = f"  {RED}       This is a known malware evasion technique.{RESET}"
        pad1  = w - 4 - rlen(warn1)
        pad2  = w - 4 - rlen(warn2)
        print(f"  {border_color}│{RESET}{warn1}{' '*max(pad1,0)}  {border_color}│{RESET}")
        print(f"  {border_color}│{RESET}{warn2}{' '*max(pad2,0)}  {border_color}│{RESET}")

    print(f"  {border_color}└{'─'*(w-4)}┘{RESET}")
    print()

def print_summary(results):
    w = term_width()
    total      = len(results)
    ok         = sum(1 for r in results if r["status"] == "OK")
    mismatches = [r for r in results if r["mismatch"]]
    errors     = sum(1 for r in results if r["status"] == "ERROR")
    unknown    = sum(1 for r in results if r["status"] in ("UNRECOGNIZED","NO_EXTENSION_RULE"))
    clean_pct  = int((ok / total) * 100) if total else 0

    # Score bar
    bar_ok   = int((ok / total) * 40)        if total else 0
    bar_warn = int((unknown / total) * 40)    if total else 0
    bar_bad  = 40 - bar_ok - bar_warn

    score_bar = (f"{GREEN}{'█' * bar_ok}{RESET}"
                 f"{YELLOW}{'░' * bar_warn}{RESET}"
                 f"{RED}{'▒' * bar_bad}{RESET}")

    import re
    def rlen(s): return len(re.sub(r'\033\[[0-9;]*m','',s))

    print(box_top(w, CYAN))
    print(box_row_center("  SCAN COMPLETE — SUMMARY REPORT  ", w))
    print(box_sep(w))
    print(box_row("", w))

    # Stats row
    stats = (f"  {GREEN}✔ Clean: {ok}{RESET}   "
             f"{YELLOW}? Unknown: {unknown}{RESET}   "
             f"{RED}✘ Mismatch: {len(mismatches)}{RESET}   "
             f"Total: {total}")
    print(box_row(stats, w))
    print(box_row("", w))

    # Score bar
    bar_label = f"  [{score_bar}]  {clean_pct}% clean"
    print(box_row(bar_label, w))
    print(box_row("", w))
    print(box_sep(w))

    # Verdict
    if len(mismatches) == 0:
        verdict = f"  {GREEN}{BOLD}  ALL CLEAR — No suspicious files detected.{RESET}"
    elif len(mismatches) == 1:
        verdict = f"  {RED}{BOLD}  ALERT — {len(mismatches)} SUSPICIOUS FILE DETECTED!{RESET}"
    else:
        verdict = f"  {RED}{BOLD}  ALERT — {len(mismatches)} SUSPICIOUS FILES DETECTED!{RESET}"
    print(box_row(verdict, w))
    print(box_row("", w))

    # List suspicious files
    if mismatches:
        print(box_sep(w))
        print(box_row(f"  {RED}{BOLD}  SUSPICIOUS FILES:{RESET}", w))
        for r in mismatches:
            detected = ", ".join(r["detected_types"])
            line1 = f"    {RED}>> {r['filename']}{RESET}"
            line2 = f"       Claims to be: {r['extension']}  |  Actually: {RED}{detected}{RESET}"
            print(box_row(line1, w))
            print(box_row(line2, w))
        print(box_row("", w))

    print(box_row(f"  {DIM}Scan finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}", w))
    print(box_row("", w))
    print(box_bot(w))
    print()


# ─── Core Scanner Logic ────────────────────────────────────

def read_header(filepath, size=512):
    with open(filepath, "rb") as f:
        return f.read(size)

def match_magic(header):
    matches = []
    for filetype, signatures in MAGIC_DB.items():
        all_match = True
        for offset, magic_bytes in signatures:
            end = offset + len(magic_bytes)
            if len(header) < end or header[offset:end] != magic_bytes:
                all_match = False
                break
        if all_match:
            matches.append(filetype)
    return matches

def analyze_file(filepath):
    result = {
        "path": str(filepath),
        "filename": filepath.name,
        "extension": filepath.suffix.lower(),
        "size_bytes": filepath.stat().st_size,
        "detected_types": [],
        "expected_types": [],
        "status": "UNKNOWN",
        "mismatch": False,
        "header_hex": "",
        "error": None,
    }
    try:
        header = read_header(filepath)
        result["header_hex"]     = header[:16].hex(" ").upper()
        result["detected_types"] = match_magic(header)
        result["expected_types"] = EXTENSION_MAP.get(result["extension"], [])

        if not result["detected_types"]:
            result["status"] = "UNRECOGNIZED"
        elif not result["expected_types"]:
            result["status"] = "NO_EXTENSION_RULE"
        else:
            overlap = set(result["detected_types"]) & set(result["expected_types"])
            result["status"]   = "OK" if overlap else "MISMATCH"
            result["mismatch"] = not bool(overlap)
    except PermissionError:
        result["error"]  = "Permission denied"
        result["status"] = "ERROR"
    except Exception as e:
        result["error"]  = str(e)
        result["status"] = "ERROR"
    return result

def format_size(size):
    for unit in ["B","KB","MB","GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"

def scan_path(target, verbose=False):
    path  = Path(target)
    files = []

    if path.is_file():
        files = [path]
    elif path.is_dir():
        files = sorted([f for f in path.rglob("*") if f.is_file()])
    else:
        print(f"\n  {RED}Error: '{target}' not found.{RESET}\n")
        sys.exit(1)

    print_section_header(f"  SCANNING  {len(files)} FILE(S)  ")
    print()

    results = []
    for i, f in enumerate(files, 1):
        animate_scan(f.name, i, len(files))
        r = analyze_file(f)
        if verbose:
            r["header_hex"] = r["header_hex"]  # already set
        else:
            r["header_hex"] = ""
        results.append(r)
        print_file_result(r, i, len(files))

    return results


# ─── Demo File Creator ─────────────────────────────────────

def create_demo_files():
    demo_dir = Path("demo_files")
    demo_dir.mkdir(exist_ok=True)

    files = {
        "real_image.png":      bytes([0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A,0,0,0,0x0D,0x49,0x48,0x44,0x52]),
        "document.pdf":        b"%PDF-1.4 demo content for scanner",
        "archive.zip":         bytes([0x50,0x4B,0x03,0x04]) + b"\x00"*50,
        "vacation_photo.jpeg": bytes([0x4D,0x5A,0x90,0x00,0x03,0x00,0x00,0x00]),  # EXE!
        "readme.txt":          bytes([0x7F,0x45,0x4C,0x46,0x02,0x01,0x01,0x00]),  # ELF!
        "notes.docx":          bytes([0x50,0x4B,0x03,0x04]) + b"\x00"*50,
    }

    for name, data in files.items():
        (demo_dir / name).write_bytes(data + b"\x00"*80)

    w = term_width()
    print(box_top(w, YELLOW))
    print(box_row_center("  DEMO FILES CREATED  ", w, color=YELLOW, text_color=BOLD))
    print(box_sep(w, YELLOW))
    print(box_row(f"  {GREEN}✔ real_image.png    {DIM}— legitimate PNG{RESET}", w, YELLOW))
    print(box_row(f"  {GREEN}✔ document.pdf      {DIM}— legitimate PDF{RESET}", w, YELLOW))
    print(box_row(f"  {GREEN}✔ archive.zip       {DIM}— legitimate ZIP{RESET}", w, YELLOW))
    print(box_row(f"  {GREEN}✔ notes.docx        {DIM}— legitimate DOCX{RESET}", w, YELLOW))
    print(box_row(f"  {RED}✘ vacation_photo.jpeg{DIM}— actually a Windows EXE!{RESET}", w, YELLOW))
    print(box_row(f"  {RED}✘ readme.txt         {DIM}— actually a Linux ELF binary!{RESET}", w, YELLOW))
    print(box_row("", w, YELLOW))
    print(box_bot(w, YELLOW))
    print()

    return str(demo_dir)


# ─── Main ──────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Magic File Scanner — ASCII Terminal UI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python magic_file_scanner_ui.py suspicious.jpeg
  python magic_file_scanner_ui.py /path/to/folder
  python magic_file_scanner_ui.py /path/to/folder -v
  python magic_file_scanner_ui.py --demo
        """
    )
    parser.add_argument("target",    nargs="?",          help="File or directory to scan")
    parser.add_argument("-v","--verbose", action="store_true", help="Show raw hex header bytes")
    parser.add_argument("--demo",    action="store_true", help="Create and scan demo test files")
    args = parser.parse_args()

    print_banner()

    if args.demo:
        target = create_demo_files()
    elif args.target:
        target = args.target
    else:
        parser.print_help()
        print(f"\n  {YELLOW}Tip: Run with --demo to see it in action.{RESET}\n")
        sys.exit(0)

    results = scan_path(target, verbose=args.verbose)
    print_summary(results)


if __name__ == "__main__":
    main()
