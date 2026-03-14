## FileTypeID-Toll
Detects the TRUE file type of any file using magic number analysis.
Flags disguised malware — e.g. a Windows EXE renamed as vacation_photo.jpeg.

## What are Magic Numbers?
Every file type has a secret signature hidden in its first few bytes.
A JPEG always starts with FF D8 FF. A Windows EXE always starts with 4D 5A.
This tool reads those bytes and compares them against a database of 25+ file types,
regardless of what the file extension claims.

## Features
- Detects 25+ file types (images, executables, archives, documents, media)
- Flags extension mismatches that indicate disguised malware
- ASCII terminal UI with live scan animation
- Scan a single file or an entire folder recursively

## Run Java version
### Compile
```bash
javac MagicFileScanner.java
```

### Run

**Built-in demo (creates test files including disguised ones):**
```bash
java MagicFileScanner --demo
```

**Scan a single file:**
```bash
java MagicFileScanner suspicious.jpeg
```

**Scan an entire folder:**
```bash
java MagicFileScanner path/to/folder
```

**Verbose mode (shows raw hex header bytes):**
```bash
java MagicFileScanner path/to/folder -v
```

### Windows Path Examples
```bash
java MagicFileScanner "<path>"
java MagicFileScanner "<path>"
```

## Run Python version
**Run the built-in demo:**
```bash
python filetypeid-tool.py --demo
```

**Scan a single file:**
```bash
python filetypeid-tool.py suspicious.jpeg
```

**Scan a folder:**
```bash
python filetypeid-tool.py "<path>"
```

**Scan with verbose mode:**
```bash
python filetypeid-tool.py "<path>" -v
```

## Example Output

**Clean file:**
```
[ OK  ]  real_image.png  [.png]  96 B
Status   | MATCH — File type verified
Detected | PNG
Expected | PNG
```

**Suspicious file (disguised malware):**
```
[ !!  ]  vacation_photo.jpeg  [.jpeg]  108 B
Status   | MISMATCH — POSSIBLE MALWARE DISGUISE
Detected | EXE/DLL (Windows PE)
Expected | JPEG

  /!\  WARNING: Extension does not match real file content!
       This is a known malware evasion technique.
```

**Unknown format:**
```
[  ~  ]  readme.txt  [.txt]  88 B
Status   | NO RULE FOR THIS EXTENSION
Detected | ELF (Linux binary)
```

## Requirements
- Python 3.10+ (no external libraries needed)
- Java 17 or above (no external libraries needed)

## Author
Shaamil Khan A
