import java.io.*;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.*;

public class filetypeid_tool_java {

    // ─── ANSI Colors ───────────────────────────────────────
    static final String RED    = "\033[91m";
    static final String GREEN  = "\033[92m";
    static final String YELLOW = "\033[93m";
    static final String CYAN   = "\033[96m";
    static final String BOLD   = "\033[1m";
    static final String RESET  = "\033[0m";

    // ─── Magic Signature Record ─────────────────────────────
    record Signature(int offset, byte[] magic) {}

    // ─── Scan Result Record ─────────────────────────────────
    static class ScanResult {
        String path, filename, extension;
        long sizeBytes;
        List<String> detectedTypes = new ArrayList<>();
        List<String> expectedTypes = new ArrayList<>();
        String status = "UNKNOWN";
        boolean mismatch = false;
        String headerHex = "";
        String error = null;
    }

    // ─── Magic Number Database ──────────────────────────────
    static final Map<String, List<Signature>> MAGIC_DB = new LinkedHashMap<>();
    static {
        // Images
        put("JPEG",            sig(0, 0xFF, 0xD8, 0xFF));
        put("PNG",             sig(0, 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A));
        put("GIF87",           sig(0, 'G','I','F','8','7','a'));
        put("GIF89",           sig(0, 'G','I','F','8','9','a'));
        put("BMP",             sig(0, 0x42, 0x4D));
        put("TIFF_LE",         sig(0, 0x49, 0x49, 0x2A, 0x00));
        put("TIFF_BE",         sig(0, 0x4D, 0x4D, 0x00, 0x2A));
        // Documents
        put("PDF",             sig(0, '%','P','D','F'));
        put("DOC",             sig(0, 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1));
        put("DOCX/XLSX/PPTX",  sig(0, 0x50, 0x4B, 0x03, 0x04));
        // Archives
        put("ZIP",             sig(0, 0x50, 0x4B, 0x03, 0x04));
        put("RAR",             sig(0, 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07));
        put("7ZIP",            sig(0, 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C));
        put("GZIP",            sig(0, 0x1F, 0x8B));
        // Executables
        put("EXE/DLL (Windows PE)", sig(0, 0x4D, 0x5A));
        put("ELF (Linux binary)",   sig(0, 0x7F, 'E','L','F'));
        put("MACHO (macOS binary)", sig(0, 0xCF, 0xFA, 0xED, 0xFE));
        // Media
        put("MP3",             sig(0, 0xFF, 0xFB));
        put("FLAC",            sig(0, 'f','L','a','C'));
        put("MKV",             sig(0, 0x1A, 0x45, 0xDF, 0xA3));
        // Other
        put("SQLite DB",       sig(0, 'S','Q','L','i','t','e',' ','f','o','r','m','a','t',' ','3', 0x00));
        put("CLASS (Java bytecode)", sig(0, 0xCA, 0xFE, 0xBA, 0xBE));
        put("XML/HTML",        sig(0, '<','?','x','m','l'));
    }

    // ─── Extension → Expected Type Map ─────────────────────
    static final Map<String, List<String>> EXTENSION_MAP = new HashMap<>();
    static {
        EXTENSION_MAP.put(".jpg",    List.of("JPEG"));
        EXTENSION_MAP.put(".jpeg",   List.of("JPEG"));
        EXTENSION_MAP.put(".png",    List.of("PNG"));
        EXTENSION_MAP.put(".gif",    List.of("GIF87", "GIF89"));
        EXTENSION_MAP.put(".bmp",    List.of("BMP"));
        EXTENSION_MAP.put(".tif",    List.of("TIFF_LE", "TIFF_BE"));
        EXTENSION_MAP.put(".tiff",   List.of("TIFF_LE", "TIFF_BE"));
        EXTENSION_MAP.put(".pdf",    List.of("PDF"));
        EXTENSION_MAP.put(".doc",    List.of("DOC"));
        EXTENSION_MAP.put(".docx",   List.of("DOCX/XLSX/PPTX"));
        EXTENSION_MAP.put(".xlsx",   List.of("DOCX/XLSX/PPTX"));
        EXTENSION_MAP.put(".pptx",   List.of("DOCX/XLSX/PPTX"));
        EXTENSION_MAP.put(".zip",    List.of("ZIP", "DOCX/XLSX/PPTX"));
        EXTENSION_MAP.put(".rar",    List.of("RAR"));
        EXTENSION_MAP.put(".7z",     List.of("7ZIP"));
        EXTENSION_MAP.put(".gz",     List.of("GZIP"));
        EXTENSION_MAP.put(".exe",    List.of("EXE/DLL (Windows PE)"));
        EXTENSION_MAP.put(".dll",    List.of("EXE/DLL (Windows PE)"));
        EXTENSION_MAP.put(".mp3",    List.of("MP3"));
        EXTENSION_MAP.put(".flac",   List.of("FLAC"));
        EXTENSION_MAP.put(".mkv",    List.of("MKV"));
        EXTENSION_MAP.put(".db",     List.of("SQLite DB"));
        EXTENSION_MAP.put(".sqlite", List.of("SQLite DB"));
        EXTENSION_MAP.put(".class",  List.of("CLASS (Java bytecode)"));
        EXTENSION_MAP.put(".xml",    List.of("XML/HTML"));
        EXTENSION_MAP.put(".html",   List.of("XML/HTML"));
    }

    // ─── Helper: build a Signature list ────────────────────
    static void put(String type, Signature sig) {
        MAGIC_DB.computeIfAbsent(type, k -> new ArrayList<>()).add(sig);
    }

    static Signature sig(int offset, int... bytes) {
        byte[] b = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) b[i] = (byte) bytes[i];
        return new Signature(offset, b);
    }

    // ─── Read file header ───────────────────────────────────
    static byte[] readHeader(Path path, int size) throws IOException {
        try (InputStream in = Files.newInputStream(path)) {
            return in.readNBytes(size);
        }
    }

    // ─── Match magic numbers ────────────────────────────────
    static List<String> matchMagic(byte[] header) {
        List<String> matches = new ArrayList<>();
        for (var entry : MAGIC_DB.entrySet()) {
            for (Signature sig : entry.getValue()) {
                int end = sig.offset() + sig.magic().length;
                if (header.length >= end) {
                    byte[] slice = Arrays.copyOfRange(header, sig.offset(), end);
                    if (Arrays.equals(slice, sig.magic())) {
                        matches.add(entry.getKey());
                        break;
                    }
                }
            }
        }
        return matches;
    }

    // ─── Analyze a single file ──────────────────────────────
    static ScanResult analyzeFile(Path path) {
        ScanResult r = new ScanResult();
        r.path     = path.toString();
        r.filename = path.getFileName().toString();
        r.extension = getExtension(r.filename).toLowerCase();
        try {
            r.sizeBytes    = Files.size(path);
            byte[] header  = readHeader(path, 512);
            r.headerHex    = toHex(Arrays.copyOf(header, Math.min(16, header.length)));
            r.detectedTypes = matchMagic(header);
            r.expectedTypes = EXTENSION_MAP.getOrDefault(r.extension, List.of());

            if (r.detectedTypes.isEmpty()) {
                r.status = "UNRECOGNIZED";
            } else if (r.expectedTypes.isEmpty()) {
                r.status = "NO_EXTENSION_RULE";
            } else {
                boolean overlap = r.detectedTypes.stream().anyMatch(r.expectedTypes::contains);
                if (overlap) {
                    r.status = "OK";
                } else {
                    r.status  = "MISMATCH";
                    r.mismatch = true;
                }
            }
        } catch (IOException e) {
            r.error  = e.getMessage();
            r.status = "ERROR";
        }
        return r;
    }

    // ─── Print result for one file ──────────────────────────
    static void printResult(ScanResult r, boolean verbose) {
        String icon, label;
        switch (r.status) {
            case "OK"                -> { icon = GREEN+"✔"+RESET; label = GREEN+"MATCH"+RESET; }
            case "MISMATCH"          -> { icon = RED+"✘"+RESET;   label = RED+BOLD+"MISMATCH — POSSIBLE DISGUISE"+RESET; }
            case "UNRECOGNIZED"      -> { icon = YELLOW+"?"+RESET; label = YELLOW+"UNRECOGNIZED FORMAT"+RESET; }
            case "NO_EXTENSION_RULE" -> { icon = CYAN+"~"+RESET;  label = CYAN+"NO RULE FOR THIS EXTENSION"+RESET; }
            default                  -> { icon = YELLOW+"!"+RESET; label = YELLOW+r.status+RESET; }
        }

        System.out.printf("%n  %s  %s%s%s  [%s]  %s%n", icon, BOLD, r.filename, RESET,
                r.extension.isEmpty() ? "(no ext)" : r.extension, formatSize(r.sizeBytes));
        System.out.println("     Status   : " + label);
        System.out.println("     Detected : " + (r.detectedTypes.isEmpty() ? "(none matched)" : String.join(", ", r.detectedTypes)));
        if (!r.expectedTypes.isEmpty())
            System.out.println("     Expected : " + String.join(", ", r.expectedTypes));
        if (verbose)
            System.out.println("     Header   : " + r.headerHex);
        if (r.error != null)
            System.out.println("     Error    : " + r.error);
        if (r.mismatch) {
            System.out.println("\n     " + RED + "⚠  WARNING: File extension does not match detected content." + RESET);
            System.out.println("     " + RED + "   This is a common malware evasion technique!" + RESET);
        }
    }

    // ─── Print summary ──────────────────────────────────────
    static void printSummary(List<ScanResult> results) {
        long ok         = results.stream().filter(r -> r.status.equals("OK")).count();
        long mismatches = results.stream().filter(r -> r.mismatch).count();
        long errors     = results.stream().filter(r -> r.status.equals("ERROR")).count();
        long unknown    = results.stream().filter(r -> r.status.equals("UNRECOGNIZED") || r.status.equals("NO_EXTENSION_RULE")).count();
        List<ScanResult> flagged = results.stream().filter(r -> r.mismatch).toList();
        String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        System.out.println("\n" + BOLD + "─".repeat(55));
        System.out.println("  SCAN SUMMARY  —  " + ts);
        System.out.println("─".repeat(55) + RESET);
        System.out.println("  Total scanned  : " + results.size());
        System.out.println(GREEN + "  Clean matches  : " + ok + RESET);
        System.out.println(YELLOW + "  Unknown/No rule : " + unknown + RESET);
        System.out.println(RED + "  MISMATCHES     : " + mismatches + RESET);
        System.out.println("  Errors         : " + errors);

        if (!flagged.isEmpty()) {
            System.out.println("\n  " + RED + BOLD + "⚠  SUSPICIOUS FILES:" + RESET);
            for (ScanResult r : flagged) {
                System.out.println("  " + RED + "→  " + r.path + RESET);
                System.out.println("     Extension '" + r.extension + "' but detected as: " + String.join(", ", r.detectedTypes));
            }
        }
        System.out.println(BOLD + "─".repeat(55) + RESET + "\n");
    }

    // ─── Scan a file or directory ───────────────────────────
    static List<ScanResult> scanPath(String target, boolean verbose) throws IOException {
        Path path = Paths.get(target);
        List<Path> files = new ArrayList<>();

        if (Files.isRegularFile(path)) {
            files.add(path);
        } else if (Files.isDirectory(path)) {
            try (Stream<Path> walk = Files.walk(path)) {
                files = walk.filter(Files::isRegularFile).sorted().collect(Collectors.toList());
            }
        } else {
            System.out.println(RED + "Error: '" + target + "' is not a valid file or directory." + RESET);
            System.exit(1);
        }

        System.out.println("\n" + BOLD + "─".repeat(55) + RESET);
        System.out.println(BOLD + "  Magic File Scanner — Scanning " + files.size() + " file(s)" + RESET);
        System.out.println(BOLD + "─".repeat(55) + RESET);

        List<ScanResult> results = new ArrayList<>();
        for (Path f : files) {
            ScanResult r = analyzeFile(f);
            results.add(r);
            printResult(r, verbose);
        }
        return results;
    }

    // ─── Create demo files ──────────────────────────────────
    static String createDemoFiles() throws IOException {
        Path demo = Paths.get("demo_files");
        Files.createDirectories(demo);

        // Real PNG
        byte[] png = {(byte)0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A,0x00,0x00,0x00,0x0D,0x49,0x48,0x44,0x52};
        Files.write(demo.resolve("real_image.png"), padded(png, 116));

        // Real PDF
        Files.write(demo.resolve("document.pdf"), "%PDF-1.4 fake content for demo".getBytes());

        // DISGUISED: EXE as JPEG
        byte[] exe = {0x4D,0x5A,(byte)0x90,0x00,0x03,0x00,0x00,0x00};
        Files.write(demo.resolve("vacation_photo.jpeg"), padded(exe, 108));

        // DISGUISED: ELF as .txt
        byte[] elf = {0x7F,0x45,0x4C,0x46,0x02,0x01,0x01,0x00};
        Files.write(demo.resolve("readme.txt"), padded(elf, 58));

        // Real ZIP
        byte[] zip = {0x50,0x4B,0x03,0x04};
        Files.write(demo.resolve("archive.zip"), padded(zip, 54));

        System.out.println(GREEN + "Demo files created in 'demo_files/' — including 2 disguised files." + RESET);
        return demo.toString();
    }

    static byte[] padded(byte[] header, int total) {
        byte[] result = new byte[total];
        System.arraycopy(header, 0, result, 0, Math.min(header.length, total));
        return result;
    }

    // ─── Utilities ──────────────────────────────────────────
    static String getExtension(String filename) {
        int dot = filename.lastIndexOf('.');
        return (dot >= 0) ? filename.substring(dot) : "";
    }

    static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) sb.append(" ");
            sb.append(String.format("%02X", bytes[i]));
        }
        return sb.toString();
    }

    static String formatSize(long size) {
        String[] units = {"B", "KB", "MB", "GB"};
        double s = size;
        for (String u : units) {
            if (s < 1024) return String.format("%.1f %s", s, u);
            s /= 1024;
        }
        return String.format("%.1f TB", s);
    }

    // ─── Main ───────────────────────────────────────────────
    public static void main(String[] args) throws IOException {
        if (args.length == 0) {
            printUsage();
            return;
        }

        boolean verbose = Arrays.asList(args).contains("-v") || Arrays.asList(args).contains("--verbose");
        boolean demo    = Arrays.asList(args).contains("--demo");
        String  target  = Arrays.stream(args).filter(a -> !a.startsWith("-")).findFirst().orElse(null);

        if (demo) {
            target = createDemoFiles();
        } else if (target == null) {
            printUsage();
            return;
        }

        List<ScanResult> results = scanPath(target, verbose);
        printSummary(results);
    }

    static void printUsage() {
        System.out.println(BOLD + "\nMagic File Scanner — Usage:" + RESET);
        System.out.println("  java filetypeid-tool_java <file_or_directory> [-v]");
        System.out.println("  java filetypeid-tool_java --demo");
        System.out.println("\nOptions:");
        System.out.println("  -v, --verbose    Show raw header bytes");
        System.out.println("  --demo           Create and scan demo files\n");
        System.out.println("Examples:");
        System.out.println("  java filetypeid-tool_java suspicious.jpeg");
        System.out.println("  java filetypeid-tool_java /path/to/folder -v");
        System.out.println("  java filetypeid-tool_java --demo\n");
    }
}
