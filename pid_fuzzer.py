#!/usr/bin/env python3
# Python 3.9+, Windows only
import argparse, csv, datetime, json, os, re, sys, socket, time, textwrap, base64, hashlib, random
import ctypes as C
import ctypes.wintypes as W
from typing import Dict, List, Optional, Tuple
from pathlib import Path

# ---- Win32 constants / DLLs ----
PROCESS_VM_READ                   = 0x0010
PROCESS_VM_WRITE                  = 0x0020
PROCESS_VM_OPERATION              = 0x0008
PROCESS_CREATE_THREAD             = 0x0002
PROCESS_QUERY_INFORMATION         = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
LIST_MODULES_ALL = 0x03
MAX_PATH = 260
GENERIC_WRITE  = 0x40000000
OPEN_EXISTING  = 3
INVALID_HANDLE_VALUE = C.c_void_p(-1).value

kernel32 = C.WinDLL("kernel32", use_last_error=True)
psapi    = C.WinDLL("psapi",    use_last_error=True)

CreateFileW = kernel32.CreateFileW
CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE]
CreateFileW.restype  = W.HANDLE

WaitNamedPipeW = kernel32.WaitNamedPipeW
WaitNamedPipeW.argtypes = [W.LPCWSTR, W.DWORD]
WaitNamedPipeW.restype  = W.BOOL

WriteFile = kernel32.WriteFile
WriteFile.argtypes = [W.HANDLE, W.LPCVOID, W.DWORD, C.POINTER(W.DWORD), W.LPVOID]
WriteFile.restype  = W.BOOL

def _raise_last_error(msg: str):
    err = C.get_last_error()
    raise OSError(f"{msg} (WinErr={err})")

# ---- PE structures (64-bit) ----
class IMAGE_DOS_HEADER(C.Structure):
    _fields_ = [
        ("e_magic", W.WORD),
        ("e_cblp", W.WORD),
        ("e_cp", W.WORD),
        ("e_crlc", W.WORD),
        ("e_cparhdr", W.WORD),
        ("e_minalloc", W.WORD),
        ("e_maxalloc", W.WORD),
        ("e_ss", W.WORD),
        ("e_sp", W.WORD),
        ("e_csum", W.WORD),
        ("e_ip", W.WORD),
        ("e_cs", W.WORD),
        ("e_lfarlc", W.WORD),
        ("e_ovno", W.WORD),
        ("e_res", W.WORD * 4),
        ("e_oemid", W.WORD),
        ("e_oeminfo", W.WORD),
        ("e_res2", W.WORD * 10),
        ("e_lfanew", W.LONG),
    ]

IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16

class IMAGE_FILE_HEADER(C.Structure):
    _fields_ = [
        ("Machine", W.WORD),
        ("NumberOfSections", W.WORD),
        ("TimeDateStamp", W.DWORD),
        ("PointerToSymbolTable", W.DWORD),
        ("NumberOfSymbols", W.DWORD),
        ("SizeOfOptionalHeader", W.WORD),
        ("Characteristics", W.WORD),
    ]

class IMAGE_DATA_DIRECTORY(C.Structure):
    _fields_ = [("VirtualAddress", W.DWORD), ("Size", W.DWORD)]

class IMAGE_OPTIONAL_HEADER64(C.Structure):
    _fields_ = [
        ("Magic", W.WORD),
        ("MajorLinkerVersion", C.c_ubyte),
        ("MinorLinkerVersion", C.c_ubyte),
        ("SizeOfCode", W.DWORD),
        ("SizeOfInitializedData", W.DWORD),
        ("SizeOfUninitializedData", W.DWORD),
        ("AddressOfEntryPoint", W.DWORD),
        ("BaseOfCode", W.DWORD),
        ("ImageBase", C.c_uint64),
        ("SectionAlignment", W.DWORD),
        ("FileAlignment", W.DWORD),
        ("MajorOperatingSystemVersion", W.WORD),
        ("MinorOperatingSystemVersion", W.WORD),
        ("MajorImageVersion", W.WORD),
        ("MinorImageVersion", W.WORD),
        ("MajorSubsystemVersion", W.WORD),
        ("MinorSubsystemVersion", W.WORD),
        ("Win32VersionValue", W.DWORD),
        ("SizeOfImage", W.DWORD),
        ("SizeOfHeaders", W.DWORD),
        ("CheckSum", W.DWORD),
        ("Subsystem", W.WORD),
        ("DllCharacteristics", W.WORD),
        ("SizeOfStackReserve", C.c_uint64),
        ("SizeOfStackCommit", C.c_uint64),
        ("SizeOfHeapReserve", C.c_uint64),
        ("SizeOfHeapCommit", C.c_uint64),
        ("LoaderFlags", W.DWORD),
        ("NumberOfRvaAndSizes", W.WORD),
        ("DataDirectory", IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
    ]

class IMAGE_NT_HEADERS64(C.Structure):
    _fields_ = [
        ("Signature", W.DWORD),
        ("FileHeader", IMAGE_FILE_HEADER),
        ("OptionalHeader", IMAGE_OPTIONAL_HEADER64),
    ]

class IMAGE_IMPORT_DESCRIPTOR(C.Structure):
    _fields_ = [
        ("OriginalFirstThunk", W.DWORD),
        ("TimeDateStamp", W.DWORD),
        ("ForwarderChain", W.DWORD),
        ("Name", W.DWORD),
        ("FirstThunk", W.DWORD),
    ]

class IMAGE_THUNK_DATA64(C.Union):
    _fields_ = [
        ("ForwarderString", C.c_uint64),
        ("Function", C.c_uint64),
        ("Ordinal", C.c_uint64),
        ("AddressOfData", C.c_uint64),
    ]

class IMAGE_IMPORT_BY_NAME(C.Structure):
    _fields_ = [("Hint", W.WORD)]  # followed by ASCII name

# ---- PSAPI: module enumeration / info ----
EnumProcessModulesEx = psapi.EnumProcessModulesEx
EnumProcessModulesEx.argtypes = [W.HANDLE, C.POINTER(W.HMODULE), W.DWORD, C.POINTER(W.DWORD), W.DWORD]
EnumProcessModulesEx.restype  = W.BOOL

GetModuleFileNameExW = psapi.GetModuleFileNameExW
GetModuleFileNameExW.argtypes = [W.HANDLE, W.HMODULE, W.LPWSTR, W.DWORD]
GetModuleFileNameExW.restype  = W.DWORD

class MODULEINFO(C.Structure):
    _fields_ = [("lpBaseOfDll", W.LPVOID),
                ("SizeOfImage", W.DWORD),
                ("EntryPoint", W.LPVOID)]

GetModuleInformation = psapi.GetModuleInformation
GetModuleInformation.argtypes = [W.HANDLE, W.HMODULE, C.POINTER(MODULEINFO), W.DWORD]
GetModuleInformation.restype  = W.BOOL

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
OpenProcess.restype  = W.HANDLE

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [W.HANDLE]
CloseHandle.restype  = W.BOOL

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [W.HANDLE, W.LPCVOID, W.LPVOID, C.c_size_t, C.POINTER(C.c_size_t)]
ReadProcessMemory.restype  = W.BOOL

# ---------------- Helpers (shared) ----------------
def now_stamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")

def ensure_outdir(path: str):
    os.makedirs(path, exist_ok=True)

def ensure_artifacts():
    os.makedirs("artifacts", exist_ok=True)

def loud_banner(msg: str):
    bar = "=" * max(36, len(msg) + 10)
    print(f"\n{bar}\n*** {msg} ***\n{bar}\n")

def load_seeds_from_jsonl(path: str) -> List[bytes]:
    out: List[bytes] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            rec = json.loads(line)
            out.append(base64.b64decode(rec["data_b64"]))
    return out

def load_seeds_from_json(path: str) -> List[bytes]:
    blob = json.load(open(path, "r", encoding="utf-8"))
    return [base64.b64decode(r["data_b64"]) for r in blob.get("seeds", [])]

# ---------- NEW: unified seed loaders & auto-config ----------
def load_seeds_from_directory(dir_path: str) -> Tuple[List[bytes], List[str]]:
    """
    Load all .bin files under a directory tree. Infer labels from folder names:
      - .../tcp/port_<PORT>/... -> 'tcp:<PORT>'
      - .../pipe/<NAME>/...     -> 'pipe:<NAME>'
      - otherwise: 'generic'
    """
    seeds: List[bytes] = []
    labels: List[str] = []
    for root, _dirs, files in os.walk(dir_path):
        for fn in files:
            if not fn.lower().endswith(".bin"):
                continue
            p = os.path.join(root, fn)
            try:
                with open(p, "rb") as f:
                    seeds.append(f.read())
                lab = "generic"
                lowroot = root.replace("\\", "/").lower()
                m = re.search(r"/port_(\d+)(?:/|$)", lowroot)
                if m:
                    lab = f"tcp:{m.group(1)}"
                m2 = re.search(r"/pipe/([^/\\]+)(?:/|$)", lowroot)
                if m2:
                    lab = f"pipe:{m2.group(1)}"
                labels.append(lab)
            except Exception as e:
                print(f"[seeds] skipping {p}: {e}")
    return seeds, labels

def load_seeds_any(path: str) -> Tuple[List[bytes], List[str]]:
    """
    Accepts:
      - directory of .bin files (returns inferred labels)
      - JSONL with 'data_b64' (and optional 'label')
      - JSON with {"seeds":[...]} (supports seeds_import.json or seeds_manifest.json)
    Returns: (seeds_bytes_list, labels_list)
    """
    if os.path.isdir(path):
        return load_seeds_from_directory(path)

    ext = os.path.splitext(path)[1].lower()
    if ext == ".jsonl":
        seeds: List[bytes] = []
        labels: List[str] = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if "data_b64" in rec:
                    seeds.append(base64.b64decode(rec["data_b64"]))
                    labels.append(rec.get("label", ""))
        return seeds, labels

    # JSON (import json or manifest)
    blob = json.load(open(path, "r", encoding="utf-8"))
    recs = blob.get("seeds")
    if recs is None and isinstance(blob, list):
        recs = blob
    if recs is None:
        recs = []
    seeds: List[bytes] = []
    labels: List[str] = []
    for r in recs:
        if "data_b64" in r:
            seeds.append(base64.b64decode(r["data_b64"]))
            labels.append(r.get("label", ""))
    return seeds, labels

def maybe_autoconfig_transport_from_labels(labels: List[str]) -> None:
    """
    If FUZZ_PID_MODE is unset or 'noop', choose a transport based on labels:
      - exactly one tcp:<port>  -> mode=tcp with 127.0.0.1:<port>
      - exactly one pipe:<name> -> mode=pipe with \\.\pipe\<name>
      - otherwise               -> mode=file (drop dir created)
    Will NOT override an already-set non-'noop' FUZZ_PID_MODE.
    """
    mode = ((os.environ.get("FUZZ_PID_MODE") or "noop").strip()).lower()

    if mode != "noop":
        print(f"[auto] FUZZ_PID_MODE already set to '{mode}', not overriding.")
        return

    tcp_ports: List[int] = []
    pipes: List[str] = []
    for lab in labels or []:
        if isinstance(lab, str) and lab.startswith("tcp:"):
            try:
                tcp_ports.append(int(lab.split(":", 1)[1]))
            except Exception:
                pass
        elif isinstance(lab, str) and lab.startswith("pipe:"):
            pipes.append(lab.split(":", 1)[1])

    tcp_ports = sorted(set(tcp_ports))
    seen = set()
    pipes = [p for p in pipes if not (p in seen or seen.add(p))]

    if len(tcp_ports) == 1 and not pipes:
        os.environ["FUZZ_PID_MODE"] = "tcp"
        os.environ.setdefault("FUZZ_PID_TCP_ADDR", "127.0.0.1")
        os.environ["FUZZ_PID_TCP_PORT"] = str(tcp_ports[0])
        print(f"[auto] FUZZ_PID_MODE=tcp  FUZZ_PID_TCP_ADDR={os.environ['FUZZ_PID_TCP_ADDR']}  FUZZ_PID_TCP_PORT={os.environ['FUZZ_PID_TCP_PORT']}")
        return

    if len(pipes) == 1 and not tcp_ports:
        os.environ["FUZZ_PID_MODE"] = "pipe"
        pipe_name = pipes[0]
        if not pipe_name.startswith(r"\\.\pipe\\") and not pipe_name.startswith(r"\\.\pipe\ "):
            os.environ["FUZZ_PID_PIPE_NAME"] = r"\\.\pipe\\" + pipe_name
        else:
            os.environ["FUZZ_PID_PIPE_NAME"] = pipe_name
        print(f"[auto] FUZZ_PID_MODE=pipe FUZZ_PID_PIPE_NAME={os.environ['FUZZ_PID_PIPE_NAME']}")
        return

    os.environ["FUZZ_PID_MODE"] = "file"
    os.environ.setdefault("FUZZ_PID_DROP_DIR", os.path.join("artifacts", "deliveries"))
    ensure_outdir(os.environ["FUZZ_PID_DROP_DIR"])
    print(f"[auto] effective FUZZ_PID_MODE={os.environ['FUZZ_PID_MODE']!r}")

# ---------------- Strict overflow classifier ----------------
class OverflowClassifier:
    """
    Classifies crashes as probable buffer overflows (strong signals).
    Accepts:
      - Windows: 0xC0000409 (STACK_BUFFER_OVERRUN), 0xC0000374 (HEAP_CORRUPTION)
      - Windows: 0xC0000005 (ACCESS_VIOLATION) only when stderr has overflow markers
      - POSIX: signals {SEGV=11, BUS=7, ABRT=6} only when stderr has overflow markers
      - ASan/UBSan text markers regardless of rc
    """
    OVERFLOW_STDERR_PATTERNS = [
        r"stack smashing detected",
        r"buffer overflow detected",
        r"addresssanitizer",
        r"stack-buffer-overflow",
        r"heap-buffer-overflow",
        r"__fortify_fail",
        r"_security_check_cookie",
        r"stack cookie",
        r"WER_CRASH_DUMP_DETECTED",
    ]
    _pat = re.compile("|".join(f"(?:{p})" for p in OVERFLOW_STDERR_PATTERNS), re.IGNORECASE)

    @staticmethod
    def _posix_signal(rc: Optional[int]) -> Optional[int]:
        if rc is not None and rc < 0:
            return -rc
        return None

    @staticmethod
    def _win_status(rc: Optional[int]) -> Optional[int]:
        if rc is None:
            return None
        return rc & 0xFFFFFFFF

    def classify(self, return_code: Optional[int], stderr_bytes: bytes) -> Tuple[bool, List[str]]:
        s = (stderr_bytes or b"").decode("utf-8", errors="ignore")
        markers = bool(self._pat.search(s))
        indicators: List[str] = []
        if markers:
            indicators.append("stderr:overflow_markers")

        status = self._win_status(return_code)
        if status == 0xC0000409:
            indicators.append("ntstatus:STACK_BUFFER_OVERRUN")
            return True, indicators
        if status == 0xC0000374:
            indicators.append("ntstatus:HEAP_CORRUPTION")
            return True, indicators
        if status == 0xC0000005 and markers:
            indicators.append("ntstatus:ACCESS_VIOLATION+markers")
            return True, indicators

        sig = self._posix_signal(return_code)
        if sig in (11, 7, 6) and markers:
            indicators.append(f"posix_signal:{sig}+markers")
            return True, indicators

        if markers and (status is None or status == 0):
            indicators.append("asan_text_only")
            return True, indicators

        return False, indicators

# ---------------- Heuristic signals (latency / stderr burst / rc sets) ----------------
class HeuristicSignals:
    def __init__(self):
        self.lat_ms = []
        self.stderr_lens = []
        self.rc_hist = {}

    def update_and_score(self, *, dt_ms: float, stderr_len: int, rc: Optional[int]) -> Tuple[bool, List[str], float]:
        reasons = []
        # update history
        self.lat_ms.append(dt_ms)
        self.lat_ms = self.lat_ms[-200:]
        self.stderr_lens.append(stderr_len)
        self.stderr_lens = self.stderr_lens[-200:]
        if rc is not None:
            self.rc_hist[rc] = self.rc_hist.get(rc, 0) + 1
            if rc in (3, -1073741819, 0xC0000005):  # generic Windows AV or odd exits
                reasons.append(f"rc:{rc}")

        # compute z-ish scores
        def mean(xs): return sum(xs)/len(xs) if xs else 0.0
        def stdev(xs):
            if len(xs) < 2: return 0.0
            m = mean(xs); return (sum((x-m)*(x-m) for x in xs)/ (len(xs)-1))**0.5

        lat_m, lat_s = mean(self.lat_ms), stdev(self.lat_ms)
        sd_m, sd_s = mean(self.stderr_lens), stdev(self.stderr_lens)
        z_lat = (dt_ms - lat_m) / (lat_s if lat_s > 1e-6 else 1e9)
        z_sd  = (stderr_len - sd_m) / (sd_s if sd_s > 1e-6 else 1e9)

        score = max(z_lat, z_sd)
        if z_lat > 4.0:
            reasons.append("latency_spike")
        if z_sd > 4.0:
            reasons.append("stderr_spike")

        suspicious = bool(reasons)
        return suspicious, reasons, score

# ---------------- Token harvesting from stderr ----------------
_token_rgx = re.compile(r"[A-Za-z0-9_]{4,32}")
def harvest_tokens_from_stderr(stderr: bytes) -> List[bytes]:
    s = (stderr or b"").decode("utf-8", errors="ignore")
    toks = set()
    for m in _token_rgx.findall(s):
        if m.lower() in ("error","fatal","exception","warning","failed","invalid","stack","heap"):
            continue
        toks.add(m.encode("latin-1", "ignore"))
    return list(toks)

# ---------------- File templates to exercise real parsers ----------------
def with_file_template(payload: bytes, kind: Optional[str]) -> bytes:
    if not kind: return payload
    k = kind.lower()
    if k == "png":
        # minimal PNG w/ payload in IDAT
        return (b"\x89PNG\r\n\x1a\n"
                b"\x00\x00\x00\rIHDR" + b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00" +
                b"\x90wS\xde" +
                b"\x00\x00\x00\x08IDAT" + payload[:1024] +
                b"\x00\x00\x00\x00IEND\xaeB`\x82")
    if k == "zip":
        return b"PK\x03\x04" + payload[:2048]
    if k == "json":
        try:
            s = payload.decode("latin-1","ignore")
        except:
            s = str(payload)
        return ("{\"data\":\"" + s.replace("\\","\\\\").replace("\"","\\\"")[:4000] + "\"}").encode("utf-8","ignore")
    if k == "xml":
        return (b"<?xml version='1.0'?><data>" + payload[:4000] + b"</data>")
    if k == "bmp":
        body = payload[:4096]
        header = b"BM" + (14+40+len(body)).to_bytes(4,"little") + b"\x00\x00\x00\x00" + (14+40).to_bytes(4,"little")
        dib = (40).to_bytes(4,"little")+ (1).to_bytes(4,"little")+ (1).to_bytes(4,"little") + (1).to_bytes(2,"little")+ (24).to_bytes(2,"little") + (0).to_bytes(4,"little")+ len(body).to_bytes(4,"little")+ (2835).to_bytes(4,"little")*2 + (0).to_bytes(4,"little")*2
        return header+dib+body
    if k == "wav":
        body = payload[:4096]
        return b"RIFF" + (36+len(body)).to_bytes(4,"little") + b"WAVEfmt " + (16).to_bytes(4,"little") + (1).to_bytes(2,"little")+ (1).to_bytes(2,"little") + (8000).to_bytes(4,"little")+ (8000).to_bytes(4,"little")+ (1).to_bytes(2,"little")+ (8).to_bytes(2,"little")+ b"data" + len(body).to_bytes(4,"little") + body
    return payload

# ---- hashing / normalize helpers ----
def _sha1(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()

def _normalize_text_for_bucket(s: str) -> str:
    # Strip paths, hex pointers, decimal PIDs, timestamps
    s = re.sub(r"[A-Za-z]:(?:\\[^\\\r\n]+)+", "PATH", s)
    s = re.sub(r"0x[0-9A-Fa-f]+", "0xADDR", s)
    s = re.sub(r"\b\d{5,}\b", "NUM", s)
    s = re.sub(r"\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\b", "TIME", s)
    return "\n".join(s.splitlines()[:12]).strip()

# ---- Crash bucketer ----
class CrashBucketer:
    def __init__(self):
        self._seen = set()
    def _key(self, rc: Optional[int], stderr: bytes) -> str:
        s = (stderr or b"").decode("utf-8", errors="ignore")
        s = _normalize_text_for_bucket(s)
        return f"{rc}|{_sha1(s.encode('utf-8', 'ignore'))}"
    def seen_before(self, rc: Optional[int], stderr: bytes) -> bool:
        k = self._key(rc, stderr)
        if k in self._seen: return True
        self._seen.add(k); return False

# ---- Novelty map: black-box "coverage-ish" ----
class NoveltyMap:
    def __init__(self):
        self._keys = set()
    def _vec(self, *, rc: Optional[int], dt_ms: float, stdout: bytes, stderr: bytes) -> bytes:
        se = len(stderr or b"")
        so = len(stdout or b"")
        rc_mod = (rc or 0) & 0xFF
        latb = int(max(0, min(9999, dt_ms))) // 10
        se_b = se // 64
        so_b = so // 64
        norm = _normalize_text_for_bucket((stderr or b"").decode("utf-8", "ignore"))
        lines = norm.splitlines()[:4]
        fp = _sha1("\n".join(lines).encode("utf-8", "ignore"))[:12]
        return f"{se_b}:{so_b}:{rc_mod}:{latb}:{fp}".encode()
    def accept(self, *, rc: Optional[int], dt_ms: float, stdout: bytes, stderr: bytes) -> bool:
        key = _sha1(self._vec(rc=rc, dt_ms=dt_ms, stdout=stdout, stderr=stderr))
        if key in self._keys: return False
        self._keys.add(key); return True

# ---- Corpus manager ----
class CorpusManager:
    def __init__(self, root="artifacts/corpus", cap=500):
        self.root = root; self.cap = cap
        ensure_outdir(self.root); self._count = 0
    def save(self, payload: bytes, tag: str = "novel") -> str:
        self._count += 1
        if self._count > self.cap: return ""
        fn = os.path.join(self.root, f"{tag}_{now_stamp()}.bin")
        with open(fn, "wb") as f: f.write(payload)
        return fn

# ---- Minimizer ----
def minimize_payload(payload: bytes, predicate, time_budget_ms: int = 1200) -> bytes:
    start = time.perf_counter()
    best = payload
    # Phase 1: chunk remove
    step = max(8, len(best)//8)
    while step >= 8 and (time.perf_counter()-start)*1000 < time_budget_ms:
        changed = False; i = 0
        while i < len(best) and (time.perf_counter()-start)*1000 < time_budget_ms:
            j = min(len(best), i+step)
            cand = best[:i] + best[j:]
            if len(cand) >= 1 and predicate(cand):
                best = cand; changed = True
            else:
                i += step
        if not changed: step //= 2
    # Phase 2: overwrite windows
    step = max(4, len(best)//16)
    for bval in (0x41, 0x00, 0xFF, 0x20):
        if (time.perf_counter()-start)*1000 >= time_budget_ms: break
        i = 0
        while i < len(best) and (time.perf_counter()-start)*1000 < time_budget_ms:
            j = min(len(best), i+step)
            cand = bytearray(best)
            for k in range(i, j): cand[k] = bval
            cand = bytes(cand)
            if predicate(cand): best = cand
            i += step
    return best

# ---- Length schedule (avoid stuck sizes) ----
def _length_schedule(iter_idx: int, base_len: int, max_growth: int) -> int:
    B = [32, 48, 64, 80, 96, 128, 160, 192, 224, 256, 384, 512, 768, 1024, 1536, 2048]
    wave = B[(iter_idx // 7) % len(B)]
    soft_cap = min(base_len + max_growth, 4096)
    return max(1, min(soft_cap, wave))

# ---- WER CrashDump watcher ----
class WerWatcher:
    def __init__(self, dir_path=None):
        dir_path = dir_path or os.path.join(os.environ.get("LOCALAPPDATA",""), "CrashDumps")
        self.dir = dir_path
        self._seen = set()
        if self.dir and os.path.isdir(self.dir):
            for fn in os.listdir(self.dir):
                self._seen.add(fn)
    def poll_new(self) -> List[str]:
        if not self.dir or not os.path.isdir(self.dir): return []
        out = []
        for fn in os.listdir(self.dir):
            if fn in self._seen: continue
            self._seen.add(fn)
            if fn.lower().endswith((".dmp",".mdmp")):
                out.append(os.path.join(self.dir, fn))
        return out

# ---------------- Repro script builder ----------------
class ReproScriptBuilder:
    """
    Writes a self-contained Python reproducer for argv/stdin/env/file and can re-run once.
    """
    def __init__(self, out_dir: str = "crashes"):
        self.out_dir = out_dir
        ensure_outdir(self.out_dir)

    def _write_payload_files(self, base: str, payload: bytes) -> Tuple[str, str]:
        bin_path = os.path.join(self.out_dir, base + ".bin")
        txt_path = os.path.join(self.out_dir, base + ".txt")
        with open(bin_path, "wb") as f:
            f.write(payload)
        with open(txt_path, "w", encoding="utf-8", errors="ignore") as f:
            f.write(payload.decode("latin-1", errors="replace"))
        return bin_path, txt_path

    def _script_body(self, target: str, surface: str, payload_bin: str,
                     timeout: Optional[float], arg_index: Optional[int],
                     env_overrides: Optional[Dict[str, str]],
                     file_arg_index: Optional[int]) -> str:
        return textwrap.dedent(f"""\
        #!/usr/bin/env python3
        import os, sys, subprocess, time

        TARGET = {json.dumps(target)}
        SURFACE = {json.dumps(surface)}
        PAYLOAD_BIN = {json.dumps(payload_bin)}
        TIMEOUT = {repr(timeout) if timeout is not None else 'None'}
        ARG_INDEX = {arg_index if arg_index is not None else 'None'}
        FILE_ARG_INDEX = {file_arg_index if file_arg_index is not None else 'None'}
        ENV_OVERRIDES = {json.dumps(env_overrides or {})}

        def main():
            with open(PAYLOAD_BIN, "rb") as f:
                payload = f.read()

            env = os.environ.copy()
            env.update(ENV_OVERRIDES or {{}})

            if SURFACE == "argv":
                if ARG_INDEX is None:
                    print("[repro] ARG_INDEX required for argv"); sys.exit(2)
                max_idx = max(ARG_INDEX, 1)
                argv = [TARGET] + ["DUMMY"] * max_idx
                argv[ARG_INDEX] = payload.decode("latin-1", errors="ignore")
                t0=time.perf_counter()
                cp = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=TIMEOUT)
            elif SURFACE == "stdin":
                t0=time.perf_counter()
                cp = subprocess.run([TARGET], input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=TIMEOUT)
            elif SURFACE == "env":
                env = env.copy()
                env["PAYLOAD"] = payload.decode("latin-1", errors="ignore")
                t0=time.perf_counter()
                cp = subprocess.run([TARGET], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=TIMEOUT)
            elif SURFACE == "file":
                if FILE_ARG_INDEX is None:
                    print("[repro] FILE_ARG_INDEX required for file"); sys.exit(2)
                tmp_path = os.path.join(os.path.dirname(PAYLOAD_BIN), "input_{now_stamp()}.dat")
                with open(tmp_path, "wb") as f:
                    f.write(payload)
                max_idx = max(FILE_ARG_INDEX, 1)
                argv = [TARGET] + ["DUMMY"] * max_idx
                argv[FILE_ARG_INDEX] = tmp_path
                t0=time.perf_counter()
                cp = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=TIMEOUT)
            else:
                print("[repro] Unknown surface:", SURFACE); sys.exit(2)

            dt_ms = (time.perf_counter()-t0)*1000.0
            print("[repro] returncode:", cp.returncode, "dt_ms=%.1f" % dt_ms)
            if cp.stdout:
                print("[repro] --- stdout ---\\n" + cp.stdout.decode("utf-8", errors="replace"))
            if cp.stderr:
                print("[repro] --- stderr ---\\n" + cp.stderr.decode("utf-8", errors="replace"))

        if __name__ == "__main__":
            main()
        """)

    def build_and_optionally_run(self, *, target_path: str, surface: str, payload: bytes,
                                 timeout: Optional[float] = 2.0,
                                 arg_index: Optional[int] = None,
                                 env_overrides: Optional[Dict[str, str]] = None,
                                 file_arg_index: Optional[int] = None,
                                 run_after_write: bool = True) -> Dict[str, str]:
        base = f"overflow_{now_stamp()}"
        bin_path, txt_path = self._write_payload_files(base, payload)
        script_path = os.path.join(self.out_dir, base + ".py")
        script = self._script_body(target_path, surface, bin_path, timeout, arg_index, env_overrides, file_arg_index)
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script)
        try:
            os.chmod(script_path, 0o755)
        except Exception:
            pass
        if run_after_write:
            try:
                os.system(f"\"{sys.executable}\" \"{script_path}\"")
            except Exception as e:
                print(f"[repro] Error re-running: {e}")
        return {"payload_bin": bin_path, "payload_txt": txt_path, "reproducer_py": script_path}

# ---------------- Core OOP inspector (IAT) ----------------
class ProcessImportsInspector:
    """
    Read-only inspector:
      - list loaded modules (DLLs)
      - parse import table (IAT) for the EXE or for each module (opt)
    """
    def __init__(self, pid: int):
        self.pid = pid
        self.hProcess: Optional[W.HANDLE] = None
        self._open()

    def _open(self):
        access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ
        h = OpenProcess(access, False, self.pid)
        if not h:
            _raise_last_error(f"OpenProcess failed for PID {self.pid}")
        self.hProcess = h

    def close(self):
        if self.hProcess:
            CloseHandle(self.hProcess)
            self.hProcess = None

    # ----- RPM helpers -----
    def _rpm(self, addr: int, size: int) -> bytes:
        buf = (C.c_ubyte * size)()
        read = C.c_size_t(0)
        ok = ReadProcessMemory(self.hProcess, C.c_void_p(addr), buf, size, C.byref(read))
        if not ok or read.value != size:
            _raise_last_error(f"ReadProcessMemory failed at 0x{addr:016X} size {size}")
        return bytes(buf)

    def _rpm_struct(self, addr: int, cstruct):
        size = C.sizeof(cstruct)
        data = self._rpm(addr, size)
        inst = cstruct()
        C.memmove(C.byref(inst), data, size)
        return inst

    def _read_c_string(self, addr: int, maxlen: int = 4096) -> str:
        out = bytearray()
        step = 256
        total = 0
        while total < maxlen:
            chunk = self._rpm(addr + total, step)
            for b in chunk:
                if b == 0:
                    return out.decode(errors="replace")
                out.append(b)
            total += step
        return out.decode(errors="replace")

    # ----- modules -----
    def list_modules(self) -> List[Dict]:
        needed = W.DWORD(0)
        EnumProcessModulesEx(self.hProcess, None, 0, C.byref(needed), LIST_MODULES_ALL)
        count = needed.value // C.sizeof(W.HMODULE)
        arr = (W.HMODULE * count)()
        if not EnumProcessModulesEx(self.hProcess, arr, needed, C.byref(needed), LIST_MODULES_ALL):
            _raise_last_error("EnumProcessModulesEx failed")

        mods = []
        for i in range(count):
            hmod = arr[i]
            path_buf = C.create_unicode_buffer(MAX_PATH * 4)
            GetModuleFileNameExW(self.hProcess, hmod, path_buf, len(path_buf))
            mi = MODULEINFO()
            if not GetModuleInformation(self.hProcess, hmod, C.byref(mi), C.sizeof(mi)):
                _raise_last_error("GetModuleInformation failed")
            base = int(C.cast(mi.lpBaseOfDll, W.LPVOID).value)
            mods.append({"hmodule": hmod, "base": base, "size": mi.SizeOfImage, "path": path_buf.value})
        return mods

    # ----- import parsing for a given module base -----
    def enumerate_imports_for_base(self, image_base: int) -> List[Dict]:
        dos = self._rpm_struct(image_base, IMAGE_DOS_HEADER)
        if dos.e_magic != 0x5A4D:  # 'MZ'
            return []

        nt_addr = image_base + dos.e_lfanew
        nt = self._rpm_struct(nt_addr, IMAGE_NT_HEADERS64)
        if nt.Signature != 0x4550:  # 'PE\0\0'
            return []
        opt = nt.OptionalHeader

        dir_import = opt.DataDirectory[1]  # IMPORT
        import_rva = dir_import.VirtualAddress
        import_size = dir_import.Size
        if import_rva == 0 or import_size == 0:
            return []

        imports = []
        desc_size = C.sizeof(IMAGE_IMPORT_DESCRIPTOR)
        idx = 0
        while True:
            desc_addr = image_base + import_rva + idx * desc_size
            desc = self._rpm_struct(desc_addr, IMAGE_IMPORT_DESCRIPTOR)
            if desc.Name == 0:
                break

            dll_name = self._read_c_string(image_base + desc.Name)
            oft_rva = desc.OriginalFirstThunk or 0
            ft_rva  = desc.FirstThunk or 0
            if ft_rva == 0:
                idx += 1
                continue

            thunk_index = 0
            while True:
                iat_entry_va = image_base + ft_rva + thunk_index * C.sizeof(IMAGE_THUNK_DATA64)
                t_ft = self._rpm_struct(iat_entry_va, IMAGE_THUNK_DATA64)
                if t_ft.Function == 0:
                    break

                func_name = None
                hint_val = None
                ordinal_val = None

                if oft_rva:
                    int_entry_va = image_base + oft_rva + thunk_index * C.sizeof(IMAGE_THUNK_DATA64)
                    t_oft = self._rpm_struct(int_entry_va, IMAGE_THUNK_DATA64)
                    if (t_oft.Ordinal & (1 << 63)) != 0:
                        ordinal_val = t_oft.Ordinal & 0xFFFF
                    else:
                        ibn_addr = image_base + t_oft.AddressOfData
                        hint_raw = self._rpm(ibn_addr, 2)
                        hint_val = int.from_bytes(hint_raw, "little", signed=False)
                        func_name = self._read_c_string(ibn_addr + 2)

                imports.append({
                    "dll": dll_name,
                    "func": func_name,
                    "ordinal": ordinal_val,
                    "hint": hint_val,
                    "iat_entry_va": iat_entry_va,
                    "resolved_ptr": t_ft.Function,
                    "image_base": image_base,
                })
                thunk_index += 1

            idx += 1

        return imports

    def enumerate_imports_main_only(self) -> List[Dict]:
        mods = self.list_modules()
        if not mods:
            return []
        main = mods[0]
        return self.enumerate_imports_for_base(main["base"])

    def enumerate_imports_all_modules(self) -> List[Dict]:
        out: List[Dict] = []
        for m in self.list_modules():
            try:
                out.extend(self.enumerate_imports_for_base(m["base"]))
            except Exception:
                pass
        return out

# ---------------- Artifact writer & printing ----------------
def filter_entries(entries: List[Dict], dll_rgx: Optional[str], func_rgx: Optional[str], only_ordinal: bool) -> List[Dict]:
    dr = re.compile(dll_rgx, re.I) if dll_rgx else None
    fr = re.compile(func_rgx, re.I) if func_rgx else None
    out = []
    for e in entries:
        if dr and not dr.search(e["dll"] or ""):
            continue
        if only_ordinal and e.get("ordinal") is None:
            continue
        if fr:
            fname = e.get("func") or ""
            if not fr.search(fname):
                continue
        out.append(e)
    return out

def write_artifacts(base: str, entries: List[Dict]) -> Dict[str, str]:
    ensure_artifacts()
    json_path = os.path.join("artifacts", base + ".json")
    csv_path  = os.path.join("artifacts", base + ".csv")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)

    cols = ["dll", "func", "ordinal", "hint", "iat_entry_va", "resolved_ptr", "image_base"]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for e in entries:
            w.writerow([e.get(c, "") for c in cols])

    return {"json": json_path, "csv": csv_path}

def print_preview(entries: List[Dict], limit: int = 50):
    print(f"[+] Imported functions (showing up to {limit}):")
    print("    {:<28}  {:<36}  {:>16}  {:>16}".format("DLL", "Function/Ordinal", "IAT Entry", "Resolved Ptr"))
    shown = 0
    for e in entries[:limit]:
        f_display = e["func"] if e["func"] else f"ordinal#{e.get('ordinal')}"
        print(f"    {e['dll']:<28}  {f_display:<36}  0x{e['iat_entry_va']:016X}  0x{e['resolved_ptr']:016X}")
        shown += 1
    if len(entries) > shown:
        print(f"    ... +{len(entries) - shown} more")

def get_exe_path_from_pid(pid: int) -> str:
    insp = ProcessImportsInspector(pid)
    try:
        mods = insp.list_modules()
        if not mods:
            raise RuntimeError(f"No modules found for PID {pid}")
        return mods[0]["path"]
    finally:
        insp.close()

# ---------------- Fuzzing Skeleton (process-spawn) ----------------
class FuzzSkeleton:
    """
    Usable fuzzer for spawned targets.
    - Deterministic, length-bounded mutator + length schedule
    - Simple runner for argv/stdin/env/file
    - Novelty-driven corpus, crash bucketing, minimizer, heuristics, WER watcher
    """
    def __init__(self, *, target_path: str, surface: str,
                 timeout: float, arg_index: Optional[int],
                 file_arg_index: Optional[int],
                 env_overrides: Dict[str, str],
                 out_dir: str):
        import subprocess  # local import
        self.subprocess = subprocess

        self.target_path = target_path
        self.surface = surface
        self.timeout = timeout
        self.arg_index = arg_index
        self.file_arg_index = file_arg_index
        self.env_overrides = env_overrides
        self.out_dir = out_dir

        self.max_growth = int(os.environ.get("FUZZ_PID_MAX_GROW", "1024"))
        self._avoid_set = set()
        self.file_template = os.environ.get("FUZZ_FILE_TEMPLATE", None)

        self.classifier = OverflowClassifier()
        self.repro = ReproScriptBuilder(out_dir=out_dir)
        self.crash_buckets = CrashBucketer()
        self.novelty = NoveltyMap()
        self.corpus = CorpusManager()
        self.hsig = HeuristicSignals()
        self.tokens: List[bytes] = []
        self.wer = WerWatcher(os.environ.get("FUZZ_WER_DIR"))

    # ---- deterministic mutator ----
    def _mutate(self, seed: bytes, iteration: int) -> bytes:
        def xorshift32(x: int) -> int:
            x ^= (x << 13) & 0xFFFFFFFF
            x ^= (x >> 17) & 0xFFFFFFFF
            x ^= (x << 5)  & 0xFFFFFFFF
            return x & 0xFFFFFFFF
        def rnd(state: int, mod: int) -> (int, int):
            state = xorshift32(state)
            return (state % max(1, mod)), state
        def sanitize(buf: bytearray, avoid: set) -> bytearray:
            if not avoid: return buf
            st = 0xDEADBEEF
            for i,b in enumerate(buf):
                if b in avoid:
                    idx, st = rnd(st, 256)
                    rep = idx
                    while rep in avoid:
                        rep = (rep + 1) & 0xFF
                    buf[i] = rep
            return buf

        s = seed or b"A"
        it = max(0, int(iteration))
        seed_hash = ((len(s) & 0xFFFF) << 16) ^ (it & 0xFFFF) or 0xBEEFCAFE
        strat = it % 7

        if strat == 0:
            out = bytes(sanitize(bytearray(s), self._avoid_set))
        elif strat == 1:
            buf = bytearray(s)
            pos = (seed_hash % max(1,len(buf)))
            bit = (seed_hash >> 5) & 7
            buf[pos] ^= (1 << bit)
            out = bytes(sanitize(buf, self._avoid_set))
        elif strat == 2:
            interesting = [0x00,0xFF,0x7F,0x80,0x20,0x0A,0x0D,0x09,0x41,0x61,0x2F,0x5C]
            buf = bytearray(s)
            pos = seed_hash % max(1,len(buf))
            buf[pos] = interesting[it % len(interesting)]
            out = bytes(sanitize(buf, self._avoid_set))
        elif strat == 3:
            buf = bytearray(s)
            win_len = min(max(2, (it % 7) + 2), max(1, len(buf)))
            start_max = max(1, len(buf) - win_len + 1)
            start = seed_hash % start_max
            delta = ((it & 3) - 1)
            for i in range(start, start + win_len):
                buf[i] = (buf[i] + delta) & 0xFF
            out = bytes(sanitize(buf, self._avoid_set))
        elif strat == 4:
            cap = min(len(s) + max(16, min(128, len(s) or 64)), len(s) + self.max_growth)
            base = s or b"A"
            rep = (cap + len(base) - 1) // len(base)
            buf = bytearray((base * rep)[:cap])
            if buf:
                pos = seed_hash % len(buf)
                buf[pos] = (buf[pos] ^ (it & 0x7F)) & 0xFF
            out = bytes(sanitize(buf, self._avoid_set))
        elif strat == 5 and self.tokens:
            # splice-in token
            tok = random.choice(self.tokens)
            pos = seed_hash % (len(s)+1)
            out = s[:pos] + tok + s[pos:]
        else:
            mid = len(s) // 2
            out = (s[:mid] + s[:mid-1:-1]) if s else b"A"

        # length schedule bias (prevents plateaus)
        target_len = _length_schedule(it, len(s), self.max_growth)
        if len(out) < target_len:
            out = (out + out[::-1] + b"A"*target_len)[:target_len]
        elif len(out) > target_len:
            head = target_len // 2
            tail = target_len - head
            out = out[:head] + out[-tail:]

        return bytes(out)

    def _choose_surface_for_payload(self, payload: bytes) -> Tuple[str, Optional[int], Optional[int]]:
        if self.surface != "auto":
            return self.surface, self.arg_index, self.file_arg_index
        if self.arg_index is not None and b"\x00" not in payload:
            return "argv", self.arg_index, None
        if self.file_arg_index is not None:
            return "file", None, self.file_arg_index
        return "stdin", None, None

    # ---- runner for spawned process ----
    def _execute(self, payload: bytes) -> Tuple[int, bytes, bytes, float]:
        env = os.environ.copy()
        env.update(self.env_overrides or {})

        chosen_surface, arg_idx, file_idx = self._choose_surface_for_payload(payload)
        if chosen_surface == "argv":
            if arg_idx is None:
                raise ValueError("argv surface requires --arg-index (auto)")
            max_idx = max(arg_idx, 1)
            argv = [self.target_path] + ["DUMMY"] * max_idx
            argv[arg_idx] = payload.decode("latin-1", errors="ignore")
            t0 = time.perf_counter()
            cp = self.subprocess.run(argv, stdout=self.subprocess.PIPE, stderr=self.subprocess.PIPE,
                                     env=env, timeout=self.timeout)
            dt_ms = (time.perf_counter() - t0) * 1000.0
            return cp.returncode or 0, cp.stdout or b"", cp.stderr or b"", dt_ms

        if chosen_surface == "stdin":
            t0 = time.perf_counter()
            cp = self.subprocess.run([self.target_path], input=payload,
                                     stdout=self.subprocess.PIPE, stderr=self.subprocess.PIPE,
                                     env=env, timeout=self.timeout)
            dt_ms = (time.perf_counter() - t0) * 1000.0
            return cp.returncode or 0, cp.stdout or b"", cp.stderr or b"", dt_ms

        if chosen_surface == "env":
            env2 = env.copy()
            env2["PAYLOAD"] = payload.decode("latin-1", errors="ignore")
            t0 = time.perf_counter()
            cp = self.subprocess.run([self.target_path], stdout=self.subprocess.PIPE, stderr=self.subprocess.PIPE,
                                     env=env2, timeout=self.timeout)
            dt_ms = (time.perf_counter() - t0) * 1000.0
            return cp.returncode or 0, cp.stdout or b"", cp.stderr or b"", dt_ms

        if chosen_surface == "file":
            if file_idx is None:
                raise ValueError("file surface requires --file-arg-index (auto)")
            tmp = os.path.join(self.out_dir, f"input_{now_stamp()}.dat")
            # apply optional template
            to_write = with_file_template(payload, self.file_template)
            with open(tmp, "wb") as f:
                f.write(to_write)
            max_idx = max(file_idx, 1)
            argv = [self.target_path] + ["DUMMY"] * max_idx
            argv[file_idx] = tmp
            t0 = time.perf_counter()
            cp = self.subprocess.run(argv, stdout=self.subprocess.PIPE, stderr=self.subprocess.PIPE,
                                     env=env, timeout=self.timeout)
            dt_ms = (time.perf_counter() - t0) * 1000.0
            return cp.returncode or 0, cp.stdout or b"", cp.stderr or b"", dt_ms

        raise ValueError(f"unknown surface: {chosen_surface}")

    # ---- orchestrator for spawned process ----
    def run(self, seeds: List[bytes], max_iters: int) -> None:
        if not seeds:
            print("[fuzz] No seeds provided; nothing to do.")
            return

        print(f"[fuzz] Skeleton started | target={self.target_path} | surface={self.surface} "
              f"| iters={max_iters} | seeds={len(seeds)}")

        for si, seed in enumerate(seeds):
            print(f"[fuzz] seed {si+1}/{len(seeds)} (len={len(seed)})")
            for it in range(max(1, max_iters)):
                try:
                    payload = self._mutate(seed, it)
                except Exception as e:
                    print(f"[fuzz] mutation error at iter {it}: {e}")
                    continue

                try:
                    rc, stdout, stderr, dt_ms = self._execute(payload)
                except Exception as e:
                    print(f"[fuzz] execution error at iter {it}: {e}")
                    continue

                # WER crashdump watcher
                wer_new = self.wer.poll_new()
                if wer_new:
                    print(f"[wer] new crash dumps detected: {len(wer_new)}")
                    stderr = (stderr or b"") + b"\nWER_CRASH_DUMP_DETECTED\n"

                # token harvest from stderr
                new_toks = harvest_tokens_from_stderr(stderr)
                for t in new_toks:
                    if t not in self.tokens:
                        self.tokens.append(t)
                if new_toks:
                    print(f"[dict] harvested {len(new_toks)} tokens from stderr (total {len(self.tokens)})")

                # novelty -> corpus
                if self.novelty.accept(rc=rc, dt_ms=dt_ms, stdout=stdout, stderr=stderr):
                    saved = self.corpus.save(payload, tag="novel")
                    if saved:
                        print(f"[corpus] novel behavior -> saved {saved}")

                # heuristics
                suspicious, h_reasons, h_score = self.hsig.update_and_score(
                    dt_ms=dt_ms, stderr_len=len(stderr or b""), rc=rc
                )

                # classification (strong) + optional promotion
                is_overflow, indicators = self.classifier.classify(rc, stderr)
                crashed = is_overflow
                if not crashed and os.environ.get("FUZZ_PROMOTE_HEUR", "0") == "1" and suspicious:
                    crashed = True
                    indicators = (indicators or []) + [f"heur:{'+'.join(h_reasons)}"]

                if not crashed:
                    continue

                # bucket suppression
                if self.crash_buckets.seen_before(rc, stderr):
                    print("[crash] duplicate bucket; skipping repro bundle")
                    continue

                # minimization
                do_min = os.environ.get("FUZZ_MINIMIZE", "1") == "1"
                min_ms = int(os.environ.get("FUZZ_MINIMIZE_BUDGET_MS", "1200"))
                if do_min:
                    def pred(b: bytes) -> bool:
                        try:
                            rc2, so2, se2, _dt = self._execute(b)
                        except Exception:
                            return False
                        ok2, _ = self.classifier.classify(rc2, se2)
                        if ok2:
                            return True
                        if os.environ.get("FUZZ_PROMOTE_HEUR", "0") == "1":
                            suspicious2, _r, _s = self.hsig.update_and_score(
                                dt_ms=_dt, stderr_len=len(se2 or b""), rc=rc2
                            )
                            return suspicious2
                        return False
                    payload_min = minimize_payload(payload, pred, time_budget_ms=min_ms)
                    if len(payload_min) < len(payload):
                        print(f"[min] shrank payload {len(payload)} -> {len(payload_min)} bytes")
                        payload = payload_min

                # save crash payload
                saved = self.corpus.save(payload, tag="crash")
                if saved:
                    print(f"[crash] saved payload -> {saved}")

                print("\n=== PROBABLE VULN (spawned) ===")
                print("Indicators:", ", ".join(indicators))
                paths = self.repro.build_and_optionally_run(
                    target_path=self.target_path,
                    surface=self.surface,
                    payload=payload,
                    timeout=self.timeout,
                    arg_index=self.arg_index,
                    env_overrides=self.env_overrides,
                    file_arg_index=self.file_arg_index,
                    run_after_write=True
                )
                print("[fuzz] Repro bundle:", json.dumps(paths, indent=2))
                print("[fuzz] Stopping after first positive (skeleton behavior).")
                return

        print("[fuzz] Completed without detecting probable buffer overflows.")

# ---------------- Fuzzing Skeleton for a running PID ----------------
class FuzzSkeletonPID:
    """
    Safe, non-operational-by-default skeleton that attaches to a running PID (read-only)
    and delivers payloads via opt-in transports (noop/file/tcp/pipe). No injection or RPM writes.
    """
    def __init__(self, *, pid: int, target_path_for_repro: str, surface: str,
                 timeout: float,
                 arg_index: Optional[int],
                 file_arg_index: Optional[int],
                 env_overrides: Dict[str, str],
                 out_dir: str):
        self.pid = pid
        self.surface = surface
        self.timeout = timeout
        self.arg_index = arg_index
        self.file_arg_index = file_arg_index
        self.env_overrides = env_overrides
        self.out_dir = out_dir
        self.target_path_for_repro = target_path_for_repro

        # Transport/monitor configuration via environment variables
        self.mode = (os.environ.get("FUZZ_PID_MODE", "noop") or "noop").strip().lower()
        self.drop_dir = (os.environ.get("FUZZ_PID_DROP_DIR", os.path.join("artifacts", "deliveries")) or "").strip() or os.path.join("artifacts", "deliveries")
        self.tcp_addr = (os.environ.get("FUZZ_PID_TCP_ADDR", "127.0.0.1") or "127.0.0.1").strip()
        self.tcp_port = int((os.environ.get("FUZZ_PID_TCP_PORT", "0") or "0").strip() or "0")
        self.pipe_name = (os.environ.get("FUZZ_PID_PIPE_NAME", "") or "").strip() or None
        self.monitor_log = (os.environ.get("FUZZ_PID_MONITOR_LOG", "") or "").strip() or None
        self.file_template = os.environ.get("FUZZ_FILE_TEMPLATE", None)

        ensure_outdir(self.drop_dir)

        # Mutation & log-tail config (env overrides)
        self.max_growth = int(os.environ.get("FUZZ_PID_MAX_GROW", "1024"))
        self.avoid_hex  = os.environ.get("FUZZ_PID_AVOID_HEX", "")
        self._avoid_set = {int(t, 16) & 0xFF for t in re.split(r"[,\s]+", self.avoid_hex) if t} if self.avoid_hex else set()
        self._log_pos: int = 0

        # Attach read-only to the process (metadata only)
        access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
        self.hProcess = OpenProcess(access, False, pid)
        if not self.hProcess:
            _raise_last_error(f"OpenProcess failed for PID {pid}")

        self.classifier = OverflowClassifier()
        self.repro = ReproScriptBuilder(out_dir=out_dir)
        self.crash_buckets = CrashBucketer()
        self.novelty = NoveltyMap()
        self.corpus = CorpusManager()
        self.hsig = HeuristicSignals()
        self.tokens: List[bytes] = []
        self.wer = WerWatcher(os.environ.get("FUZZ_WER_DIR"))

    def close(self):
        if self.hProcess:
            CloseHandle(self.hProcess)
            self.hProcess = None

    # ---- deterministic mutator (same ideas as spawn) ----
    def _mutate(self, seed: bytes, iteration: int) -> bytes:
        def xorshift32(x: int) -> int:
            x ^= (x << 13) & 0xFFFFFFFF
            x ^= (x >> 17) & 0xFFFFFFFF
            x ^= (x << 5)  & 0xFFFFFFFF
            return x & 0xFFFFFFFF
        def rnd(state: int, mod: int) -> (int, int):
            state = xorshift32(state)
            return (state % max(1, mod)), state
        def sanitize(buf: bytearray) -> bytearray:
            if not self._avoid_set:
                return buf
            st = 0xDEADBEEF
            for i, b in enumerate(buf):
                if b in self._avoid_set:
                    idx, st = rnd(st, 256)
                    rep = idx
                    if rep in self._avoid_set:
                        rep = (rep + 1) & 0xFF
                        while rep in self._avoid_set:
                            rep = (rep + 1) & 0xFF
                    buf[i] = rep
            return buf

        s = seed or b"A"
        it = max(0, int(iteration))
        strat = it % 7

        if strat == 0:
            out = bytes(sanitize(bytearray(s)))
        elif strat == 1:
            buf = bytearray(s)
            pos = (len(buf) and (it % len(buf))) or 0
            bit = (it >> 5) & 7
            buf[pos] ^= (1 << bit)
            out = bytes(sanitize(buf))
        elif strat == 2:
            interesting = [0x00,0xFF,0x7F,0x80,0x20,0x0A,0x0D,0x09,0x41,0x61,0x2F,0x5C]
            buf = bytearray(s)
            pos = (len(buf) and (it % len(buf))) or 0
            buf[pos] = interesting[it % len(interesting)]
            out = bytes(sanitize(buf))
        elif strat == 3:
            buf = bytearray(s)
            win_len = min(max(2, (it % 7) + 2), max(1, len(buf)))
            start_max = max(1, len(buf) - win_len + 1)
            start = it % start_max
            delta = ((it & 3) - 1)
            for i in range(start, start + win_len):
                buf[i] = (buf[i] + delta) & 0xFF
            out = bytes(sanitize(buf))
        elif strat == 4:
            cap = min(len(s) + max(16, min(128, len(s) or 64)), len(s) + self.max_growth)
            base = s or b"A"
            rep = (cap + len(base) - 1) // len(base)
            buf = bytearray((base * rep)[:cap])
            if buf:
                pos = it % len(buf)
                buf[pos] = (buf[pos] ^ (it & 0x7F)) & 0xFF
            out = bytes(sanitize(buf))
        elif strat == 5 and self.tokens:
            tok = random.choice(self.tokens)
            pos = (len(s)+1) and (it % (len(s)+1))
            out = s[:pos] + tok + s[pos:]
        else:
            mid = len(s) // 2
            out = (s[:mid] + s[:mid-1:-1]) if s else b"A"

        target_len = _length_schedule(it, len(s), self.max_growth)
        if len(out) < target_len:
            out = (out + out[::-1] + b"A"*target_len)[:target_len]
        elif len(out) > target_len:
            head = target_len // 2
            tail = target_len - head
            out = out[:head] + out[-tail:]

        return bytes(out)

    # ---- delivery to running PID ----
    def _deliver_to_pid(self, payload: bytes) -> None:
        mode = self.mode

        if mode == "noop":
            print(f"[fuzz-pid] (noop) would deliver {len(payload)} bytes")
            return

        if mode == "file":
            stamp = now_stamp()
            out_path = os.path.join(self.drop_dir, f"payload_{stamp}.bin")
            to_write = with_file_template(payload, self.file_template)
            with open(out_path, "wb") as f:
                f.write(to_write)
            with open(out_path + ".meta.json", "w", encoding="utf-8") as mf:
                json.dump({"pid": self.pid, "bytes": len(to_write), "timestamp": stamp, "surface": self.surface}, mf, indent=2)
            print(f"[fuzz-pid] (file) wrote payload -> {out_path}")
            return

        if mode == "tcp":
            if not self.tcp_port:
                raise RuntimeError("FUZZ_PID_TCP_PORT not set or zero for tcp mode")
            addr = self.tcp_addr or "127.0.0.1"
            attempts = 3
            for i in range(attempts):
                try:
                    with socket.create_connection((addr, self.tcp_port), timeout=self.timeout) as sock:
                        sock.sendall(payload)
                        if os.environ.get("FUZZ_PID_TCP_APPEND_NL") == "1":
                            sock.sendall(b"\n")
                    print(f"[fuzz-pid] (tcp) sent {len(payload)} bytes to {addr}:{self.tcp_port}")
                    return
                except Exception:
                    if i == attempts - 1:
                        raise
                    time.sleep(0.05 * (i + 1))
            return

        if mode == "pipe":
            if not self.pipe_name:
                raise RuntimeError("FUZZ_PID_PIPE_NAME is required for pipe mode, e.g. \\\\.\\pipe\\MyPipe")
            wait_ms = int(float(os.environ.get("FUZZ_PID_PIPE_WAIT_MS", str(int(self.timeout * 1000)))) or 0)
            if wait_ms > 0:
                WaitNamedPipeW(self.pipe_name, wait_ms)
            h = CreateFileW(self.pipe_name, GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None)
            if int(h) == 0 or int(h) == INVALID_HANDLE_VALUE:
                _raise_last_error(f"CreateFileW on pipe failed: {self.pipe_name}")
            try:
                n_written = W.DWORD(0)
                ok = WriteFile(h, payload, len(payload), C.byref(n_written), None)
                if not ok or n_written.value != len(payload):
                    _raise_last_error(f"WriteFile to pipe incomplete: {n_written.value}/{len(payload)}")
                print(f"[fuzz-pid] (pipe) wrote {n_written.value} bytes to {self.pipe_name}")
            finally:
                CloseHandle(h)
            return

        raise ValueError(f"Unknown FUZZ_PID_MODE='{mode}' (expected noop|file|tcp|pipe)")

    # ---- incremental signal collection ----
    def _collect_signals(self) -> Tuple[Optional[int], bytes]:
        rc: Optional[int] = None
        log_path = self.monitor_log
        if not log_path:
            return rc, b""

        p = Path(log_path)
        if not p.exists() or not p.is_file():
            return rc, b""

        try:
            size = p.stat().st_size
            if self._log_pos > size:
                self._log_pos = 0
            with p.open("rb") as f:
                f.seek(self._log_pos, os.SEEK_SET)
                data = f.read()
                self._log_pos = f.tell()
        except Exception as e:
            print(f"[fuzz-pid] monitor read failed: {e}")
            data = b""

        time.sleep(min(0.02, max(0.0, self.timeout / 200.0)))
        return rc, data

    # ---- orchestrator ----
    def run(self, seeds: List[bytes], max_iters: int) -> None:
        try:
            if not seeds:
                print("[fuzz-pid] No seeds provided; nothing to do.")
                return

            print(f"[fuzz-pid] Skeleton started | pid={self.pid} | surface={self.surface} | iters={max_iters} | seeds={len(seeds)}")
            for si, seed in enumerate(seeds):
                print(f"[fuzz-pid] seed {si+1}/{len(seeds)} (len={len(seed)})")
                for it in range(max_iters):
                    try:
                        payload = self._mutate(seed, it)
                    except Exception as e:
                        print(f"[fuzz-pid] mutation error at iter {it}: {e}")
                        continue

                    try:
                        t0 = time.perf_counter()
                        self._deliver_to_pid(payload)
                        rc, stderr = self._collect_signals()
                        dt_ms = (time.perf_counter() - t0) * 1000.0
                        stdout = b""
                    except Exception as e:
                        print(f"[fuzz-pid] delivery error at iter {it}: {e}")
                        continue

                    # WER crashdump watcher
                    wer_new = self.wer.poll_new()
                    if wer_new:
                        print(f"[wer] new crash dumps detected: {len(wer_new)}")
                        stderr = (stderr or b"") + b"\nWER_CRASH_DUMP_DETECTED\n"

                    # token harvest
                    new_toks = harvest_tokens_from_stderr(stderr)
                    for t in new_toks:
                        if t not in self.tokens:
                            self.tokens.append(t)
                    if new_toks:
                        print(f"[dict] harvested {len(new_toks)} tokens from stderr (total {len(self.tokens)})")

                    # novelty -> corpus
                    if self.novelty.accept(rc=rc, dt_ms=dt_ms, stdout=stdout, stderr=stderr):
                        saved = self.corpus.save(payload, tag="novel")
                        if saved:
                            print(f"[corpus] novel behavior -> saved {saved}")

                    # heuristics
                    suspicious, h_reasons, h_score = self.hsig.update_and_score(
                        dt_ms=dt_ms, stderr_len=len(stderr or b""), rc=rc
                    )

                    # classification + promotion
                    is_overflow, indicators = self.classifier.classify(rc, stderr)
                    crashed = is_overflow
                    if not crashed and os.environ.get("FUZZ_PROMOTE_HEUR", "0") == "1" and suspicious:
                        crashed = True
                        indicators = (indicators or []) + [f"heur:{'+'.join(h_reasons)}"]

                    if not crashed:
                        continue

                    if self.crash_buckets.seen_before(rc, stderr):
                        print("[crash] duplicate bucket; skipping repro bundle")
                        continue

                    # minimization (heuristic in PID mode)
                    do_min = os.environ.get("FUZZ_MINIMIZE", "1") == "1"
                    min_ms = int(os.environ.get("FUZZ_MINIMIZE_BUDGET_MS", "1200"))
                    if do_min:
                        def pred(b: bytes) -> bool:
                            t0m = time.perf_counter()
                            try:
                                self._deliver_to_pid(b)
                            except Exception:
                                return False
                            rc2, se2 = self._collect_signals()
                            dt2 = (time.perf_counter() - t0m) * 1000.0
                            ok2, _ = self.classifier.classify(rc2, se2)
                            if ok2: return True
                            susp2, _r, _s = self.hsig.update_and_score(dt_ms=dt2, stderr_len=len(se2 or b""), rc=rc2)
                            return susp2
                        payload_min = minimize_payload(payload, pred, time_budget_ms=min_ms)
                        if len(payload_min) < len(payload):
                            print(f"[min] shrank payload {len(payload)} -> {len(payload_min)} bytes")
                            payload = payload_min

                    saved = self.corpus.save(payload, tag="crash")
                    if saved:
                        print(f"[crash] saved payload -> {saved}")

                    print("\n=== PROBABLE VULN (PID) ===")
                    print("Indicators:", ", ".join(indicators))
                    paths = self.repro.build_and_optionally_run(
                        target_path=self.target_path_for_repro,
                        surface=self.surface,
                        payload=payload,
                        timeout=self.timeout,
                        arg_index=self.arg_index,
                        env_overrides=self.env_overrides,
                        file_arg_index=self.file_arg_index,
                        run_after_write=True
                    )
                    print("[fuzz-pid] Repro bundle:", json.dumps(paths, indent=2))
                    print("[fuzz-pid] Stopping after first positive (skeleton behavior).")
                    return

            print("[fuzz-pid] Completed without detecting probable buffer overflows.")
        finally:
            self.close()

# ---------------- CLI ----------------
def parse_args():
    p = argparse.ArgumentParser(
        description="IAT snapshot + strict overflow classifier + repro generator + fuzz skeleton (+ PID skeleton)"
    )
    sub = p.add_subparsers(dest="cmd", required=False)

    # iat (default)
    pi = sub.add_parser("iat", help="Snapshot import table (IAT) of a running PID")
    pi.add_argument("pid", type=int, help="Target process PID")
    pi.add_argument("--all-modules", action="store_true",
                    help="Walk import tables for every loaded module (not just main EXE)")
    pi.add_argument("--dll-regex", default=None, help="Regex to include only matching DLLs (case-insensitive)")
    pi.add_argument("--func-regex", default=None, help="Regex to include only matching function names")
    pi.add_argument("--only-ordinal", action="store_true", help="Keep only imports by ordinal")
    pi.add_argument("--no-artifacts", action="store_true", help="Do not write JSON/CSV artifacts")
    pi.add_argument("--limit", type=int, default=50, help="Preview limit for stdout")

    # classify
    pc = sub.add_parser("classify", help="Strictly decide if a run indicates a probable buffer overflow")
    pc.add_argument("--rc", type=int, required=True, help="Process return code from the run")
    pc.add_argument("--stderr", required=True, help="Path to captured stderr file")

    # classify-repro
    pr = sub.add_parser("classify-repro", help="Classify overflow; if positive, emit reproducible script and payload")
    pr.add_argument("--rc", type=int, required=True, help="Process return code from the run")
    pr.add_argument("--stderr", required=True, help="Path to captured stderr file")
    pr.add_argument("--target", required=True, help="Target binary path for the reproducer")
    pr.add_argument("--surface", choices=["argv", "stdin", "env", "file"], required=True,
                    help="Surface used when the overflow occurred")
    pr.add_argument("--payload-bin", required=True, help="Path to the exact payload bytes that triggered the issue")
    pr.add_argument("--timeout", type=float, default=2.0, help="Timeout seconds for repro")
    pr.add_argument("--arg-index", type=int, default=None, help="argv index when surface=argv")
    pr.add_argument("--file-arg-index", type=int, default=None, help="argv index where file path is placed when surface=file")
    pr.add_argument("--env", action="append", default=[], help="ENV override KEY=VAL (repeatable)")
    pr.add_argument("--out-dir", default="crashes", help="Output directory for payload & repro")
    pr.add_argument("--no-rerun", action="store_true", help="Do not auto-execute the reproducer once")

    # fuzz-skeleton (spawn)
    pf = sub.add_parser("fuzz-skeleton", help="Spawned-process fuzzing skeleton")
    tgt = pf.add_mutually_exclusive_group(required=True)
    tgt.add_argument("--target", help="Path to target binary (for repro bundles)")
    tgt.add_argument("--target-pid", type=int, help="Resolve the EXE path from this running PID")
    pf.add_argument("--surface", choices=["auto", "argv", "stdin", "env", "file"], default="auto",
                    help="Surface to fuzz; 'auto' chooses argv (if possible, no NULs and --arg-index), else file (if --file-arg-index), else stdin")
    pf.add_argument("--timeout", type=float, default=2.0, help="Timeout seconds (used in repro bundles)")
    pf.add_argument("--arg-index", type=int, default=None, help="argv index when surface=argv")
    pf.add_argument("--file-arg-index", type=int, default=None, help="argv index where file path is placed when surface=file")
    pf.add_argument("--env", action="append", default=[], help="ENV override KEY=VAL (repeatable)")
    pf.add_argument("--out-dir", default="crashes", help="Where to write repro bundles")
    pf.add_argument("--seed-bin", action="append", default=[], help="Seed payload file (binary). Repeatable.")
    pf.add_argument("--seeds", default=None,
                    help="Import seeds from a file (.json|.jsonl|manifest) or a directory of .bin files")
    pf.add_argument("--max-iters", type=int, default=50, help="Iterations per seed (skeleton)")
    pf.add_argument("--ack-permission", action="store_true",
                    help="Acknowledges you have explicit permission to test this target (required)")

    # fuzz-skeleton-pid (attach; deliver via file/tcp/pipe)
    pfp = sub.add_parser("fuzz-skeleton-pid", help="PID fuzzing skeleton (attach to running process)")
    pfp.add_argument("--pid", type=int, required=True, help="Running process PID to target (read-only attach)")
    pfp.add_argument("--target", required=True, help="Path to target binary (only for building repro bundles)")
    pfp.add_argument("--surface", choices=["auto", "argv", "stdin", "env", "file"], default="auto",
                     help="Semantic surface for repro bundles; 'auto' prefers argv (if possible), else file (if --file-arg-index), else stdin")
    pfp.add_argument("--timeout", type=float, default=2.0, help="Timeout seconds (used in repro bundles)")
    pfp.add_argument("--arg-index", type=int, default=None, help="argv index when surface=argv (repro hint)")
    pfp.add_argument("--file-arg-index", type=int, default=None, help="argv index where file path is placed when surface=file (repro hint)")
    pfp.add_argument("--env", action="append", default=[], help="ENV override KEY=VAL (repro hint)")
    pfp.add_argument("--out-dir", default="crashes", help="Where to write repro bundles")
    pfp.add_argument("--seed-bin", action="append", default=[], help="Seed payload file (binary). Repeatable.")
    pfp.add_argument("--seeds", default=None,
                     help="Import seeds from a file (.json|.jsonl|manifest) or a directory of .bin files")
    pfp.add_argument("--max-iters", type=int, default=50, help="Iterations per seed (skeleton)")
    pfp.add_argument("--ack-permission", action="store_true",
                     help="Acknowledges you have explicit permission to test this running process (required)")
    pfp.add_argument("--no-auto-config", action="store_true",
                     help="Disable auto FUZZ_PID_* transport config derived from seed labels")

    return p.parse_args()

def _read_file_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def _env_list_to_dict(items: List[str]) -> Dict[str, str]:
    env = {}
    for p in items or []:
        if "=" not in p:
            raise ValueError(f"--env expects KEY=VALUE, got: {p}")
        k, v = p.split("=", 1)
        env[k] = v
    return env

def cmd_iat(args):
    loud_banner(f"IAT Snapshot for PID {args.pid}")
    insp = ProcessImportsInspector(args.pid)
    try:
        entries = (insp.enumerate_imports_all_modules()
                   if args.all_modules else
                   insp.enumerate_imports_main_only())

        if args.dll_regex or args.func_regex or args.only_ordinal:
            entries = filter_entries(entries, args.dll_regex, args.func_regex, args.only_ordinal)

        entries.sort(key=lambda e: (e["dll"].lower(), (e["func"] or f"ordinal#{e.get('ordinal',0)}").lower()))
        print_preview(entries, args.limit)

        if not args.no_artifacts:
            base = f"iat_{args.pid}_{now_stamp()}"
            paths = write_artifacts(base, entries)
            print(f"\n[+] Artifacts:")
            print(f"    JSON: {paths['json']}")
            print(f"    CSV : {paths['csv']}\n")
    finally:
        insp.close()

def cmd_classify(args):
    stderr = _read_file_bytes(args.stderr)
    clf = OverflowClassifier()
    verdict, indicators = clf.classify(args.rc, stderr)
    print(json.dumps({"probable_overflow": verdict, "indicators": indicators}, indent=2))

def cmd_classify_repro(args):
    stderr = _read_file_bytes(args.stderr)
    payload = _read_file_bytes(args.payload_bin)

    clf = OverflowClassifier()
    verdict, indicators = clf.classify(args.rc, stderr)
    print("[*] Indicators:", ", ".join(indicators) if indicators else "(none)")
    if not verdict:
        print("[!] Not classed as overflow; no repro emitted.")
        print(json.dumps({"probable_overflow": False, "indicators": indicators}, indent=2))
        return

    print("[+] Probable buffer overflow: generating reproducible script & payload bundle")
    builder = ReproScriptBuilder(out_dir=args.out_dir)
    paths = builder.build_and_optionally_run(
        target_path=args.target,
        surface=args.surface,
        payload=payload,
        timeout=args.timeout,
        arg_index=args.arg_index,
        env_overrides=_env_list_to_dict(args.env),
        file_arg_index=args.file_arg_index,
        run_after_write=not args.no_rerun
    )
    print(json.dumps({
        "probable_overflow": True,
        "indicators": indicators,
        "repro_paths": paths
    }, indent=2))

def _dedupe_bytes_with_labels(seeds: List[bytes], labels: List[str]) -> Tuple[List[bytes], List[str]]:
    if not seeds:
        return seeds, labels
    seen = set()
    uniq_b: List[bytes] = []
    uniq_l: List[str] = []
    for b, lab in zip(seeds, labels or [""] * len(seeds)):
        if b in seen:
            continue
        seen.add(b)
        uniq_b.append(b)
        uniq_l.append(lab)
    return uniq_b, uniq_l

def cmd_fuzz_skeleton(args):
    if not args.ack_permission:
        print("[!] Refusing to run: please supply --ack-permission ...")
        sys.exit(2)

    # Resolve target path if a PID was provided
    target_path = args.target
    if args.target_pid is not None:
        try:
            target_path = get_exe_path_from_pid(args.target_pid)
            print(f"[fuzz] Resolved PID {args.target_pid} -> {target_path}")
        except Exception as e:
            print(f"[!] Failed to resolve EXE path from PID {args.target_pid}: {e}")
            sys.exit(2)

    seeds: List[bytes] = []
    labels: List[str] = []
    if args.seeds:
        try:
            seeds, labels = load_seeds_any(args.seeds)
        except Exception as e:
            print(f"[fuzz] Failed unified seed load ({e}); falling back.")
            if args.seeds.lower().endswith(".jsonl"):
                seeds = load_seeds_from_jsonl(args.seeds)
            else:
                seeds = load_seeds_from_json(args.seeds)
    else:
        for sp in args.seed_bin or []:
            try:
                with open(sp, "rb") as f:
                    seeds.append(f.read())
            except Exception as e:
                print(f"[fuzz] Failed to read seed {sp}: {e}")

    if seeds:
        seeds, _ = _dedupe_bytes_with_labels(seeds, labels)

    if not os.path.isfile(target_path):
        print(f"[!] Target must be a PATH to an executable for fuzz-skeleton (got: {target_path})")
        sys.exit(2)

    if not seeds:
        print("[!] No seeds loaded.")

    skel = FuzzSkeleton(
        target_path=target_path,
        surface=args.surface,
        timeout=args.timeout,
        arg_index=args.arg_index,
        file_arg_index=args.file_arg_index,
        env_overrides=_env_list_to_dict(args.env),
        out_dir=args.out_dir
    )
    skel.run(seeds=seeds, max_iters=max(1, args.max_iters))

def cmd_fuzz_skeleton_pid(args):
    if not args.ack_permission:
        print("[!] Refusing to run: please supply --ack-permission ...")
        sys.exit(2)

    seeds: List[bytes] = []
    labels: List[str] = []
    if args.seeds:
        try:
            seeds, labels = load_seeds_any(args.seeds)
        except Exception as e:
            print(f"[fuzz-pid] Failed unified seed load ({e}); falling back.")
            if args.seeds.lower().endswith(".jsonl"):
                seeds = load_seeds_from_jsonl(args.seeds)
            else:
                seeds = load_seeds_from_json(args.seeds)
    else:
        for sp in args.seed_bin or []:
            try:
                with open(sp, "rb") as f:
                    seeds.append(f.read())
                    labels.append("")  # unknown
            except Exception as e:
                print(f"[fuzz-pid] Failed to read seed {sp}: {e}")

    if seeds:
        seeds, labels = _dedupe_bytes_with_labels(seeds, labels)

    if not seeds:
        print("[!] No seeds loaded.")
    else:
        by = {"tcp": 0, "pipe": 0, "generic": 0, "other": 0}
        for lab in labels:
            if isinstance(lab, str) and lab.startswith("tcp:"):
                by["tcp"] += 1
            elif isinstance(lab, str) and lab.startswith("pipe:"):
                by["pipe"] += 1
            elif lab == "generic":
                by["generic"] += 1
            else:
                by["other"] += 1
        print(f"[fuzz-pid] Seeds loaded: {len(seeds)}  (tcp={by['tcp']}, pipe={by['pipe']}, generic={by['generic']}, other={by['other']})")

    # Auto-configure transport from labels unless disabled
    if seeds and not getattr(args, "no_auto_config", False):
        maybe_autoconfig_transport_from_labels(labels)

    skel = FuzzSkeletonPID(
        pid=args.pid,
        target_path_for_repro=args.target,
        surface=args.surface,
        timeout=args.timeout,
        arg_index=args.arg_index,
        file_arg_index=args.file_arg_index,
        env_overrides=_env_list_to_dict(args.env),
        out_dir=args.out_dir
    )
    skel.run(seeds=seeds, max_iters=max(1, args.max_iters))

def main():
    args = parse_args()
    if args.cmd in (None, "iat"):
        if args.cmd is None:
            if len(sys.argv) == 1:
                print("usage: script.py iat <pid> [options]\n"
                      "       script.py classify ...\n"
                      "       script.py classify-repro ...\n"
                      "       script.py fuzz-skeleton ...\n"
                      "       script.py fuzz-skeleton-pid ...")
                sys.exit(2)
        cmd_iat(args)
    elif args.cmd == "classify":
        cmd_classify(args)
    elif args.cmd == "classify-repro":
        cmd_classify_repro(args)
    elif args.cmd == "fuzz-skeleton":
        cmd_fuzz_skeleton(args)
    elif args.cmd == "fuzz-skeleton-pid":
        cmd_fuzz_skeleton_pid(args)
    else:
        print(f"Unknown command: {args.cmd}")
        sys.exit(2)

if __name__ == "__main__":
    main()
