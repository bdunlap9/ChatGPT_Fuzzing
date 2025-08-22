#!/usr/bin/env python3
# Windows-only helper to build a "seed bin" based on a PID's observed IPC surfaces.
# - Detects TCP listeners for the PID (via psutil or netstat fallback)
# - Detects named pipes owned by the PID (via GetNamedPipeServerProcessId)
# - Auto-builds a per-PID DICTIONARY by extracting strings from the target's modules (disk + best-effort memory)
# - Generates deterministic, varied payloads per port/pipe, and synthesizes dictionary-based seeds
# - Emits a seeds/ directory tree + a seeds_manifest.json that maps seeds -> surfaces
# - Also emits import-ready files: seeds_import.json / seeds_import.jsonl
#
# Usage (example):
#   python seed_generator.py <PID> --out seeds --per-port 24 --per-pipe 24 --http-guess
#   (dictionary is auto-generated; see --no-dict to disable)
#
# Notes:
# - Pipe discovery is best-effort (no writes/injection).
# - Module strings extraction is read-only; memory reads are best-effort and limited.

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Iterable

# -------- optional psutil import --------
try:
    import psutil  # type: ignore
    HAVE_PSUTIL = True
except Exception:
    HAVE_PSUTIL = False

# ---- Win32 (named pipes + optional module list/memory read) ----
import ctypes as C
import ctypes.wintypes as W

kernel32 = C.WinDLL("kernel32", use_last_error=True)
psapi    = C.WinDLL("psapi",    use_last_error=True)

CreateFileW = kernel32.CreateFileW
CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE]
CreateFileW.restype  = W.HANDLE

WaitNamedPipeW = kernel32.WaitNamedPipeW
WaitNamedPipeW.argtypes = [W.LPCWSTR, W.DWORD]
WaitNamedPipeW.restype  = W.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [W.HANDLE]
CloseHandle.restype  = W.BOOL

GetNamedPipeServerProcessId = kernel32.GetNamedPipeServerProcessId
GetNamedPipeServerProcessId.argtypes = [W.HANDLE, C.POINTER(W.DWORD)]
GetNamedPipeServerProcessId.restype  = W.BOOL

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
OpenProcess.restype  = W.HANDLE

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [W.HANDLE, W.LPCVOID, W.LPVOID, C.c_size_t, C.POINTER(C.c_size_t)]
ReadProcessMemory.restype  = W.BOOL

EnumProcessModulesEx = psapi.EnumProcessModulesEx
EnumProcessModulesEx.argtypes = [W.HANDLE, C.POINTER(W.HMODULE), W.DWORD, C.POINTER(W.DWORD), W.DWORD]
EnumProcessModulesEx.restype  = W.BOOL

GetModuleFileNameExW = psapi.GetModuleFileNameExW
GetModuleFileNameExW.argtypes = [W.HANDLE, W.HMODULE, W.LPWSTR, W.DWORD]
GetModuleFileNameExW.restype  = W.DWORD

LIST_MODULES_ALL = 0x03

PROCESS_VM_READ                   = 0x0010
PROCESS_QUERY_INFORMATION         = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

GENERIC_READ  = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ  = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = C.c_void_p(-1).value

MAX_PATH = 260

# -------- utilities --------
def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def now_stamp() -> str:
    return time.strftime("%Y%m%d_%H%M%S") + f"_{int((time.time()%1)*1e6):06d}"

def xorshift32(x: int) -> int:
    x ^= (x << 13) & 0xFFFFFFFF
    x ^= (x >> 17) & 0xFFFFFFFF
    x ^= (x << 5)  & 0xFFFFFFFF
    return x & 0xFFFFFFFF

def rnd(state: int, mod: int) -> Tuple[int,int]:
    state = xorshift32(state)
    return (state % max(1, mod)), state

def interesting_bytes() -> List[int]:
    return [0x00,0xFF,0x7F,0x80,0x20,0x0A,0x0D,0x09,0x41,0x61,0x2F,0x5C]

def safe_name(name: str) -> str:
    # Directory-safe name for per-pipe buckets
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name)[:120] or "pipe"

# ===== TCP listener discovery =====
def discover_listeners_psutil(pid: int) -> List[int]:
    ports: List[int] = []
    for c in psutil.net_connections(kind="tcp"):
        if c.pid == pid and str(getattr(c, "status", "")).upper() == "LISTEN":
            laddr = getattr(c, "laddr", None)
            if laddr and hasattr(laddr, "port"):
                ports.append(int(laddr.port))
    return sorted(list(set(ports)))

def discover_listeners_netstat(pid: int) -> List[int]:
    try:
        out = subprocess.check_output(
            ["netstat", "-ano"],
            text=True, stderr=subprocess.DEVNULL,
            encoding="utf-8", errors="ignore"
        )
    except Exception:
        return []
    ports: List[int] = []
    for line in out.splitlines():
        if "LISTENING" not in line.upper():
            continue
        parts = re.split(r"\s+", line.strip())
        if len(parts) < 5:
            continue
        proto = parts[0].upper()
        laddr = parts[1]
        status = parts[3].upper()
        owner  = parts[4]
        if proto != "TCP" or status != "LISTENING":
            continue
        try:
            owner_pid = int(owner)
        except ValueError:
            continue
        if owner_pid != pid:
            continue
        m = re.search(r":(\d+)$", laddr)
        if m:
            ports.append(int(m.group(1)))
    return sorted(list(set(ports)))

def discover_tcp_listeners(pid: int) -> List[int]:
    if HAVE_PSUTIL:
        try:
            return discover_listeners_psutil(pid)
        except Exception:
            pass
    return discover_listeners_netstat(pid)

# ===== Named pipe enumeration =====
def list_all_named_pipes() -> List[str]:
    try:
        return [n for n in os.listdir(r"\\.\pipe\\") if n]
    except Exception:
        return []

def pipe_owned_by_pid(pipe_name: str, pid: int, wait_ms: int = 50) -> bool:
    """Best-effort: try to open the pipe and query its server PID."""
    path = r"\\.\pipe\{}".format(pipe_name)
    try:
        WaitNamedPipeW(path, wait_ms)
    except Exception:
        pass

    handle = CreateFileW(
        path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        0,
        None
    )
    if int(handle) == 0 or int(handle) == INVALID_HANDLE_VALUE:
        handle = CreateFileW(
            path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None
        )
        if int(handle) == 0 or int(handle) == INVALID_HANDLE_VALUE:
            return False

    try:
        out_pid = W.DWORD(0)
        ok = GetNamedPipeServerProcessId(handle, C.byref(out_pid))
        if not ok:
            return False
        return int(out_pid.value) == int(pid)
    finally:
        try:
            CloseHandle(handle)
        except Exception:
            pass

def discover_named_pipes_for_pid(pid: int, wait_ms: int = 50) -> List[str]:
    owned: List[str] = []
    for name in list_all_named_pipes():
        try:
            if pipe_owned_by_pid(name, pid, wait_ms):
                owned.append(name)
        except Exception:
            pass
    return sorted(set(owned))

# ===== Module discovery (for dictionary building) =====
def enum_modules_win32(pid: int) -> List[str]:
    """
    Return on-disk module paths for the PID (main exe + DLLs), best-effort without psutil.
    """
    access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    h = OpenProcess(access, False, pid)
    if not h:
        return []
    try:
        needed = W.DWORD(0)
        EnumProcessModulesEx(h, None, 0, C.byref(needed), LIST_MODULES_ALL)
        count = needed.value // C.sizeof(W.HMODULE)
        if count == 0:
            return []
        arr = (W.HMODULE * count)()
        if not EnumProcessModulesEx(h, arr, needed, C.byref(needed), LIST_MODULES_ALL):
            return []
        paths: List[str] = []
        for i in range(count):
            buf = C.create_unicode_buffer(MAX_PATH * 4)
            GetModuleFileNameExW(h, arr[i], buf, len(buf))
            if buf.value:
                paths.append(buf.value)
        return sorted(set(paths))
    finally:
        CloseHandle(h)

def module_paths_for_pid(pid: int) -> List[str]:
    if HAVE_PSUTIL:
        try:
            p = psutil.Process(pid)
            mods = set()
            # exe + memory_maps (backed files)
            if p.exe():
                mods.add(p.exe())
            for m in p.memory_maps():
                if getattr(m, "path", ""):
                    mods.add(m.path)
            return sorted(mods)
        except Exception:
            pass
    return enum_modules_win32(pid)

# ===== strings extraction & dictionary synthesis =====
_ASCII_RE = re.compile(rb"[ -~]{4,}")  # printable ASCII, len>=4
_UTF16LE_RE = re.compile(b"(?:[ -~]\x00){4,}")  # UTF-16LE printable, len>=4

def extract_strings_from_blob(blob: bytes, min_len: int, max_len: int) -> Iterable[str]:
    # ASCII
    for m in _ASCII_RE.finditer(blob):
        s = m.group(0)
        if len(s) >= min_len:
            yield s[:max_len].decode("ascii", "ignore")
    # UTF-16LE
    for m in _UTF16LE_RE.finditer(blob):
        s = m.group(0)
        try:
            t = s.decode("utf-16le", "ignore")
        except Exception:
            continue
        if len(t) >= min_len:
            yield t[:max_len]

def token_ok(t: str, min_len: int, max_len: int) -> bool:
    if not (min_len <= len(t) <= max_len):
        return False
    # trim obvious junk
    t = t.strip().strip("\x00")
    if not t:
        return False
    # reject mostly whitespace/control
    if not re.search(r"[A-Za-z0-9]", t):
        return False
    # avoid huge whitespace runs or single-char spam
    if len(set(t)) == 1 and len(t) > 3:
        return False
    # allow urls/paths/keys/headers/commands etc
    return True

def score_token(t: str) -> int:
    score = 0
    L = len(t)
    score += min(L, 64)  # length helps
    if re.search(r"[\\/:]", t): score += 8
    if re.search(r"^[A-Z_]{3,}$", t): score += 4
    if re.search(r"(?i)host|content|length|type|token|user|pass|auth|cmd|json", t): score += 6
    if re.search(r"^\w{3,20}$", t): score += 3
    if re.search(r"\.(json|xml|ini|cfg|conf|zip|log|tmp)$", t, re.I): score += 5
    if re.search(r"^[A-Za-z]{3,9}/[A-Za-z0-9.+-]{2,}$", t): score += 5  # MIME-ish
    return score

def read_small(path: str, cap: int = 8 * 1024 * 1024) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(cap)
    except Exception:
        return b""

def rpm_best_effort(hProc, base_addr: int, size: int, chunk: int = 0x20000, cap: int = 2 * 1024 * 1024) -> bytes:
    """
    Read up to 'cap' bytes from the start of a module mapping (best-effort).
    Avoids large scans; returns empty on failure.
    """
    buf = bytearray()
    read = C.c_size_t(0)
    remaining = min(size, cap)
    addr = base_addr
    tmp = (C.c_ubyte * chunk)()
    while remaining > 0:
        to_read = min(remaining, chunk)
        ok = ReadProcessMemory(hProc, C.c_void_p(addr), tmp, to_read, C.byref(read))
        if not ok or read.value == 0:
            break
        buf.extend(bytes(tmp[:read.value]))
        addr += read.value
        remaining -= read.value
        if read.value < to_read:
            break
    return bytes(buf)

def build_pid_dictionary(pid: int, min_len: int, max_len: int, max_tokens: int) -> Tuple[List[str], Dict]:
    """
    Collect tokens from (1) on-disk module images, (2) best-effort memory reads of modules.
    Returns (tokens_sorted, debug_meta)
    """
    paths = module_paths_for_pid(pid)
    tokens: Dict[str, int] = {}
    disk_hits = 0
    mem_hits  = 0

    # From disk
    for p in paths:
        blob = read_small(p)
        if not blob:
            continue
        for s in extract_strings_from_blob(blob, min_len, max_len):
            if token_ok(s, min_len, max_len):
                tokens[s] = tokens.get(s, 0) + 1
                disk_hits += 1

    # From memory (best-effort): read the first couple MB of the main module only
    # to stay swift and avoid excessive RPM. If psutil is present, we can try exe().
    h = None
    try:
        h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if h:
            # enumerate modules quickly to find the first one (main image)
            needed = W.DWORD(0)
            EnumProcessModulesEx(h, None, 0, C.byref(needed), LIST_MODULES_ALL)
            cnt = needed.value // C.sizeof(W.HMODULE)
            if cnt > 0:
                arr = (W.HMODULE * cnt)()
                if EnumProcessModulesEx(h, arr, needed, C.byref(needed), LIST_MODULES_ALL):
                    main_mod = arr[0]
                    # Try to read a capped slice from memory
                    blob = rpm_best_effort(h, C.addressof(main_mod), 8 * 1024 * 1024)
                    if blob:
                        for s in extract_strings_from_blob(blob, min_len, max_len):
                            if token_ok(s, min_len, max_len):
                                tokens[s] = tokens.get(s, 0) + 1
                                mem_hits += 1
    except Exception:
        pass
    finally:
        if h:
            CloseHandle(h)

    # Rank & trim
    ranked = sorted(tokens.items(), key=lambda kv: (score_token(kv[0]), kv[1]), reverse=True)
    ranked = [k for k, _ in ranked[:max_tokens]]

    meta = {
        "module_paths": paths,
        "num_paths": len(paths),
        "disk_string_hits": disk_hits,
        "mem_string_hits": mem_hits,
        "token_count": len(ranked),
    }
    return ranked, meta

# ===== seed generation =====
def sanitize(buf: bytearray, avoid: Optional[set]) -> bytearray:
    if not avoid:
        return buf
    st = 0xCAFEBABE
    for i,b in enumerate(buf):
        if b in avoid:
            idx, st = rnd(st, 256)
            rep = idx
            if rep in avoid:
                rep = (rep + 1) & 0xFF
                while rep in avoid:
                    rep = (rep + 1) & 0xFF
            buf[i] = rep
    return buf

def mutate(seed: bytes, iteration: int, max_growth: int, avoid: Optional[set]) -> bytes:
    """
    Deterministic, length-bounded mutations (aligned with PID fuzzer styles).
    """
    s = seed or b"A"
    it = max(0, int(iteration))
    seed_hash = ((len(s) & 0xFFFF) << 16) ^ (it & 0xFFFF) or 0xDEADBEEF
    strat = it % 6

    if strat == 0:
        return bytes(sanitize(bytearray(s), avoid))

    if strat == 1:
        buf = bytearray(s)
        pos, seed_hash = rnd(seed_hash, len(buf))
        bit, seed_hash = rnd(seed_hash, 8)
        buf[pos] ^= (1 << bit)
        return bytes(sanitize(buf, avoid))

    if strat == 2:
        ints = interesting_bytes()
        buf = bytearray(s)
        pos, seed_hash = rnd(seed_hash, len(buf))
        buf[pos] = ints[it % len(ints)]
        return bytes(sanitize(buf, avoid))

    if strat == 3:
        buf = bytearray(s)
        win_len = min(max(2, (it % 7) + 2), max(1, len(buf)))
        start_max = max(1, len(buf) - win_len + 1)
        start, seed_hash = rnd(seed_hash, start_max)
        delta = ((it & 3) - 1)  # -1,0,1,2
        for i in range(start, start + win_len):
            buf[i] = (buf[i] + delta) & 0xFF
        return bytes(sanitize(buf, avoid))

    if strat == 4:
        cap = min(len(s) + max(16, min(64, len(s) or 64)), len(s) + max_growth)
        base = s or b"A"
        rep = (cap + len(base) - 1) // len(base)
        buf = bytearray((base * rep)[:cap])
        if buf:
            pos, seed_hash = rnd(seed_hash, len(buf))
            buf[pos] = (buf[pos] ^ (it & 0x7F)) & 0xFF
        return bytes(sanitize(buf, avoid))

    mid = len(s) // 2
    out = (s[:mid] + s[:mid-1:-1]) if s else b"A"
    return bytes(sanitize(bytearray(out), avoid))

def canned_seeds(http_like: bool=False, line_oriented: bool=False) -> List[bytes]:
    seeds: List[bytes] = []
    if http_like:
        seeds += [
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            b"POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nAAAA",
            b"HEAD /aaaa HTTP/1.1\r\nHost: localhost\r\n\r\n",
        ]
    if line_oriented:
        seeds += [
            b"PING\n", b"STATUS\r\n", b"HELP\n",
            b"JSON {\"q\":\"test\"}\n",
            b"CMD AAAAAAAA\r\n",
        ]
    seeds += [
        b"A"*16, b"A"*64, b"A"*256,
        b"\x00"*16, b"\xff"*32,
        b"%x%x%x%n", b"{0}{1}{2}",
        ("𝔸" * 16).encode("utf-8"),
        b"\x01\x02\x7f\xff/\x5c..%$'\"\x00\x0a\x0d",
    ]
    body = b"B"*32
    seeds.append(len(body).to_bytes(2,"big")+body)  # simple length-prefixed
    return seeds

def synthesize_from_dict(tokens: List[str], http_like: bool=False, line_oriented: bool=False, cap: int=64) -> List[bytes]:
    """
    Turn top tokens into protocol-ish seeds (kept short, varied).
    """
    outs: List[bytes] = []
    def add(b: bytes):
        if len(outs) < cap:
            outs.append(b)

    for t in tokens:
        if len(outs) >= cap:
            break
        try:
            tb = t.encode("utf-8", "ignore")
        except Exception:
            continue

        # Paths / headers / keys / commands
        if http_like:
            add(b"GET /" + tb[:48] + b" HTTP/1.1\r\nHost: localhost\r\n\r\n")
            add(tb[:32] + b": A\r\n\r\n")
            add(b"POST /" + tb[:32] + b" HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nAAAA")
        elif line_oriented:
            add(tb[:64] + b"\r\n")
            add(b"CMD " + tb[:56] + b"\r\n")
            add(b"JSON {\"" + tb[:24] + b"\": \"AAAA\"}\n")
        else:
            # generic
            add(tb[:64])
            add(tb[:32] + b"=AAAA")
            add(b"/" + tb[:48])

    return outs

def write_seed_files(base_dir: Path, name_prefix: str, blobs: List[bytes]) -> List[Path]:
    ensure_dir(base_dir)
    written: List[Path] = []
    for i, b in enumerate(blobs):
        p = base_dir / f"{name_prefix}_{i:03d}.bin"
        p.write_bytes(b)
        written.append(p)
    return written

# -------- seed export helpers (for --seeds import) --------
def seed_record(path: Path, label: str) -> dict:
    data = path.read_bytes()
    return {
        "label": label,
        "path": str(path.as_posix()),
        "data_b64": base64.b64encode(data).decode("ascii"),
    }

def write_jsonl(records, out_path: Path):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def write_json(records, out_path: Path, meta: dict):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    blob = {"meta": meta, "seeds": records}
    out_path.write_text(json.dumps(blob, indent=2, ensure_ascii=False), encoding="utf-8")

# -------- main orchestration --------
def main():
    ap = argparse.ArgumentParser(description="Create dynamic seed bins for fuzzing based on a running PID (Windows).")
    ap.add_argument("pid", type=int, help="Target PID")
    ap.add_argument("--out", default="seeds", help="Output root directory")
    ap.add_argument("--per-port", type=int, default=16, help="Mutated seeds per discovered TCP port")
    ap.add_argument("--per-pipe", type=int, default=None, help="Mutated seeds per discovered named pipe (default: --per-port)")
    ap.add_argument("--max-grow", type=int, default=1024, help="Max growth per mutation")
    ap.add_argument("--avoid-hex", default="", help="Comma/space-separated hex bytes to avoid (e.g. '00,0a,0d')")
    ap.add_argument("--http-guess", action="store_true", help="If a port looks like HTTP (80/8080/8000/443/3000), add HTTP-ish seeds")
    ap.add_argument("--export-jsonl", default=None, help="(Optional) Also write a global JSONL outside pid folder.")
    ap.add_argument("--export-json",  default=None, help="(Optional) Also write a global JSON outside pid folder.")
    # Dictionary options
    ap.add_argument("--no-dict", action="store_true", help="Disable auto dictionary from PID modules")
    ap.add_argument("--dict-max", type=int, default=300, help="Max tokens to keep in dictionary")
    ap.add_argument("--dict-min-len", type=int, default=3, help="Min token length")
    ap.add_argument("--dict-max-len", type=int, default=64, help="Max token length")
    ap.add_argument("--dict-per-port", type=int, default=48, help="Dict-based seeds per TCP port (before mutation)")
    ap.add_argument("--dict-per-pipe", type=int, default=48, help="Dict-based seeds per named pipe (before mutation)")
    args = ap.parse_args()

    if os.name != "nt":
        print("[!] This helper is intended for Windows.")

    out_root = Path(args.out)
    ensure_dir(out_root)
    pid_root = out_root / f"pid_{args.pid}"
    ensure_dir(pid_root)

    # discover surfaces
    ports = discover_tcp_listeners(args.pid)
    pipes = discover_named_pipes_for_pid(args.pid, wait_ms=50)

    # parse avoid set
    avoid_set = {int(t, 16) & 0xFF for t in re.split(r"[,\s]+", args.avoid_hex) if t} if args.avoid_hex else set()

    # auto dictionary
    dict_tokens: List[str] = []
    dict_meta: Dict = {}
    if not args.no_dict:
        dict_tokens, dict_meta = build_pid_dictionary(
            args.pid, min_len=args.dict_min_len, max_len=args.dict_max_len, max_tokens=args.dict_max
        )
        # Save dictionary
        dict_path = pid_root / "dictionary.txt"
        with dict_path.open("w", encoding="utf-8") as f:
            for t in dict_tokens:
                f.write(t + "\n")
    else:
        dict_path = None

    manifest: Dict = {
        "pid": args.pid,
        "created_at": now_stamp(),
        "out_root": str(out_root.resolve()),
        "ports": [],
        "pipes": [],
        "generic": [],
        "notes": [
            "Seeds are deterministic across runs for the same (seed, iteration).",
            "Named pipes are discovered via GetNamedPipeServerProcessId (best-effort).",
            "HTTP-like seeds added if --http-guess and port is commonly HTTP.",
            "Dictionary auto-built from module strings unless --no-dict."
        ],
        "dictionary": {
            "path": str((pid_root / "dictionary.txt").resolve()) if not args.no_dict else None,
            "count": len(dict_tokens),
            "meta": dict_meta
        }
    }

    # Per-port seeds
    for port in ports:
        httpish = args.http_guess and port in (80, 8080, 8000, 443, 3000)
        bucket = pid_root / "tcp" / f"port_{port}"
        ensure_dir(bucket)

        base = canned_seeds(http_like=httpish, line_oriented=False)

        # Include dict-based synth seeds (if any)
        if dict_tokens:
            dict_seeds = synthesize_from_dict(dict_tokens, http_like=httpish, line_oriented=False, cap=args.dict_per_port)
            base = dict_seeds + base

        # Mutate deterministically up to per-port
        mutated: List[bytes] = []
        per = max(1, args.per_port)
        idx = 0
        while len(mutated) < per:
            s = base[idx % len(base)]
            it = idx
            mutated.append(mutate(s, it, args.max_grow, avoid_set))
            idx += 1

        paths = write_seed_files(bucket, f"tcp_{port}", mutated)
        manifest["ports"].append({
            "port": port,
            "surface": "tcp",
            "http_like": bool(httpish),
            "count": len(paths),
            "dir": str(bucket.resolve()),
            "seeds": [str(p.name) for p in paths],
        })

    # Per-pipe seeds (line-oriented defaults)
    per_pipe = args.per_pipe if args.per_pipe is not None else args.per_port
    for name in pipes:
        bucket = pid_root / "pipe" / safe_name(name)
        ensure_dir(bucket)
        base = canned_seeds(http_like=False, line_oriented=True)

        if dict_tokens:
            dict_seeds = synthesize_from_dict(dict_tokens, http_like=False, line_oriented=True, cap=args.dict_per_pipe)
            base = dict_seeds + base

        mutated: List[bytes] = []
        per = max(1, per_pipe)
        idx = 0
        while len(mutated) < per:
            s = base[idx % len(base)]
            it = idx
            mutated.append(mutate(s, it, args.max_grow, avoid_set))
            idx += 1

        paths = write_seed_files(bucket, f"pipe_{safe_name(name)}", mutated)
        manifest["pipes"].append({
            "name": name,
            "surface": "pipe",
            "count": len(paths),
            "dir": str(bucket.resolve()),
            "seeds": [str(p.name) for p in paths],
        })

    # Generic seeds for pipe/file/stdin surfaces
    generic_bucket = pid_root / "generic"
    ensure_dir(generic_bucket)
    gen_seeds = canned_seeds(http_like=False, line_oriented=True)
    if dict_tokens:
        gen_seeds = synthesize_from_dict(dict_tokens, http_like=False, line_oriented=True, cap=48) + gen_seeds
    extra = [mutate(gen_seeds[0], i, args.max_grow, avoid_set) for i in range(12)]
    gen_paths = write_seed_files(generic_bucket, "generic", gen_seeds + extra)
    manifest["generic"] = {
        "surface": ["pipe", "file", "stdin"],
        "dir": str(generic_bucket.resolve()),
        "count": len(gen_paths),
        "seeds": [p.name for p in gen_paths],
    }

    # Build import records
    records: List[dict] = []
    for port_info in manifest["ports"]:
        port_dir = Path(port_info["dir"])
        for name in port_info["seeds"]:
            records.append(seed_record(port_dir / name, f"tcp:{port_info['port']}"))
    for pipe_info in manifest["pipes"]:
        pipe_dir = Path(pipe_info["dir"])
        for name in pipe_info["seeds"]:
            records.append(seed_record(pipe_dir / name, f"pipe:{pipe_info['name']}"))
    gen_dir = Path(manifest["generic"]["dir"])
    for name in manifest["generic"]["seeds"]:
        records.append(seed_record(gen_dir / name, "generic"))

    meta = {
        "pid": args.pid,
        "created_at": manifest["created_at"],
        "note": "base64-encoded seeds; 'label' hints surface (tcp:<port> / pipe:<name> / generic)"
    }

    # Write import-ready files into pid folder
    import_json_path  = pid_root / "seeds_import.json"
    import_jsonl_path = pid_root / "seeds_import.jsonl"
    write_json(records, import_json_path, meta)
    write_jsonl(records, import_jsonl_path)

    # Pack them into the manifest too (so manifest itself is importable by your fuzzer)
    manifest["seeds"] = records
    manifest["imports_file_json"]  = str(import_json_path.resolve())
    manifest["imports_file_jsonl"] = str(import_jsonl_path.resolve())

    # Write manifest
    manifest_path = pid_root / "seeds_manifest.json"
    ensure_dir(manifest_path.parent)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    # Optional global exports
    if args.export_jsonl:
        write_jsonl(records, Path(args.export_jsonl))
    if args.export_json:
        write_json(records, Path(args.export_json), meta)

    # Summary
    print("\n[+] Seed bin created")
    print(f"    PID: {args.pid}")
    print(f"    Root: {out_root.resolve()}")
    if ports:
        print(f"    TCP listeners discovered: {', '.join(map(str, ports))}")
    else:
        print("    TCP listeners discovered: (none)")
    if pipes:
        print(f"    Named pipes discovered: {', '.join(pipes)}")
    else:
        print("    Named pipes discovered: (none)")
    print(f"    Dictionary: {manifest['dictionary']['path']} (tokens={manifest['dictionary']['count']})")
    print(f"    Manifest: {manifest_path.resolve()}")
    print(f"    Import JSON : {import_json_path.resolve()}")
    print(f"    Import JSONL: {import_jsonl_path.resolve()}")
    print("    You can pass ANY of the above three files to pid_fuzzer via --seeds.\n")

if __name__ == "__main__":
    main()
