#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Async Seed Bin Builder (Windows)
--------------------------------
Reorganized version of your seed generator into a single asyncio-oriented
class with clear methods and Windows-specific helpers. Supports two modes:
  - PID mode (discover TCP listeners, named pipes, build dictionary from
    process modules / main image bytes best-effort)
  - File mode (build dictionary & file-derived seeds from a given binary)

Outputs a structured seed bin directory with:
  - Per-port TCP seed folders
  - Per-pipe seed folders
  - Generic seeds (stdin/pipe/file surfaces)
  - Optional file-type seeds (json/xml/png/zip/bmp/wav/txt)
  - Import-ready JSON and JSONL files (base64 payloads + labels)
  - Dictionary file (strings extracted from disk + main module memory)
  - Manifest JSON with metadata

Python: 3.9+
OS: Windows (named pipe / process APIs); still runs on non-Windows but will
     skip pipe/process-specific bits.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

# -------- optional psutil import --------
try:
    import psutil  # type: ignore
    HAVE_PSUTIL = True
except Exception:
    HAVE_PSUTIL = False

IS_WINDOWS = (os.name == "nt")

# ---- Win32 (named pipes + module list/memory read) ----
if IS_WINDOWS:
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

    class MODULEINFO(C.Structure):
        _fields_ = [("lpBaseOfDll", W.LPVOID),
                    ("SizeOfImage", W.DWORD),
                    ("EntryPoint", W.LPVOID)]

    GetModuleInformation = psapi.GetModuleInformation
    GetModuleInformation.argtypes = [W.HANDLE, W.HMODULE, C.POINTER(MODULEINFO), W.DWORD]
    GetModuleInformation.restype  = W.BOOL

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


def rnd(state: int, mod: int) -> Tuple[int, int]:
    state = xorshift32(state)
    return (state % max(1, mod)), state


def interesting_bytes() -> List[int]:
    return [0x00, 0xFF, 0x7F, 0x80, 0x20, 0x0A, 0x0D, 0x09, 0x41, 0x61, 0x2F, 0x5C]


def safe_name(name: str) -> str:
    # Directory-safe name for per-pipe buckets
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name)[:120] or "pipe"


# ===== strings extraction & dictionary synthesis =====
_ASCII_RE = re.compile(rb"[ -~]{4,}")
_UTF16LE_RE = re.compile(b"(?:[ -~]\x00){4,}")


def extract_strings_from_blob(blob: bytes, min_len: int, max_len: int) -> Iterable[str]:
    for m in _ASCII_RE.finditer(blob):
        s = m.group(0)
        if len(s) >= min_len:
            yield s[:max_len].decode("ascii", "ignore")
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
    t = t.strip().strip("\x00")
    if not t:
        return False
    if not re.search(r"[A-Za-z0-9]", t):
        return False
    if len(set(t)) == 1 and len(t) > 3:
        return False
    return True


def score_token(t: str) -> int:
    score = 0
    L = len(t)
    score += min(L, 64)
    if re.search(r"[\\/:]", t):
        score += 8
    if re.search(r"^[A-Z_]{3,}$", t):
        score += 4
    if re.search(r"(?i)host|content|length|type|token|user|pass|auth|cmd|json", t):
        score += 6
    if re.search(r"^\w{3,20}$", t):
        score += 3
    if re.search(r"\.(json|xml|ini|cfg|conf|zip|log|tmp)$", t, re.I):
        score += 5
    if re.search(r"^[A-Za-z]{3,9}/[A-Za-z0-9.+-]{2,}$", t):
        score += 5
    return score


def read_small(path: str, cap: int = 8 * 1024 * 1024) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(cap)
    except Exception:
        return b""


# ----- NEW: file templates (wrap raw payload into real-ish file formats) -----

def with_file_template(payload: bytes, kind: str) -> bytes:
    k = (kind or "").lower()
    if k == "png":
        return (b"\x89PNG\r\n\x1a\n"
                b"\x00\x00\x00\rIHDR" + b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00" +
                b"\x90wS\xde" +
                b"\x00\x00\x00\x08IDAT" + payload[:1024] +
                b"\x00\x00\x00\x00IEND\xaeB`\x82")
    if k == "zip":
        return b"PK\x03\x04" + payload[:2048]
    if k == "json":
        try:
            s = payload.decode("latin-1", "ignore")
        except Exception:
            s = str(payload)
        return ("{\"data\":\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")[:4000] + "\"}").encode("utf-8", "ignore")
    if k == "xml":
        return (b"<?xml version='1.0'?>\n<data>" + payload[:4000] + b"</data>")
    if k == "bmp":
        body = payload[:4096]
        header = b"BM" + (14 + 40 + len(body)).to_bytes(4, "little") + b"\x00\x00\x00\x00" + (14 + 40).to_bytes(4, "little")
        dib = (40).to_bytes(4, "little") + (1).to_bytes(4, "little") + (1).to_bytes(4, "little") + (1).to_bytes(2, "little") + (24).to_bytes(2, "little") + (0).to_bytes(4, "little") + len(body).to_bytes(4, "little") + (2835).to_bytes(4, "little") * 2 + (0).to_bytes(4, "little") * 2
        return header + dib + body
    if k == "wav":
        body = payload[:4096]
        return b"RIFF" + (36 + len(body)).to_bytes(4, "little") + b"WAVEfmt " + (16).to_bytes(4, "little") + (1).to_bytes(2, "little") + (1).to_bytes(2, "little") + (8000).to_bytes(4, "little") + (8000).to_bytes(4, "little") + (1).to_bytes(2, "little") + (8).to_bytes(2, "little") + b"data" + len(body).to_bytes(4, "little") + body
    if k == "txt":
        return payload.replace(b"\x00", b"?")
    return payload  # raw/bin


_FILE_EXT = {
    "json": ".json", "xml": ".xml", "png": ".png", "zip": ".zip",
    "bmp": ".bmp", "wav": ".wav", "txt": ".txt", "bin": ".bin", "raw": ".bin"
}


def parse_file_types(s: Optional[str]) -> List[str]:
    if not s:
        return []
    raw = re.split(r"[,\s]+", s.strip())
    out: List[str] = []
    for t in raw:
        t = t.strip().lower()
        if not t:
            continue
        if t in _FILE_EXT:
            out.append(t)
    seen = set(); ordered = []
    for t in out:
        if t in seen:
            continue
        seen.add(t)
        ordered.append(t)
    return ordered


# -------- seed export helpers (for --seeds import) --------

def seed_record(path: Path, label: str) -> dict:
    data = path.read_bytes()
    return {
        "label": label,
        "path": str(path.as_posix()),
        "data_b64": base64.b64encode(data).decode("ascii"),
    }


async def write_jsonl(records, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records)
    await asyncio.to_thread(out_path.write_text, text, encoding="utf-8")


async def write_json(records, out_path: Path, meta: dict) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    blob = {"meta": meta, "seeds": records}
    data = json.dumps(blob, indent=2, ensure_ascii=False)
    await asyncio.to_thread(out_path.write_text, data, encoding="utf-8")


# ===== mutation + canned/synth seeds =====

def sanitize(buf: bytearray, avoid: Optional[set]) -> bytearray:
    if not avoid:
        return buf
    st = 0xCAFEBABE
    for i, b in enumerate(buf):
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
        delta = ((it & 3) - 1)
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


def canned_seeds(http_like: bool = False, line_oriented: bool = False, avoid: Optional[set] = None) -> List[bytes]:
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
        b"A" * 16, b"A" * 64, b"A" * 256,
        b"\xff" * 32,
        b"%x%x%x%n", b"{0}{1}{2}",
        ("𝔸" * 16).encode("utf-8"),
        b"\x01\x02\x7f\xff/\x5c..%$'\"\x0d",  # <-- intentionally removed 00 & 0a
    ]
    body = b"B" * 32
    seeds.append(len(body).to_bytes(2, "big") + body)

    if avoid:
        seeds = [bytes(sanitize(bytearray(s), avoid)) for s in seeds]

    return seeds


def synthesize_from_dict(tokens: List[str], http_like: bool = False, line_oriented: bool = False, cap: int = 64) -> List[bytes]:
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

        if http_like:
            add(b"GET /" + tb[:48] + b" HTTP/1.1\r\nHost: localhost\r\n\r\n")
            add(tb[:32] + b": A\r\n\r\n")
            add(b"POST /" + tb[:32] + b" HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nAAAA")
        elif line_oriented:
            add(tb[:64] + b"\r\n")
            add(b"CMD " + tb[:56] + b"\r\n")
            add(b"JSON {\"" + tb[:24] + b"\": \"AAAA\"}\n")
        else:
            add(tb[:64])
            add(tb[:32] + b"=AAAA")
            add(b"/" + tb[:48])

    return outs


class AsyncSeedBinBuilder:
    def __init__(self, *,
                 pid: Optional[int],
                 file_path: Optional[str],
                 out_dir: str,
                 per_port: int = 16,
                 per_pipe: Optional[int] = None,
                 max_grow: int = 1024,
                 avoid_hex: str = "",
                 http_guess: bool = False,
                 export_jsonl: Optional[str] = None,
                 export_json: Optional[str] = None,
                 no_dict: bool = False,
                 dict_max: int = 300,
                 dict_min_len: int = 3,
                 dict_max_len: int = 64,
                 dict_per_port: int = 48,
                 dict_per_pipe: int = 48,
                 file_types: str = "",
                 per_file_type: int = 24,
                 emit_pretty_ext: bool = False):
        self.pid = pid
        self.file_path = file_path
        self.is_pid_mode = pid is not None
        self.root_label = f"pid_{pid}" if self.is_pid_mode else f"file_{Path(file_path).stem}"
        self.out_root = Path(out_dir)
        self.per_port = per_port
        self.per_pipe = per_port if per_pipe is None else per_pipe
        self.max_grow = max_grow
        self.avoid_set = {int(t, 16) & 0xFF for t in re.split(r"[ ,]+", avoid_hex) if t} if avoid_hex else set()
        self.http_guess = http_guess
        self.export_jsonl = export_jsonl
        self.export_json = export_json
        self.no_dict = no_dict
        self.dict_max = dict_max
        self.dict_min_len = dict_min_len
        self.dict_max_len = dict_max_len
        self.dict_per_port = dict_per_port
        self.dict_per_pipe = dict_per_pipe
        self.file_types = parse_file_types(file_types)
        self.per_file_type = per_file_type
        self.emit_pretty_ext = emit_pretty_ext

        ensure_dir(self.out_root)
        self.root = self.out_root / self.root_label
        ensure_dir(self.root)

        self.manifest: Dict = {
            "mode": "pid" if self.is_pid_mode else "file",
            "pid": self.pid if self.is_pid_mode else None,
            "target_file": os.path.abspath(self.file_path) if not self.is_pid_mode and self.file_path else None,
            "created_at": now_stamp(),
            "out_root": str(self.out_root.resolve()),
            "ports": [],
            "pipes": [],
            "generic": [],
            "files": [],
            "notes": [
                "Seeds are deterministic across runs for the same (seed, iteration).",
                "Named pipes are discovered via GetNamedPipeServerProcessId (best-effort).",
                "HTTP-like seeds added if --http-guess and port is commonly HTTP.",
                "Dictionary auto-built from module strings unless --no-dict.",
                "File seeds are actual file bytes; avoid setting FUZZ_FILE_TEMPLATE simultaneously to prevent double-wrapping."
            ],
            "dictionary": {
                "path": None,
                "count": 0,
                "meta": {}
            }
        }

    # ===== discovery =====
    async def discover_tcp_listeners(self, pid: int) -> List[int]:
        if HAVE_PSUTIL:
            try:
                def _ps():
                    ports: List[int] = []
                    for c in psutil.net_connections(kind="tcp"):
                        if c.pid == pid and str(getattr(c, "status", "")).upper() == "LISTEN":
                            laddr = getattr(c, "laddr", None)
                            if laddr and hasattr(laddr, "port"):
                                ports.append(int(laddr.port))
                    return sorted(set(ports))
                return await asyncio.to_thread(_ps)
            except Exception:
                pass
        # netstat fallback
        def _netstat() -> List[int]:
            try:
                out = subprocess.check_output(["netstat", "-ano"], text=True, stderr=subprocess.DEVNULL, encoding="utf-8", errors="ignore")
            except Exception:
                return []
            ports: List[int] = []
            for line in out.splitlines():
                if "LISTEN" not in line.upper() and "LISTENING" not in line.upper():
                    continue
                parts = re.split(r"\s+", line.strip())
                if len(parts) < 4:
                    continue
                proto = parts[0].upper()
                if proto != "TCP":
                    continue
                laddr = parts[1]
                owner = parts[-1]
                try:
                    owner_pid = int(owner)
                except ValueError:
                    continue
                if owner_pid != pid:
                    continue
                m = re.search(r":(\d+)$", laddr)
                if m:
                    ports.append(int(m.group(1)))
            return sorted(set(ports))
        return await asyncio.to_thread(_netstat)

    async def list_all_named_pipes(self) -> List[str]:
        if not IS_WINDOWS:
            return []
        def _lst():
            try:
                return [n for n in os.listdir(r"\\.\pipe\\") if n]
            except Exception:
                return []
        return await asyncio.to_thread(_lst)

    async def pipe_owned_by_pid(self, pipe_name: str, pid: int, wait_ms: int = 50) -> bool:
        if not IS_WINDOWS:
            return False
        path = r"\\.\pipe\{}".format(pipe_name)
        def _check() -> bool:
            try:
                WaitNamedPipeW(path, wait_ms)
            except Exception:
                pass
            handle = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None)
            if int(handle) == 0 or int(handle) == INVALID_HANDLE_VALUE:
                handle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None)
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
        return await asyncio.to_thread(_check)

    async def discover_named_pipes_for_pid(self, pid: int, wait_ms: int = 50) -> List[str]:
        names = await self.list_all_named_pipes()
        owned: List[str] = []
        sem = asyncio.Semaphore(32)
        async def _probe(name: str):
            async with sem:
                try:
                    if await self.pipe_owned_by_pid(name, pid, wait_ms):
                        owned.append(name)
                except Exception:
                    return
        await asyncio.gather(*(_probe(n) for n in names))
        return sorted(set(owned))

    # ===== dictionary =====
    async def module_paths_for_pid(self, pid: int) -> List[str]:
        if HAVE_PSUTIL:
            def _ps_paths() -> List[str]:
                try:
                    p = psutil.Process(pid)
                    mods = set()
                    if p.exe():
                        mods.add(p.exe())
                    for m in p.memory_maps():
                        if getattr(m, "path", ""):
                            mods.add(m.path)
                    return sorted(mods)
                except Exception:
                    return []
            return await asyncio.to_thread(_ps_paths)
        if not IS_WINDOWS:
            return []
        def _win_paths() -> List[str]:
            try:
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
            except Exception:
                return []
        return await asyncio.to_thread(_win_paths)

    async def rpm_best_effort(self, hProc, base_addr: int, size: int, chunk: int = 0x20000, cap: int = 2 * 1024 * 1024) -> bytes:
        if not IS_WINDOWS:
            return b""
        def _read() -> bytes:
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
        return await asyncio.to_thread(_read)

    async def build_pid_dictionary(self, pid: int, min_len: int, max_len: int, max_tokens: int) -> Tuple[List[str], Dict]:
        if not IS_WINDOWS:
            return [], {"warning": "Windows-only dictionary (PID) not available on this OS."}
        paths = await self.module_paths_for_pid(pid)
        tokens: Dict[str, int] = {}
        disk_hits = 0
        mem_hits = 0
        # disk-backed modules
        for p in paths:
            blob = await asyncio.to_thread(read_small, p)
            if not blob:
                continue
            for s in extract_strings_from_blob(blob, min_len, max_len):
                if token_ok(s, min_len, max_len):
                    tokens[s] = tokens.get(s, 0) + 1
                    disk_hits += 1
        # main module memory slice
        def _read_main_image() -> bytes:
            h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
            if not h:
                return b""
            try:
                needed = W.DWORD(0)
                EnumProcessModulesEx(h, None, 0, C.byref(needed), LIST_MODULES_ALL)
                cnt = needed.value // C.sizeof(W.HMODULE)
                if cnt == 0:
                    return b""
                arr = (W.HMODULE * cnt)()
                if not EnumProcessModulesEx(h, arr, needed, C.byref(needed), LIST_MODULES_ALL):
                    return b""
                mi = MODULEINFO()
                if not GetModuleInformation(h, arr[0], C.byref(mi), C.sizeof(mi)):
                    return b""
                base = C.cast(mi.lpBaseOfDll, W.LPVOID).value
                size = int(mi.SizeOfImage)
                if not base or size <= 0:
                    return b""
                # read outside of to_thread? keep it here
                buf = bytearray()
                read = C.c_size_t(0)
                remaining = min(size, 2 * 1024 * 1024)
                addr = base
                tmp = (C.c_ubyte * 0x20000)()
                while remaining > 0:
                    to_read = min(remaining, 0x20000)
                    ok = ReadProcessMemory(h, C.c_void_p(addr), tmp, to_read, C.byref(read))
                    if not ok or read.value == 0:
                        break
                    buf.extend(bytes(tmp[:read.value]))
                    addr += read.value
                    remaining -= read.value
                    if read.value < to_read:
                        break
                return bytes(buf)
            finally:
                try:
                    CloseHandle(h)
                except Exception:
                    pass
        blob = await asyncio.to_thread(_read_main_image)
        if blob:
            for s in extract_strings_from_blob(blob, min_len, max_len):
                if token_ok(s, min_len, max_len):
                    tokens[s] = tokens.get(s, 0) + 1
                    mem_hits += 1
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

    async def build_file_dictionary(self, path: str, min_len: int, max_len: int, max_tokens: int) -> Tuple[List[str], Dict]:
        blob = await asyncio.to_thread(read_small, path)
        tokens: Dict[str, int] = {}
        disk_hits = 0
        for s in extract_strings_from_blob(blob, min_len, max_len):
            if token_ok(s, min_len, max_len):
                tokens[s] = tokens.get(s, 0) + 1
                disk_hits += 1
        ranked = sorted(tokens.items(), key=lambda kv: (score_token(kv[0]), kv[1]), reverse=True)
        ranked = [k for k, _ in ranked[:max_tokens]]
        return ranked, {"target_file": os.path.abspath(path), "disk_string_hits": disk_hits, "token_count": len(ranked)}

    # ===== write helpers =====
    async def write_seed_files(self, base_dir: Path, name_prefix: str, blobs: List[bytes], ext: str = ".bin") -> List[Path]:
        ensure_dir(base_dir)
        written: List[Path] = []
        for i, b in enumerate(blobs):
            p = base_dir / f"{name_prefix}_{i:03d}{ext}"
            await asyncio.to_thread(p.write_bytes, b)
            written.append(p)
        return written

    # ===== orchestration =====
    async def run(self) -> None:
        # discovery
        ports: List[int] = []
        pipes: List[str] = []
        if self.is_pid_mode and IS_WINDOWS:
            ports = await self.discover_tcp_listeners(self.pid)  # type: ignore[arg-type]
            pipes = await self.discover_named_pipes_for_pid(self.pid)  # type: ignore[arg-type]

        # dictionary
        dict_tokens: List[str] = []
        dict_meta: Dict = {}
        if not self.no_dict:
            if self.is_pid_mode and self.pid is not None:
                dict_tokens, dict_meta = await self.build_pid_dictionary(self.pid, self.dict_min_len, self.dict_max_len, self.dict_max)
            elif self.file_path:
                dict_tokens, dict_meta = await self.build_file_dictionary(self.file_path, self.dict_min_len, self.dict_max_len, self.dict_max)
            dict_path = self.root / "dictionary.txt"
            await asyncio.to_thread(
                dict_path.write_text,
                "".join(t + "\n" for t in dict_tokens),
                "utf-8",
            )
            self.manifest["dictionary"]["path"] = str(dict_path.resolve())
            self.manifest["dictionary"]["count"] = len(dict_tokens)
            self.manifest["dictionary"]["meta"] = dict_meta

        # per-port seeds
        for port in ports:
            httpish = self.http_guess and port in (80, 8080, 8000, 443, 3000)
            bucket = self.root / "tcp" / f"port_{port}"
            ensure_dir(bucket)
            base = canned_seeds(http_like=httpish, line_oriented=False)
            if dict_tokens:
                dict_seeds = synthesize_from_dict(dict_tokens, http_like=httpish, line_oriented=False, cap=self.dict_per_port)
                base = dict_seeds + base
            mutated: List[bytes] = []
            per = max(1, self.per_port)
            idx = 0
            while len(mutated) < per:
                s = base[idx % len(base)]
                it = idx
                mutated.append(mutate(s, it, self.max_grow, self.avoid_set))
                idx += 1
            paths = await self.write_seed_files(bucket, f"tcp_{port}", mutated, ext=".bin")
            self.manifest["ports"].append({
                "port": port,
                "surface": "tcp",
                "http_like": bool(httpish),
                "count": len(paths),
                "dir": str(bucket.resolve()),
                "seeds": [str(p.name) for p in paths],
            })

        # per-pipe seeds
        for name in pipes:
            bucket = self.root / "pipe" / safe_name(name)
            ensure_dir(bucket)
            base = canned_seeds(http_like=False, line_oriented=True)
            if dict_tokens:
                dict_seeds = synthesize_from_dict(dict_tokens, http_like=False, line_oriented=True, cap=self.dict_per_pipe)
                base = dict_seeds + base
            mutated: List[bytes] = []
            per = max(1, self.per_pipe)
            idx = 0
            while len(mutated) < per:
                s = base[idx % len(base)]
                it = idx
                mutated.append(mutate(s, it, self.max_grow, self.avoid_set))
                idx += 1
            paths = await self.write_seed_files(bucket, f"pipe_{safe_name(name)}", mutated, ext=".bin")
            self.manifest["pipes"].append({
                "name": name,
                "surface": "pipe",
                "count": len(paths),
                "dir": str(bucket.resolve()),
                "seeds": [str(p.name) for p in paths],
            })

        # generic seeds
        generic_bucket = self.root / "generic"
        ensure_dir(generic_bucket)
        gen_seeds = canned_seeds(http_like=False, line_oriented=True)
        if dict_tokens:
            gen_seeds = synthesize_from_dict(dict_tokens, http_like=False, line_oriented=True, cap=48) + gen_seeds
        extra = [mutate(gen_seeds[0], i, self.max_grow, self.avoid_set) for i in range(12)]
        gen_paths = await self.write_seed_files(generic_bucket, "generic", gen_seeds + extra, ext=".bin")
        self.manifest["generic"] = {
            "surface": ["pipe", "file", "stdin"],
            "dir": str(generic_bucket.resolve()),
            "count": len(gen_paths),
            "seeds": [p.name for p in gen_paths],
        }

        # file-type seeds
        file_records_meta = []
        for ftype in self.file_types:
            base = canned_seeds(http_like=False, line_oriented=False)
            if dict_tokens:
                base = synthesize_from_dict(dict_tokens, http_like=False, line_oriented=False, cap=max(1, self.per_file_type)) + base
            mutated_raw: List[bytes] = []
            per = max(1, self.per_file_type)
            idx = 0
            while len(mutated_raw) < per:
                s = base[idx % len(base)]
                it = idx
                mutated_raw.append(mutate(s, it, self.max_grow, self.avoid_set))
                idx += 1
            wrapped = [with_file_template(b, ftype) for b in mutated_raw]
            ftype_dir = self.root / "file" / ftype
            ensure_dir(ftype_dir)
            bin_paths = await self.write_seed_files(ftype_dir, f"file_{ftype}", wrapped, ext=".bin")
            pretty_paths: List[Path] = []
            if self.emit_pretty_ext:
                ext = _FILE_EXT.get(ftype, ".bin")
                pretty_paths = await self.write_seed_files(ftype_dir, f"pretty_{ftype}", wrapped, ext=ext)
            self.manifest["files"].append({
                "type": ftype,
                "dir": str(ftype_dir.resolve()),
                "count": len(wrapped),
                "bin_seeds": [p.name for p in bin_paths],
                "pretty_ext_written": bool(pretty_paths),
                "pretty_ext_list": [p.name for p in pretty_paths],
            })

        # build import records
        records: List[dict] = []
        for port_info in self.manifest["ports"]:
            port_dir = Path(port_info["dir"])  # type: ignore[index]
            for name in port_info["seeds"]:   # type: ignore[index]
                records.append(seed_record(port_dir / name, f"tcp:{port_info['port']}"))
        for pipe_info in self.manifest["pipes"]:
            pipe_dir = Path(pipe_info["dir"])  # type: ignore[index]
            for name in pipe_info["seeds"]:   # type: ignore[index]
                records.append(seed_record(pipe_dir / name, f"pipe:{pipe_info['name']}"))
        gen_dir = Path(self.manifest["generic"]["dir"])  # type: ignore[index]
        for name in self.manifest["generic"]["seeds"]:  # type: ignore[index]
            records.append(seed_record(gen_dir / name, "generic"))
        for fentry in self.manifest["files"]:
            fdir = Path(fentry["dir"])  # type: ignore[index]
            for name in fentry["bin_seeds"]:  # type: ignore[index]
                records.append(seed_record(fdir / name, f"file:{fentry['type']}"))

        meta = {
            "pid": self.pid if self.is_pid_mode else None,
            "target_file": self.manifest.get("target_file"),
            "created_at": self.manifest["created_at"],
            "note": "base64-encoded seeds; 'label' hints surface (tcp:<port> / pipe:<name> / file:<type> / generic)",
        }

        import_json_path  = self.root / "seeds_import.json"
        import_jsonl_path = self.root / "seeds_import.jsonl"
        await write_json(records, import_json_path, meta)
        await write_jsonl(records, import_jsonl_path)

        self.manifest["seeds"] = records
        self.manifest["imports_file_json"]  = str(import_json_path.resolve())
        self.manifest["imports_file_jsonl"] = str(import_jsonl_path.resolve())

        # manifest
        manifest_path = self.root / "seeds_manifest.json"
        ensure_dir(manifest_path.parent)
        await asyncio.to_thread(manifest_path.write_text, json.dumps(self.manifest, indent=2), "utf-8")

        # Optional global exports
        if self.export_jsonl:
            await write_jsonl(records, Path(self.export_jsonl))
        if self.export_json:
            await write_json(records, Path(self.export_json), meta)

        # Summary to stdout
        print("\n[+] Seed bin created")
        print(f"    Mode: {'PID' if self.is_pid_mode else 'FILE'}")
        if self.is_pid_mode:
            print(f"    PID: {self.pid}")
        else:
            print(f"    File: {self.manifest.get('target_file')}")
        print(f"    Root: {self.out_root.resolve()}")
        if ports:
            print(f"    TCP listeners discovered: {', '.join(map(str, ports))}")
        else:
            print("    TCP listeners discovered: (none)")
        if pipes:
            print(f"    Named pipes discovered: {', '.join(pipes)}")
        else:
            print("    Named pipes discovered: (none)")
        if self.file_types:
            print(f"    File types: {', '.join(self.file_types)}  (per-type={self.per_file_type}, pretty-ext={'on' if self.emit_pretty_ext else 'off'})")
        else:
            print("    File types: (none requested)")
        print(f"    Dictionary: {self.manifest['dictionary']['path']} (tokens={self.manifest['dictionary']['count']})")
        print(f"    Manifest: {manifest_path.resolve()}")
        print(f"    Import JSON : {import_json_path.resolve()}")
        print(f"    Import JSONL: {import_jsonl_path.resolve()}")
        print("    You can pass ANY of the above three files to pid_fuzzer via --seeds.\n")


# ===== CLI =====

def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Create dynamic seed bins for fuzzing based on a PID or a file (Windows).")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--pid", type=int, help="Target PID")
    group.add_argument("--file", type=str, help="Path to target binary on disk")
    ap.add_argument("--out", default="seeds", help="Output root directory")
    ap.add_argument("--per-port", type=int, default=16, help="Mutated seeds per discovered TCP port")
    ap.add_argument("--per-pipe", type=int, default=None, help="Mutated seeds per discovered named pipe (default: --per-port)")
    ap.add_argument("--max-grow", type=int, default=1024, help="Max growth per mutation")
    ap.add_argument("--avoid-hex", default="", help="Comma/space-separated hex bytes to avoid (e.g. '00,0a,0d')")
    ap.add_argument("--http-guess", action="store_true", help="If a port looks like HTTP (80/8080/8000/443/3000), add HTTP-ish seeds")
    ap.add_argument("--export-jsonl", default=None, help="(Optional) Also write a global JSONL outside pid/file folder.")
    ap.add_argument("--export-json",  default=None, help="(Optional) Also write a global JSON outside pid/file folder.")
    # Dictionary options
    ap.add_argument("--no-dict", action="store_true", help="Disable auto dictionary from PID/file")
    ap.add_argument("--dict-max", type=int, default=300, help="Max tokens to keep in dictionary")
    ap.add_argument("--dict-min-len", type=int, default=3, help="Min token length")
    ap.add_argument("--dict-max-len", type=int, default=64, help="Max token length")
    ap.add_argument("--dict-per-port", type=int, default=48, help="Dict-based seeds per TCP port (before mutation)")
    ap.add_argument("--dict-per-pipe", type=int, default=48, help="Dict-based seeds per named pipe (before mutation)")
    # File generation
    ap.add_argument("--file-types", default="", help="Comma-separated file types to generate (json,xml,png,zip,bmp,wav,txt,bin)")
    ap.add_argument("--per-file-type", type=int, default=24, help="Mutated file seeds per file type")
    ap.add_argument("--emit-pretty-ext", action="store_true", help="Also write copies with proper extensions (e.g., .json/.png) for manual testing")
    return ap.parse_args(argv)


async def _main_async(argv: Optional[List[str]] = None) -> None:
    args = _parse_args(argv)
    if not IS_WINDOWS:
        print("[!] This helper is intended for Windows; some features will be skipped.")
    builder = AsyncSeedBinBuilder(
        pid=args.pid,
        file_path=args.file,
        out_dir=args.out,
        per_port=args.per_port,
        per_pipe=args.per_pipe,
        max_grow=args.max_grow,
        avoid_hex=args.avoid_hex,
        http_guess=args.http_guess,
        export_jsonl=args.export_jsonl,
        export_json=args.export_json,
        no_dict=args.no_dict,
        dict_max=args.dict_max,
        dict_min_len=args.dict_min_len,
        dict_max_len=args.dict_max_len,
        dict_per_port=args.dict_per_port,
        dict_per_pipe=args.dict_per_pipe,
        file_types=args.file_types,
        per_file_type=args.per_file_type,
        emit_pretty_ext=args.emit_pretty_ext,
    )
    await builder.run()


if __name__ == "__main__":
    try:
        asyncio.run(_main_async())
    except KeyboardInterrupt:
        pass
