#!/usr/bin/env python3
# Python 3.9+, Windows only
import argparse
import csv
import ctypes as C
import ctypes.wintypes as W
import datetime
import json
import os
import re
import sys
import textwrap
from typing import Dict, List, Optional, Tuple

# ---- Win32 constants / DLLs ----
PROCESS_VM_READ                   = 0x0010
PROCESS_QUERY_INFORMATION         = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
LIST_MODULES_ALL = 0x03
MAX_PATH = 260

kernel32 = C.WinDLL("kernel32", use_last_error=True)
psapi    = C.WinDLL("psapi",    use_last_error=True)

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

# ---------------- Strict overflow classifier ----------------
class OverflowClassifier:
    """
    Classifies crashes as probable buffer overflows.
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
        import os, sys, subprocess

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
                cp = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=TIMEOUT)
            elif SURFACE == "stdin":
                cp = subprocess.run([TARGET], input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=TIMEOUT)
            elif SURFACE == "env":
                env = env.copy()
                env["PAYLOAD"] = payload.decode("latin-1", errors="ignore")
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
                cp = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=TIMEOUT)
            else:
                print("[repro] Unknown surface:", SURFACE); sys.exit(2)

            print("[repro] returncode:", cp.returncode)
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
                # Non-PE or unreadable; skip quietly
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

# ---------------- Fuzzing Skeleton (process-spawn) ----------------
class FuzzSkeleton:
    """
    Safe skeleton for wiring your own fuzzing (spawned targets).
    DOES NOT perform mutations or execution automatically.
    Implement _mutate and _execute to make it work.
    """
    def __init__(self, *, target_path: str, surface: str,
                 timeout: float, arg_index: Optional[int],
                 file_arg_index: Optional[int],
                 env_overrides: Dict[str, str],
                 out_dir: str):
        self.target_path = target_path
        self.surface = surface
        self.timeout = timeout
        self.arg_index = arg_index
        self.file_arg_index = file_arg_index
        self.env_overrides = env_overrides
        self.out_dir = out_dir

        self.classifier = OverflowClassifier()
        self.repro = ReproScriptBuilder(out_dir=out_dir)

    def _mutate(self, seed: bytes, iteration: int) -> bytes:
        raise NotImplementedError("FuzzSkeleton._mutate is a stub. Implement your mutation logic.")

    def _execute(self, payload: bytes) -> Tuple[int, bytes, bytes]:
        raise NotImplementedError("FuzzSkeleton._execute is a stub. Implement your runner for the chosen surface.")

    def run(self, seeds: List[bytes], max_iters: int) -> None:
        if not seeds:
            print("[fuzz] No seeds provided; nothing to do.")
            return
        print(f"[fuzz] Skeleton started | surface={self.surface} | max_iters={max_iters} | seeds={len(seeds)}")
        for si, seed in enumerate(seeds):
            print(f"[fuzz] seed {si+1}/{len(seeds)} (len={len(seed)})")
            for it in range(max_iters):
                try:
                    payload = self._mutate(seed, it)
                except NotImplementedError as e:
                    print(f"[fuzz] {e.__class__.__name__}: {e}")
                    print("[fuzz] Exiting skeleton; implement _mutate/_execute to proceed.")
                    return
                except Exception as e:
                    print(f"[fuzz] mutation error at iter {it}: {e}")
                    continue

                try:
                    rc, out, err = self._execute(payload)
                except NotImplementedError as e:
                    print(f"[fuzz] {e.__class__.__name__}: {e}")
                    print("[fuzz] Exiting skeleton; implement _mutate/_execute to proceed.")
                    return
                except Exception as e:
                    print(f"[fuzz] execution error at iter {it}: {e}")
                    continue

                is_overflow, indicators = self.classifier.classify(rc, err)
                if is_overflow:
                    print("\n=== PROBABLE BUFFER OVERFLOW ===")
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
                    print("[fuzz] Stopping after first overflow (skeleton behavior).")
                    return
        print("[fuzz] Skeleton completed without detecting probable buffer overflows.")

# ---------------- Fuzzing Skeleton for a running PID ----------------
class FuzzSkeletonPID:
    """
    Safe, non-operational skeleton that attaches to a running PID (read-only) and
    provides hooks to deliver inputs via your own IPC (stdin of a child you created,
    named pipe, socket, WM_* messages, etc.). No code injection or memory writing.

    Implement:
      - _mutate(seed, iteration) -> bytes
      - _deliver_to_pid(payload) -> None        # your IPC delivery
      - _collect_signals() -> (return_code, stderr_bytes)
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
        self.target_path_for_repro = target_path_for_repro  # used only for building a repro script

        # Attach read-only to the process for metadata (no writing)
        access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ
        self.hProcess = OpenProcess(access, False, pid)
        if not self.hProcess:
            _raise_last_error(f"OpenProcess failed for PID {pid}")

        # Optional: you can use the inspector to enrich context if you wish
        self.classifier = OverflowClassifier()
        self.repro = ReproScriptBuilder(out_dir=out_dir)

    def close(self):
        if self.hProcess:
            CloseHandle(self.hProcess)
            self.hProcess = None

    # ----------------- YOU IMPLEMENT THESE -----------------
    def _mutate(self, seed: bytes, iteration: int) -> bytes:
        """
        TODO: implement your mutation logic here.
        Keep it length-bound and deterministic if you want stable repros.
        """
        raise NotImplementedError("FuzzSkeletonPID._mutate is a stub. Implement your mutation logic.")

    def _deliver_to_pid(self, payload: bytes) -> None:
        """
        TODO: deliver 'payload' to the running process indicated by self.pid.
        Examples (non-exhaustive):
          - If the target exposes a named pipe: connect and send bytes.
          - If it's a socket server: connect and send bytes.
          - If it's GUI: PostMessage/SendMessage with bounded data (very limited).
        This skeleton intentionally does NOT use WriteProcessMemory / injection.
        """
        raise NotImplementedError("FuzzSkeletonPID._deliver_to_pid is a stub. Implement your IPC delivery.")

    def _collect_signals(self) -> Tuple[Optional[int], bytes]:
        """
        TODO: collect outcome signals from the running process after delivery.
        Return:
          - return_code (int or None if still running)
          - stderr_bytes (bytes; logs you captured or tailed)
        Ideas:
          - If the target logs to a file, read the delta and return it as 'stderr_bytes'.
          - If you wrap with external monitoring (ETW/WER), summarize into stderr-like text.
        """
        return None, b""

    # ----------------- Orchestrator -----------------
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
                    except NotImplementedError as e:
                        print(f"[fuzz-pid] {e.__class__.__name__}: {e}")
                        print("[fuzz-pid] Exiting skeleton; implement _mutate/_deliver_to_pid/_collect_signals.")
                        return
                    except Exception as e:
                        print(f"[fuzz-pid] mutation error at iter {it}: {e}")
                        continue

                    try:
                        self._deliver_to_pid(payload)
                    except NotImplementedError as e:
                        print(f"[fuzz-pid] {e.__class__.__name__}: {e}")
                        print("[fuzz-pid] Exiting skeleton; implement _mutate/_deliver_to_pid/_collect_signals.")
                        return
                    except Exception as e:
                        print(f"[fuzz-pid] delivery error at iter {it}: {e}")
                        continue

                    rc, stderr = self._collect_signals()
                    is_overflow, indicators = self.classifier.classify(rc, stderr)
                    if is_overflow:
                        print("\n=== PROBABLE BUFFER OVERFLOW (PID skeleton) ===")
                        print("Indicators:", ", ".join(indicators))
                        # Build a repro for offline confirmation (spawns a new process)
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
                        print("[fuzz-pid] Stopping after first overflow (skeleton behavior).")
                        return

            print("[fuzz-pid] Completed without detecting probable buffer overflows.")
        finally:
            self.close()

# ---------------- CLI ----------------
def parse_args():
    p = argparse.ArgumentParser(description="IAT snapshot + strict overflow classifier + repro generator + fuzz skeleton (+ PID skeleton)")
    sub = p.add_subparsers(dest="cmd", required=False)

    # iat command (default)
    pi = sub.add_parser("iat", help="Snapshot import table (IAT) of a running PID")
    pi.add_argument("pid", type=int, help="Target process PID")
    pi.add_argument("--all-modules", action="store_true",
                    help="Walk import tables for every loaded module (not just main EXE)")
    pi.add_argument("--dll-regex", default=None, help="Regex to include only matching DLLs (case-insensitive)")
    pi.add_argument("--func-regex", default=None, help="Regex to include only matching function names")
    pi.add_argument("--only-ordinal", action="store_true", help="Keep only imports by ordinal")
    pi.add_argument("--no-artifacts", action="store_true", help="Do not write JSON/CSV artifacts")
    pi.add_argument("--limit", type=int, default=50, help="Preview limit for stdout")

    # classify command
    pc = sub.add_parser("classify", help="Strictly decide if a run indicates a probable buffer overflow")
    pc.add_argument("--rc", type=int, required=True, help="Process return code from the run")
    pc.add_argument("--stderr", required=True, help="Path to captured stderr file")

    # classify + repro command
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
    pr.add_argument("--env", action="append", default=[], help="ENV override KEY=VAL to include in the repro (repeatable)")
    pr.add_argument("--out-dir", default="crashes", help="Output directory for payload & repro")
    pr.add_argument("--no-rerun", action="store_true", help="Do not auto-execute the reproducer once")

    # fuzz skeleton command (spawned target; non-operational until you fill TODOs)
    pf = sub.add_parser("fuzz-skeleton", help="Non-operational fuzzing skeleton with strict overflow-only reporting")
    pf.add_argument("--target", required=True, help="Path to target binary (for repro bundles)")
    pf.add_argument("--surface", choices=["argv", "stdin", "env", "file"], required=True, help="Surface to fuzz")
    pf.add_argument("--timeout", type=float, default=2.0, help="Timeout seconds (used in repro bundles)")
    pf.add_argument("--arg-index", type=int, default=None, help="argv index when surface=argv")
    pf.add_argument("--file-arg-index", type=int, default=None, help="argv index where file path is placed when surface=file")
    pf.add_argument("--env", action="append", default=[], help="ENV override KEY=VAL (repeatable)")
    pf.add_argument("--out-dir", default="crashes", help="Where to write repro bundles")
    pf.add_argument("--seed-bin", action="append", default=[], help="Seed payload file (binary). Repeatable.")
    pf.add_argument("--max-iters", type=int, default=50, help="Iterations per seed (skeleton)")
    pf.add_argument("--ack-permission", action="store_true",
                    help="Acknowledges you have explicit permission to test this target (required)")

    # fuzz skeleton **for a running PID** (non-operational until you fill TODOs)
    pfp = sub.add_parser("fuzz-skeleton-pid", help="Non-operational PID fuzzing skeleton (attach to running process)")
    pfp.add_argument("--pid", type=int, required=True, help="Running process PID to target (read-only attach)")
    pfp.add_argument("--target", required=True, help="Path to target binary (only for building repro bundles)")
    pfp.add_argument("--surface", choices=["argv", "stdin", "env", "file"], required=True,
                     help="Semantic surface you intend to fuzz (used for repro only)")
    pfp.add_argument("--timeout", type=float, default=2.0, help="Timeout seconds (used in repro bundles)")
    pfp.add_argument("--arg-index", type=int, default=None, help="argv index when surface=argv (repro hint)")
    pfp.add_argument("--file-arg-index", type=int, default=None, help="argv index where file path is placed when surface=file (repro hint)")
    pfp.add_argument("--env", action="append", default=[], help="ENV override KEY=VAL (repro hint)")
    pfp.add_argument("--out-dir", default="crashes", help="Where to write repro bundles")
    pfp.add_argument("--seed-bin", action="append", default=[], help="Seed payload file (binary). Repeatable.")
    pfp.add_argument("--max-iters", type=int, default=50, help="Iterations per seed (skeleton)")
    pfp.add_argument("--ack-permission", action="store_true",
                     help="Acknowledges you have explicit permission to test this running process (required)")

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

def cmd_fuzz_skeleton(args):
    if not args.ack_permission:
        print("[!] Refusing to run: please supply --ack-permission to confirm you have explicit authorization to test this target.")
        sys.exit(2)

    seeds: List[bytes] = []
    for sp in args.seed_bin or []:
        try:
            seeds.append(_read_file_bytes(sp))
        except Exception as e:
            print(f"[fuzz] Failed to read seed {sp}: {e}")

    skel = FuzzSkeleton(
        target_path=args.target,
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
        print("[!] Refusing to run: please supply --ack-permission to confirm you have explicit authorization to test this running process.")
        sys.exit(2)

    seeds: List[bytes] = []
    for sp in args.seed_bin or []:
        try:
            seeds.append(_read_file_bytes(sp))
        except Exception as e:
            print(f"[fuzz-pid] Failed to read seed {sp}: {e}")

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
