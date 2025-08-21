#!/usr/bin/env python3
import asyncio
import sys
import os
import argparse
import random
import string
import datetime
import json
from typing import List, Tuple, Dict, Optional
import contextlib
import re
import platform

# --- Optional cyclic pattern (pwntools) with safe fallback ---
try:
    from pwn import cyclic  # type: ignore
    def make_cyclic(n: int) -> bytes:
        return cyclic(n)
except Exception:
    def make_cyclic(n: int) -> bytes:
        alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        out = bytearray()
        while len(out) < n:
            for a in alphabet:
                for b in alphabet:
                    for c in alphabet:
                        out.extend([a, b, c])
                        if len(out) >= n:
                            return bytes(out[:n])
        return bytes(out[:n])

# ------------------ Helpers ------------------

def parse_env_kv(pairs: List[str]) -> Dict[str, str]:
    env = {}
    for p in pairs or []:
        if "=" not in p:
            raise ValueError(f"--env expects KEY=VALUE, got: {p}")
        k, v = p.split("=", 1)
        env[k] = v
    return env

def ensure_executable(path: str):
    if not os.path.exists(path) or not os.access(path, os.X_OK):
        raise FileNotFoundError(f"Target binary not found or not executable: {path}")

def now_stamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")

def decode_signal_posix(return_code: int) -> Optional[int]:
    if return_code is not None and return_code < 0:
        return -return_code
    return None

def to_printable(b: bytes, limit: int = 4096) -> str:
    txt = b.decode("utf-8", errors="replace")
    if len(txt) > limit:
        return txt[:limit] + "\n...(truncated)"
    return txt

def rc_to_winstatus(rc: int) -> Optional[int]:
    """Map a return code to unsigned 32-bit Windows NTSTATUS if it looks like one."""
    if rc is None:
        return None
    return rc & 0xFFFFFFFF

# --- Badchar handling ---

def parse_avoid_bytes(avoid_hex: Optional[str], avoid_cstr: Optional[str]) -> bytes:
    """
    Parse avoid bytes from either:
      --avoid-hex "00,0a,0d,1a"
      --avoid "\\x00\\x0a\\x0d\\x1a"
    Returns unique, sorted bytes.
    """
    s = set()
    if avoid_hex:
        for token in re.split(r"[,\s]+", avoid_hex.strip()):
            if not token:
                continue
            try:
                s.add(int(token, 16) & 0xFF)
            except ValueError:
                raise ValueError(f"Invalid hex byte in --avoid-hex: {token}")
    if avoid_cstr:
        for m in re.finditer(r"\\x([0-9a-fA-F]{2})", avoid_cstr):
            s.add(int(m.group(1), 16) & 0xFF)
    return bytes(sorted(s))

def default_avoid() -> bytes:
    base = {0x00, 0x0a, 0x0d}
    if platform.system().lower().startswith("win"):
        base.add(0x1a)  # ^Z sometimes acts as EOF in legacy consoles
    return bytes(sorted(base))

def build_allowed_table(avoid: bytes) -> bytes:
    # Always disallow NUL in argv payloads even if user forgets
    dis = set(avoid) | {0x00}
    allowed = bytes([b for b in range(256) if b not in dis])
    if not allowed:
        raise ValueError("Avoid set removes all bytes (no allowed bytes remain)")
    return allowed

def sanitize_bytes(buf: bytes, allowed: bytes) -> bytes:
    """Replace any disallowed byte with a random allowed byte (length-preserving)."""
    if not buf:
        return buf
    out = bytearray(buf)
    allowed_set = set(allowed)
    for i, b in enumerate(out):
        if b not in allowed_set:
            out[i] = allowed[random.randrange(0, len(allowed))]
    return bytes(out)

# --- Overflow heuristics ---

OVERFLOW_STDERR_PATTERNS = [
    r"stack smashing detected",                    # glibc FORTIFY
    r"buffer overflow detected",                   # glibc
    r"AddressSanitizer",                           # ASan
    r"stack-buffer-overflow",                      # ASan label
    r"heap-buffer-overflow",                       # ASan label
    r"runtime error: (?:index out of bounds|buffer overflow)",
    r"__fortify_fail", r"FORTIFY",
    r"EXC_BAD_ACCESS", r"segmentation fault",     # generic
]

def classify_probable_overflow(return_code: Optional[int], stderr: bytes) -> Tuple[bool, List[str]]:
    indicators = []

    # POSIX signals strongly associated with memory corruption
    if return_code is not None:
        sig = decode_signal_posix(return_code)
        if sig in (11, 7, 4, 6):  # SIGSEGV=11, SIGBUS=7, SIGILL=4, SIGABRT=6
            indicators.append(f"posix_signal_{sig}")

        # Windows NTSTATUS checks
        status = rc_to_winstatus(return_code)
        if status in (0xC0000005, 0xC0000409, 0xC0000374, 0xC000001D):
            # 0005=ACCESS_VIOLATION, 0409=STACK_BUFFER_OVERRUN, 0374=HEAP_CORRUPTION, 001D=ILLEGAL_INSTRUCTION
            indicators.append(f"ntstatus_{status:#010x}")

    s = stderr.decode("utf-8", errors="ignore").lower()
    for pat in OVERFLOW_STDERR_PATTERNS:
        if re.search(pat, s, flags=re.IGNORECASE):
            indicators.append(f"stderr:{pat}")

    return (len(indicators) > 0, indicators)

def loud_banner(msg: str):
    bar = "=" * max(36, len(msg) + 10)
    print(f"\n{bar}\n*** {msg} ***\n{bar}\n")

# ------------------ Fuzzer ------------------

class ArgvBufferOverflowFuzzer:
    def __init__(
        self,
        target_path: str,
        max_payload_size: int = 3000,
        step: int = 100,
        start_size: int = 0,
        timeout: float = 2.0,
        arg_indices: List[int] = [1],
        payload_type: str = "static",
        seed: Optional[int] = None,
        expect_zero_exit: bool = True,
        env_overrides: Optional[Dict[str, str]] = None,
        verbose: bool = False,
        avoid_hex: Optional[str] = None,
        avoid_cstr: Optional[str] = None,
        strict_badchars: bool = False,
    ):
        ensure_executable(target_path)
        self.target_path = target_path
        self.max_payload_size = max_payload_size
        self.step = max(1, step)
        self.start_size = max(0, start_size)
        self.timeout = timeout
        self.arg_indices = sorted(set(arg_indices))
        self.payload_type = payload_type.lower()
        self.expect_zero_exit = expect_zero_exit
        self.env = os.environ.copy()
        if env_overrides:
            self.env.update(env_overrides)
        self.env_overrides = env_overrides or {}
        self.verbose = verbose

        if seed is not None:
            random.seed(seed)

        # Global avoid/allow setup
        user_avoid = parse_avoid_bytes(avoid_hex, avoid_cstr)
        self.avoid_bytes = user_avoid if user_avoid else default_avoid()
        self.allowed_bytes = build_allowed_table(self.avoid_bytes)
        self.strict_badchars = strict_badchars

        os.makedirs("crashes", exist_ok=True)
        os.makedirs("artifacts", exist_ok=True)

    # ---------- Payload generators ----------
    def generate_payload(self, size: int) -> bytes:
        t = self.payload_type
        if t == "static":
            raw = b"A" * size
        elif t == "random":
            # high entropy then sanitize for avoid set
            raw = os.urandom(size)
        elif t == "cyclic":
            raw = make_cyclic(size)
        elif t == "format":
            patt = ("%x" * 8 + "%n").encode("latin-1")
            raw = (patt * (size // len(patt) + 1))[:size]
        elif t == "unicode":
            uni = ("𝔸" * (size // 4 + 2)).encode("utf-8")
            raw = uni[:size]
        elif t == "badchars":
            seq = bytes([0x01, 0x02, 0x7F, 0xFF]) + b"/\\..%$'\" \t\r\n"
            out = bytearray()
            while len(out) < size:
                out.extend(seq)
            raw = bytes(out[:size])
        elif t == "avoidset":
            raw = bytes(self.allowed_bytes[random.randrange(0, len(self.allowed_bytes))] for _ in range(size))
        elif t == "badchar-sweep":
            if not self.allowed_bytes:
                raise ValueError("No allowed bytes for sweep")
            rep = (size + len(self.allowed_bytes) - 1) // len(self.allowed_bytes)
            raw = (self.allowed_bytes * rep)[:size]
        else:
            raise ValueError(f"Unknown payload type: {self.payload_type}")

        # Global enforcement (length-preserving)
        payload = sanitize_bytes(raw, self.allowed_bytes)

        if self.strict_badchars:
            bad_found = set(payload) & set(self.avoid_bytes)
            if bad_found:
                raise AssertionError(f"strict-badchars violated; found: {sorted(bad_found)}")

        return payload

    def build_args(self, payload: bytes, arg_index: int) -> List[str]:
        max_idx = max(self.arg_indices)
        args = [self.target_path] + ["DUMMY"] * max_idx
        args[arg_index] = payload.decode("latin-1", errors="ignore")
        return args

    async def run_payload(self, payload: bytes, arg_index: int) -> Tuple[int, bytes, bytes]:
        args = self.build_args(payload, arg_index)
        if self.verbose:
            print(f"    exec: {args[:2]} ... (argc={len(args)})")

        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self.env,
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            stdout, stderr = await proc.communicate()
            return (-(1 << 30), stdout, stderr)

        return (proc.returncode if proc.returncode is not None else 0, stdout, stderr)

    def write_reproducer_script(
        self,
        base_no_ext: str,
        payload_bin: str,
        arg_index: int,
        timeout: Optional[float],
        probable_overflow: bool,
        indicators: List[str],
    ) -> str:
        repro_path = base_no_ext + ".py"
        banner_line = "PROBABLE BUFFER OVERFLOW" if probable_overflow else "No overflow heuristics triggered"
        script = f"""#!/usr/bin/env python3
import sys, os, subprocess, json

TARGET = {json.dumps(self.target_path)}
ARG_INDEX = {arg_index}
PAYLOAD_BIN = {json.dumps(os.path.abspath(payload_bin))}
TIMEOUT = {repr(timeout) if timeout is not None else 'None'}
ENV_OVERRIDES = {json.dumps(self.env_overrides)}
INDICATORS = {json.dumps(indicators)}
OVERFLOW_FLAG = {json.dumps(probable_overflow)}

def main():
    with open(PAYLOAD_BIN, "rb") as f:
        payload = f.read().decode("latin-1", errors="ignore")

    max_idx = max(ARG_INDEX, 1)
    argv = [TARGET] + ["DUMMY"] * max_idx
    argv[ARG_INDEX] = payload

    env = os.environ.copy()
    env.update(ENV_OVERRIDES)

    print("\\n==============================")
    print("*** Reproducer: {banner_line} ***")
    if INDICATORS:
        print("Indicators:", ", ".join(INDICATORS))
    print("==============================\\n")

    try:
        cp = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=TIMEOUT)
        rc = cp.returncode
        print("[repro] returncode:", rc)
        if rc is not None and rc < 0:
            sig = -rc
            print(f"[repro] terminated by signal: {{sig}}")
        if cp.stdout:
            print("[repro] --- stdout ---\\n" + cp.stdout.decode("utf-8", errors="replace"))
        if cp.stderr:
            print("[repro] --- stderr ---\\n" + cp.stderr.decode("utf-8", errors="replace"))
    except subprocess.TimeoutExpired as e:
        print("[repro] TIMEOUT after", TIMEOUT, "seconds")
        if e.stdout:
            print("[repro] --- stdout (partial) ---\\n" + e.stdout.decode("utf-8", errors="replace"))
        if e.stderr:
            print("[repro] --- stderr (partial) ---\\n" + e.stderr.decode("utf-8", errors="replace"))

if __name__ == "__main__":
    main()
"""
        with open(repro_path, "w", encoding="utf-8") as f:
            f.write(script)
        try:
            os.chmod(repro_path, 0o755)
        except Exception:
            pass
        return repro_path

    def write_crash_artifacts(
        self,
        reason: str,
        payload: bytes,
        arg_index: int,
        size: int,
        return_code: Optional[int],
        stdout: bytes,
        stderr: bytes,
    ) -> None:
        # Classify probable overflow
        probable_overflow, indicators = classify_probable_overflow(return_code, stderr)

        stamp = now_stamp()
        base = os.path.join("crashes", f"crash_{stamp}")
        meta_path = base + ".json"
        payload_bin = base + ".bin"
        payload_txt = base + ".txt"
        stderr_path = base + ".stderr"
        stdout_path = base + ".stdout"

        with open(payload_bin, "wb") as f:
            f.write(payload)
        with open(payload_txt, "w", encoding="utf-8", errors="ignore") as f:
            f.write(to_printable(payload))
        with open(stderr_path, "wb") as f:
            f.write(stderr or b"")
        with open(stdout_path, "wb") as f:
            f.write(stdout or b"")

        repro_script = self.write_reproducer_script(
            base, payload_bin, arg_index, self.timeout, probable_overflow, indicators
        )

        meta = {
            "target": self.target_path,
            "argv_index": arg_index,
            "payload_size": size,
            "payload_type": self.payload_type,
            "reason": reason,
            "return_code": return_code,
            "posix_signal": decode_signal_posix(return_code) if return_code is not None else None,
            "timestamp": stamp,
            "probable_overflow": probable_overflow,
            "overflow_indicators": indicators,
            "paths": {
                "meta_json": meta_path,
                "payload_bin": payload_bin,
                "payload_txt": payload_txt,
                "stderr": stderr_path,
                "stdout": stdout_path,
                "reproducer_py": repro_script,
            },
            "env_overrides": self.env_overrides,
            "timeout": self.timeout,
            "avoid_bytes_hex": [f"{b:02x}" for b in self.avoid_bytes],
        }
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

        if probable_overflow:
            loud_banner("PROBABLE BUFFER OVERFLOW DETECTED")
            print("Indicators:", ", ".join(indicators))
        print(f"  [+] Crash artifacts written: {meta_path}")
        print(f"  [+] Reproducer script: {repro_script}")

    async def fuzz_once(self, size: int, arg_index: int) -> bool:
        payload = self.generate_payload(size)
        print(f"[>] argv[{arg_index}] size {size}...", end=" ", flush=True)

        rc, out, err = await self.run_payload(payload, arg_index)

        if rc == (-(1 << 30)):
            print("TIMEOUT")
            self.write_crash_artifacts("timeout", payload, arg_index, size, None, out, err)
            return True

        sig = decode_signal_posix(rc)
        if sig is not None:
            print(f"CRASH (signal {sig})")
            self.write_crash_artifacts(f"signal_{sig}", payload, arg_index, size, rc, out, err)
            return True

        if rc != 0:
            if self.expect_zero_exit:
                print(f"NONZERO_EXIT ({rc})")
                self.write_crash_artifacts(f"nonzero_exit_{rc}", payload, arg_index, size, rc, out, err)
                return True
            else:
                print(f"exit={rc} (continuing)")
                return False

        print("OK")
        return False

    async def start_fuzzing(self):
        print(f"[+] Fuzzing: {self.target_path}")
        print(f"[+] Indices: {self.arg_indices} | Payload: {self.payload_type} | Timeout: {self.timeout}s")
        print(f"[+] Sizes: {self.start_size}..{self.max_payload_size} step {self.step}")
        print(f"[+] Avoid bytes: {' '.join(f'{b:02x}' for b in self.avoid_bytes)}")
        print(f"[+] Allowed set size: {len(self.allowed_bytes)}\n")

        # Emit a probe file of allowed bytes (useful for target-side validation)
        probe = bytes(self.allowed_bytes)
        probe_path = os.path.join("artifacts", f"badchars_probe_{now_stamp()}.bin")
        with open(probe_path, "wb") as _pf:
            _pf.write(probe)
        print(f"[+] Wrote badchar probe: {probe_path} (len={len(probe)})\n")

        for size in range(
            max(self.step, ((self.start_size + self.step - 1) // self.step) * self.step),
            self.max_payload_size + 1,
            self.step,
        ):
            for idx in self.arg_indices:
                try:
                    stop = await self.fuzz_once(size, idx)
                except Exception as e:
                    stop = True
                    print(f"\n[!] Exception during fuzz step: {e}")
                if stop:
                    print(f"\n[!] Stopping at argv[{idx}] size {size}")
                    print("[+] Fuzzing complete.\n")
                    return

        print("\n[+] Reached max payload size. Fuzzing complete.\n")

# ------------------ CLI ------------------

def parse_args():
    p = argparse.ArgumentParser(description="Argv Buffer Overflow Fuzzer (badchars-safe, overflow display & repro)")
    p.add_argument("binary", help="Path to target binary")
    p.add_argument("--indices", default="1", help="Comma-separated argv indices to fuzz (e.g., 1,2,3)")
    p.add_argument("--max-size", type=int, default=3000, help="Maximum payload size")
    p.add_argument("--start-size", type=int, default=0, help="Starting payload size")
    p.add_argument("--step", type=int, default=100, help="Increment size per attempt")
    p.add_argument("--timeout", type=float, default=2.0, help="Timeout seconds per run")
    p.add_argument("--payload-type",
                   choices=["static", "random", "cyclic", "format", "unicode", "badchars", "avoidset", "badchar-sweep"],
                   default="static",
                   help="Payload strategy")
    p.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")
    p.add_argument("--env", action="append", help="Env override KEY=VAL (can be repeated)")
    p.add_argument("--expect-zero-exit", action="store_true",
                   help="Treat any non-zero exit as interesting (stop & log)")
    p.add_argument("--verbose", action="store_true", help="Verbose exec logs")
    # New badchar options
    p.add_argument("--avoid-hex", default=None,
                   help="Comma/space-separated hex bytes to avoid (e.g., '00,0a,0d,1a')")
    p.add_argument("--avoid", dest="avoid_cstr", default=None,
                   help=r'Bytes to avoid in \xHH form (e.g., "\x00\x0a\x0d")')
    p.add_argument("--strict-badchars", action="store_true",
                   help="Fail immediately if a generated payload still contains an avoided byte")
    return p.parse_args()

def main():
    args = parse_args()
    try:
        arg_indices = [int(x.strip()) for x in args.indices.split(",") if x.strip()]
        if not arg_indices or any(i < 1 for i in arg_indices):
            raise ValueError("Indices must be >= 1 (argv[0] is the program path).")

        fuzzer = ArgvBufferOverflowFuzzer(
            target_path=args.binary,
            max_payload_size=args.max_size,
            start_size=args.start_size,
            step=args.step,
            timeout=args.timeout,
            arg_indices=arg_indices,
            payload_type=args.payload_type,
            seed=args.seed,
            expect_zero_exit=args.expect_zero_exit,
            env_overrides=parse_env_kv(args.env or []),
            verbose=args.verbose,
            avoid_hex=args.avoid_hex,
            avoid_cstr=args.avoid_cstr,
            strict_badchars=args.strict_badchars,
        )
        asyncio.run(fuzzer.start_fuzzing())
    except (FileNotFoundError, ValueError) as e:
        print(f"[!] {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
