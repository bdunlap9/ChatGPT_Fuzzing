#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Async Fuzz + IAT Inspector (Windows)
------------------------------------
Upgraded version with:
  - Live config + hotkeys (pause/toggles/timeout)
  - Target profile loader (URL or file)
  - CLI help scraper (seeds flags/headers/env)
  - Adaptive timeout (EWMA) + Windows argv length guard
  - Stability re-check before calling "probable"
  - Extra file templates (gif,jpeg,pdf,tar,7z)
  - Optional concurrency for spawn fuzzing
  - Extra PID transports (wmcopydata, file+notify)

Windows-only for IAT/Win32 parts. Python 3.9+.
"""

import argparse,asyncio,base64,csv,datetime,hashlib,json,os,random,re,socket,sys,textwrap,time,threading
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from threading import Event

# Optional deps used in certain features
try:
    import requests  # for profile loader (URL)
except Exception:
    requests = None

try:
    import tomli
except Exception:
    tomli = None

@dataclass
class FuzzSchema:
    # global knobs
    timeout: float = 2.0
    require_stable: bool = True
    promote_heur: bool = False
    minimize: bool = True
    minimize_budget_ms: int = 1200
    file_template: Optional[str] = None  # png|zip|json|xml|bmp|wav|gif|jpg|jpeg|pdf|tar|7z
    argv_pre: List[str] = field(default_factory=list)
    argv_post: List[str] = field(default_factory=list)

    # classifier tuning
    any_c000_as_crash: bool = True
    treat_warn_as_crash: bool = False
    include_rc_hints: bool = False
    timeout_is_crash: bool = False
    stderr_add_pat: str = ""     # regex OR

    # per-target hints (used to enrich globals)
    ignore_rcs: List[int] = field(default_factory=list)
    warn_rcs: List[int] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    headers: List[str] = field(default_factory=list)
    env_keys: List[str] = field(default_factory=list)
    file_templates: List[str] = field(default_factory=list)
    default_surface: Optional[str] = None  # auto|argv|stdin|env|file

    # PID transport defaults
    pid_mode: str = "noop"  # noop|file|file+notify|tcp|pipe|wmcopydata
    pid_tcp_addr: str = "127.0.0.1"
    pid_tcp_port: int = 0
    pid_pipe_name: str = ""
    pid_drop_dir: str = os.path.join("artifacts", "deliveries")
    pid_monitor_log: str = ""   # path for stderr scraping
    pid_avoid_hex: str = ""     # "00,0a,0d"
    pid_tcp_append_nl: bool = False

    # optional per-mode/per-target blocks (you may use them later)
    spawn: dict = field(default_factory=dict)
    pid: dict = field(default_factory=dict)
    targets: List[dict] = field(default_factory=list)  # [{"match":"curl.exe","flags":["--path-as-is"]}]

ALLOW_KEYS = set(FuzzSchema().__dict__.keys()) | {"include"}

def _read_config_file(path: str) -> dict:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "rb") as f:
            data = f.read()
        if path.lower().endswith((".toml", ".tml")):
            if not tomli:
                raise RuntimeError("tomli not installed for TOML files")
            return tomli.loads(data.decode("utf-8", "ignore"))
        # JSON with comments supported (// and /* */)
        txt = re.sub(r"/\*.*?\*/|//[^\n]*", "", data.decode("utf-8", "ignore"), flags=re.S)
        return json.loads(txt or "{}")
    except Exception as e:
        print(f"[config] failed to parse {path}: {e}")
        return {}

def _expand_env_strings(obj):
    # ${ENV:NAME|default}
    if isinstance(obj, str):
        def repl(m):
            name = m.group(1); default = m.group(2) or ""
            return os.environ.get(name, default)
        return re.sub(r"\$\{ENV:([A-Z0-9_]+)\|?([^}]*)\}", repl, obj)
    if isinstance(obj, list):
        return [_expand_env_strings(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _expand_env_strings(v) for k, v in obj.items()}
    return obj

def _merge(a: dict, b: dict) -> dict:
    # scalars replace; lists append-unique; dicts recurse
    out = dict(a)
    for k, v in (b or {}).items():
        if k not in out:
            out[k] = v; continue
        if isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _merge(out[k], v)
        elif isinstance(out[k], list) and isinstance(v, list):
            seen = set(out[k])
            out[k].extend([x for x in v if x not in seen])
        else:
            out[k] = v
    return out

def _strip_unknown(d: dict) -> dict:
    clean = {}
    for k, v in d.items():
        if k == "include" or k in ALLOW_KEYS:
            clean[k] = v
        else:
            print(f"[config] warning: unknown key '{k}' (ignored)")
    return clean

class ConfigManager:
    """
    Layers (earliest -> latest):
      defaults -> ~/.fuzzrc.toml -> fuzz.toml -> fuzz.json -> fuzz_config.json (live)
      -> profile (URL/file) -> env_overrides (dict) -> cli_overrides (dict)
    """
    def __init__(self, live_path="fuzz_config.json", extra_paths=None):
        self.live_path = live_path
        self.paths = [os.path.expanduser("~/.fuzzrc.toml"),
                      "fuzz.toml", "fuzz.json", live_path]
        if extra_paths: self.paths.extend(x for x in extra_paths if x)
        self._stop = Event()
        self._hash = ""
        self.effective: FuzzSchema = FuzzSchema()

    def _load_includes(self, blob: dict, base_dir: str) -> dict:
        incs = blob.get("include") or []
        if isinstance(incs, str): incs = [incs]
        merged = dict(blob)
        for rel in incs:
            p = rel if os.path.isabs(rel) else os.path.join(base_dir, rel)
            merged = _merge(_read_config_file(p), merged)
        return merged

    def load_layers(self, profile: dict = None, env_overrides: dict = None, cli_overrides: dict = None) -> FuzzSchema:
        acc: dict = asdict(FuzzSchema())
        for p in self.paths:
            d = _read_config_file(p)
            if not d: continue
            d = _expand_env_strings(d)
            d = self._load_includes(d, os.path.dirname(os.path.abspath(p)))
            d = _strip_unknown(d)
            acc = _merge(acc, d)

        if profile:
            acc = _merge(acc, _strip_unknown(profile))
        if env_overrides:
            acc = _merge(acc, env_overrides)
        if cli_overrides:
            acc = _merge(acc, cli_overrides)

        fc = FuzzSchema(**{k: acc.get(k, getattr(FuzzSchema, k, None)) for k in ALLOW_KEYS if k != "include"})
        # sanity clamps
        try:
            if not (0.2 <= float(fc.timeout) <= 60.0):
                print("[config] clamped timeout to 0.2..60"); fc.timeout = max(0.2, min(60.0, float(fc.timeout)))
        except Exception:
            fc.timeout = 2.0
        if fc.file_template and fc.file_template not in ["png","zip","json","xml","bmp","wav","gif","jpg","jpeg","pdf","tar","7z"]:
            print(f"[config] invalid file_template '{fc.file_template}', ignoring"); fc.file_template = None

        self.effective = fc
        return fc

    def write_effective_snapshot(self, path=os.path.join("artifacts","effective_config.json")):
        # runtime lookup is OK; method is called after class is defined
        AsyncFuzzInspector.ensure_outdir(os.path.dirname(path))
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(self.effective), f, indent=2)

    def apply_to_runtime(self, af: "AsyncFuzzInspector"):
        fc = self.effective
        # env for existing plumbing
        os.environ["FUZZ_MINIMIZE"] = "1" if fc.minimize else "0"
        os.environ["FUZZ_MINIMIZE_BUDGET_MS"] = str(fc.minimize_budget_ms)
        os.environ["FUZZ_TIMEOUT_BASE"] = str(fc.timeout)
        os.environ["FUZZ_ANY_C000_AS_CRASH"] = "1" if fc.any_c000_as_crash else "0"
        os.environ["FUZZ_TREAT_WARN_AS_CRASH"] = "1" if fc.treat_warn_as_crash else "0"
        os.environ["FUZZ_INCLUDE_RC_HINTS"] = "1" if fc.include_rc_hints else "0"
        os.environ["FUZZ_TIMEOUT_IS_CRASH"] = "1" if fc.timeout_is_crash else "0"
        if fc.stderr_add_pat: os.environ["FUZZ_STDERR_ADD_PAT"] = fc.stderr_add_pat

        if fc.file_template:
            os.environ["FUZZ_FILE_TEMPLATE"] = fc.file_template
            af.file_template = fc.file_template

        os.environ["FUZZ_ARGV_PRE"]  = json.dumps(fc.argv_pre or [])
        os.environ["FUZZ_ARGV_POST"] = json.dumps(fc.argv_post or [])
        af.pre_args  = fc.argv_pre or []
        af.post_args = fc.argv_post or []

        # classifier rc overrides
        af.classifier.set_target_overrides(ignore_rcs=set(fc.ignore_rcs), warn_rcs=set(fc.warn_rcs))

        # enrich global dicts
        for fl in fc.flags:
            b = fl.encode() if isinstance(fl, str) else fl
            if b not in _FLAGS_LIKE: _FLAGS_LIKE.append(b)
        for hk in fc.headers:
            b = hk.encode() if isinstance(hk, str) else hk
            if b not in _HDR_KEYS: _HDR_KEYS.append(b)
        for ek in fc.env_keys:
            tok = f"{ek}=".encode()
            if tok not in af.tokens: af.tokens.append(tok)

        # PID defaults
        if fc.pid_mode: os.environ["FUZZ_PID_MODE"] = fc.pid_mode
        os.environ["FUZZ_PID_TCP_ADDR"]   = fc.pid_tcp_addr
        os.environ["FUZZ_PID_TCP_PORT"]   = str(fc.pid_tcp_port)
        os.environ["FUZZ_PID_PIPE_NAME"]  = fc.pid_pipe_name
        os.environ["FUZZ_PID_DROP_DIR"]   = fc.pid_drop_dir
        os.environ["FUZZ_PID_MONITOR_LOG"]= fc.pid_monitor_log
        os.environ["FUZZ_PID_AVOID_HEX"]  = fc.pid_avoid_hex
        os.environ["FUZZ_PID_TCP_APPEND_NL"] = "1" if fc.pid_tcp_append_nl else "0"

    def _hash_live(self) -> str:
        try:
            with open(self.live_path, "rb") as f:
                b = f.read()
        except Exception:
            b = b""
        return hashlib.sha1(b).hexdigest()

    def start_hot_reload(self, interval=0.2, profile=None, env_overrides=None, cli_overrides=None):
        self._hash = self._hash_live()
        def loop():
            while not self._stop.is_set():
                h = self._hash_live()
                if h != self._hash:
                    self._hash = h
                    print("[cfg] live change detected -> reloading")
                    self.load_layers(profile=profile, env_overrides=env_overrides, cli_overrides=cli_overrides)
                    self.write_effective_snapshot()
                time.sleep(interval)
        t = threading.Thread(target=loop, daemon=True); t.start()
        return t

    def stop(self): self._stop.set()

# -------------------- Live Config + Hotkeys --------------------

class LiveConfig:
    """
    Simple polling config that hot-reloads from fuzz_config.json (or custom path).
    Example fuzz_config.json:
    {
      "timeout": 2.0,
      "require_stable": true,
      "promote_heur": false,
      "minimize": true
    }
    """
    def __init__(self, path="fuzz_config.json"):
        self.path = path
        self._mtime = 0.0
        self.data = {}
        self._load()

    def _load(self):
        try:
            st = os.stat(self.path)
            if st.st_mtime <= self._mtime:
                return
            self._mtime = st.st_mtime
            with open(self.path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
            print(f"[cfg] reloaded {self.path}")
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"[cfg] load error: {e}")

    def get(self, key, default=None):
        return self.data.get(key, default)

    def poll(self):
        self._load()


def start_hotkeys_thread(live_cfg: LiveConfig):
    """
    Windows-only hotkey toggles:
      P = pause/resume
      H = toggle heuristic promotion
      M = toggle minimizer
      Up/Down arrows = +/- 0.5s base timeout
    """
    try:
        import win32api
    except Exception:
        print("[hotkeys] win32api not available; hotkeys disabled")
        return

    def worker():
        paused = False
        while True:
            # P toggle pause
            if win32api.GetAsyncKeyState(ord('P')) & 0x8000:
                paused = not paused
                print(f"[hotkeys] paused={paused}")
                os.environ["FUZZ_PAUSED"] = "1" if paused else "0"
                time.sleep(0.2)

            # H toggle heuristic promotion
            if win32api.GetAsyncKeyState(ord('H')) & 0x8000:
                v = os.environ.get("FUZZ_PROMOTE_HEUR", "0")
                os.environ["FUZZ_PROMOTE_HEUR"] = "0" if v == "1" else "1"
                print(f"[hotkeys] FUZZ_PROMOTE_HEUR={os.environ['FUZZ_PROMOTE_HEUR']}")
                time.sleep(0.2)

            # M toggle minimizer
            if win32api.GetAsyncKeyState(ord('M')) & 0x8000:
                v = os.environ.get("FUZZ_MINIMIZE", "1")
                os.environ["FUZZ_MINIMIZE"] = "0" if v == "1" else "1"
                print(f"[hotkeys] FUZZ_MINIMIZE={os.environ['FUZZ_MINIMIZE']}")
                time.sleep(0.2)

            # Up/Down adjust base timeout
            if win32api.GetAsyncKeyState(0x26) & 0x8000:  # Up
                t = float(os.environ.get("FUZZ_TIMEOUT_BASE", live_cfg.get("timeout", 2.0) or 2.0))
                t = min(10.0, t + 0.5); os.environ["FUZZ_TIMEOUT_BASE"] = str(t)
                print(f"[hotkeys] timeout={t:.1f}s"); time.sleep(0.15)
            if win32api.GetAsyncKeyState(0x28) & 0x8000:  # Down
                t = float(os.environ.get("FUZZ_TIMEOUT_BASE", live_cfg.get("timeout", 2.0) or 2.0))
                t = max(0.2, t - 0.5); os.environ["FUZZ_TIMEOUT_BASE"] = str(t)
                print(f"[hotkeys] timeout={t:.1f}s"); time.sleep(0.15)

            live_cfg.poll()
            time.sleep(0.05)

    t = threading.Thread(target=worker, daemon=True)
    t.start()


# -------------------- Constants / Dictionaries --------------------

_URL_SCHEMES = [b"http", b"https", b"ftp", b"file"]
_URL_HOSTS   = [b"localhost", b"127.0.0.1", b"[::1]"]
_URL_PATHS   = [b"/", b"/%2e%2e/", b"/../../", b"/A"*64, b"/%00", b"/..%2f..%2f", b"/index.html"]
_METHODS     = [b"GET", b"POST", b"PUT", b"PATCH", b"DELETE", b"HEAD", b"OPTIONS"]
_FLAGS_LIKE  = [b"-v", b"-i", b"-k", b"--tlsv1.0", b"--tls-max", b"--limit-rate", b"--proxy", b"--header", b"--data", b"--path-as-is", b"--output", b"-sS", b"--resolve", b"--url"]
_INT_EDGES   = [b"0", b"1", b"2", b"7", b"8", b"9", b"10", b"15", b"16", b"31", b"32", b"63", b"64", b"127", b"128", b"255", b"256", b"1024", b"4095", b"4096", b"8191", b"8192"]
_HDR_KEYS    = [b"Host", b"User-Agent", b"Accept", b"Cookie", b"Range", b"If-Modified-Since", b"Referer", b"Accept-Encoding"]

def parse_env_kv(pairs: List[str]) -> Dict[str, str]:
    env: Dict[str, str] = {}
    for p in pairs or []:
        if "=" not in p:
            raise ValueError(f"--env expects KEY=VALUE, got: {p}")
        k, v = p.split("=", 1)
        env[k] = v
    return env

def load_target_profile(src: str) -> dict:
    """
    Load a target profile from URL or file (JSON or TOML).
    Keys (optional):
      ignore_rcs, warn_rcs, flags, headers, env_keys, file_templates, default_surface
    """
    try:
        if re.match(r"^https?://", src, re.I):
            if not requests:
                raise RuntimeError("requests not available for URL profiles")
            r = requests.get(src, timeout=5)
            r.raise_for_status()
            prof = r.json()
        else:
            prof = _read_config_file(src)  # supports TOML & JSON (with //, /* */ comments)
            if not isinstance(prof, dict):
                prof = {}
        return prof
    except Exception as e:
        print(f"[profile] failed to load {src}: {e}")
        return {}

def probe_cli_help(target_path: str) -> dict:
    """
    Scrape --help output to seed flags/headers/env tokens.
    """
    import subprocess
    texts = []
    for flag in ("--help","-h","/?"):
        try:
            cp = subprocess.run([target_path, flag], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2.0)
            texts.append((cp.stdout or b"") + b"\n" + (cp.stderr or b""))
        except Exception:
            pass
    blob = b"\n".join(texts).decode("utf-8", errors="ignore")
    flags = sorted(set(re.findall(r"(?:--[A-Za-z0-9][\w\-]*|-{1}[A-Za-z])", blob)))
    headers = sorted(set(re.findall(r"(?:Header|--header)\s+([A-Za-z][A-Za-z0-9\-]+):", blob, re.I)))
    envs = sorted(set(re.findall(r"\b([A-Z][A-Z0-9_]{2,})=", blob)))
    return {"flags": flags, "headers": headers, "envs": envs}


# -------------------- Classifier (module scope) --------------------
class OverflowClassifier:
    """
    Strong/weak crash classification designed to reduce repro spam:

    - Strong crash only when:
      * Stderr matches hardened crash patterns (ASan/UCRT/GS cookie/etc), or
      * Return code is an NTSTATUS in CRASH_STATUS_SET, or any 0xC000**** (unless ignored),
      * A POSIX signal-style negative rc (e.g. -11) is present,
      * WER marker appended ("WER_CRASH_DUMP_DETECTED").

    - Weak hints (non-zero rc, stderr spikes, warnings) are recorded in `inds` but do not flip `crashed=True`.

    Env knobs (all optional):
      FUZZ_ANY_C000_AS_CRASH=1   -> treat any 0xC000**** (except IGNORE_STATUS_SET) as crash (default: 1)
      FUZZ_TREAT_WARN_AS_CRASH=0 -> treat 0x8000**** as crash (default: 0 = off)
      FUZZ_INCLUDE_RC_HINTS=0    -> include plain "rc:X" hint in inds (default: 0 = off)
      FUZZ_TIMEOUT_IS_CRASH=0    -> count timeouts as crash (default: 0 = off)
      FUZZ_STDERR_ADD_PAT        -> extra patterns, '|' separated (regex OR)
    """

    CRASH_STATUS_SET = {
        0xC0000005, 0xC0000409, 0xC0000374, 0xC000001D, 0xC00000FD,
        0xC000008C, 0xC0000094, 0xC0000095, 0xC0000096, 0xC0000006,
        0xC0000025, 0xC0000028, 0xC000008E, 0xC0000090, 0xC0000091,
        0xC0000092, 0xC0000093, 0xC00002B4, 0xC00002B5,
    }
    WARN_STATUS_SET = {
        0x80000001, 0x80000002, 0x80000003, 0x80000004,
    }
    IGNORE_STATUS_SET = {
        0xC000013A,  # Ctrl+C
    }

    OVERFLOW_STDERR_PATTERNS = [
        r"stack smashing detected",
        r"buffer overflow detected",
        r"addresssanitizer|asan",
        r"ubsan|undefined behavior",
        r"msan|tsan",
        r"stack[- ]?buffer[- ]?overrun",
        r"_security_check_cookie|stack cookie|__report_gsfailure|gsfailure",
        r"heap corruption|HEAP CORRUPTION DETECTED",
        r"RtlReportCriticalFailure",
        r"invalid parameter",
        r"abort\(\)",
        r"access violation|segmentation fault|segfault",
        r"Unhandled exception",
        r"0xC0000[0-9A-Fa-f]{3}",
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

    def __init__(self):
        self.any_c000_as_crash = os.environ.get("FUZZ_ANY_C000_AS_CRASH", "1") == "1"
        self.warn_as_crash     = os.environ.get("FUZZ_TREAT_WARN_AS_CRASH", "0") == "1"
        self.include_rc_hints  = os.environ.get("FUZZ_INCLUDE_RC_HINTS", "0") == "1"
        self.timeout_is_crash  = os.environ.get("FUZZ_TIMEOUT_IS_CRASH", "0") == "1"

        extra = os.environ.get("FUZZ_STDERR_ADD_PAT", "").strip()
        if extra:
            self._pat = re.compile(self._pat.pattern + "|" + extra, re.IGNORECASE)

        self._crash_set  = OverflowClassifier.CRASH_STATUS_SET
        self._warn_set   = OverflowClassifier.WARN_STATUS_SET
        self._ignore_set = OverflowClassifier.IGNORE_STATUS_SET

        self._posix_severe = {11, 6, 4, 8, 5, 7}

        # Per-target overrides (plain rc, not NTSTATUS)
        self._ignore_plain_rcs: set[int] = set()
        self._warn_plain_rcs: set[int]   = set()

    def set_target_overrides(self, ignore_rcs: Optional[set] = None, warn_rcs: Optional[set] = None):
        self._ignore_plain_rcs = set(ignore_rcs or [])
        self._warn_plain_rcs   = set(warn_rcs or [])

    def classify(self, rc: Optional[int], stderr: bytes) -> Tuple[bool, List[str]]:
        inds: List[str] = []
        strong = False

        se_bytes = stderr or b""
        se_text  = se_bytes.decode("utf-8", errors="ignore")

        # --- Strong textual signals ---
        if self._pat.search(se_text):
            inds.append("stderr:crashy")
            strong = True
        if b"WER_CRASH_DUMP_DETECTED" in se_bytes:
            inds.append("wer:dump")
            strong = True

        # --- Return code analysis ---
        win = self._win_status(rc)
        sig = self._posix_signal(rc)

        if rc is None:
            inds.append("timeout")
            if self.timeout_is_crash:
                strong = True

        # POSIX signal mapping
        if sig in self._posix_severe:
            inds.append(f"posix:signal:{sig}")
            strong = True

        if win is not None:
            if win in self._ignore_set:
                inds.append(f"win:ignored:0x{win:08X}")
            else:
                if win in self._crash_set:
                    inds.append(f"win:0x{win:08X}")
                    strong = True
                elif self.any_c000_as_crash and (win & 0xC0000000) == 0xC0000000:
                    inds.append(f"win:c000+:{win:08X}")
                    strong = True
                elif self.warn_as_crash and (win & 0x80000000) == 0x80000000:
                    inds.append(f"win:warn:0x{win:08X}")
                    strong = True

        # Plain rc overrides (from target profile or config)
        if rc is not None:
            if rc in self._ignore_plain_rcs:
                inds.append(f"rc:ignored:{rc}")
                return False, inds
            if rc in self._warn_plain_rcs:
                inds.append(f"rc:warn:{rc}")

            if not strong and self.include_rc_hints:
                inds.append(f"rc:{rc}")

        return strong, inds


# -------------------- Adaptive Timeout --------------------

class AdaptiveTimeout:
    """
    Lightweight EWMA adaptive timeout: next_timeout ~= clamp(0.2 .. 10.0, 3x mean latency)
    """
    def __init__(self, base=2.0):
        self.base = float(base)
        self.mean = self.base * 1000.0
        self.alpha = 0.2

    def observe(self, dt_ms: float):
        self.mean = (1-self.alpha)*self.mean + self.alpha*dt_ms

    def next_timeout(self) -> float:
        t = max(0.2, min(10.0, (self.mean * 0.003)))  # 3x mean (ms to s)
        return t


# -------------------- Unified Async Class --------------------
class AsyncFuzzInspector:
    # ---- Win32 constants ----
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

    # ---------------- Lifecycle ----------------
    def __init__(self):
        # Shared state used by fuzzers (spawn + PID)
        self.max_growth = int(os.environ.get("FUZZ_PID_MAX_GROW", "1024"))
        self.file_template = os.environ.get("FUZZ_FILE_TEMPLATE", None)

        # Heuristics / novelty / buckets / tokens / WER
        self.classifier = OverflowClassifier()
        self.crash_buckets = AsyncFuzzInspector.CrashBucketer()
        self.novelty = self.NoveltyMap()
        self.hsig = self.HeuristicSignals()
        self.tokens: List[bytes] = []
        self.wer = self.WerWatcher(os.environ.get("FUZZ_WER_DIR"))

        # argv/stdin helpers
        self.pre_args = self._env_list("FUZZ_ARGV_PRE")
        self.post_args = self._env_list("FUZZ_ARGV_POST")
        self.stdin_prefix = os.environ.get("FUZZ_STDIN_PREFIX", "").encode("latin-1", "ignore")

    # ---------------- Utilities ----------------
    @staticmethod
    def now_stamp() -> str:
        return datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")

    @staticmethod
    def ensure_outdir(path: str):
        os.makedirs(path, exist_ok=True)

    @staticmethod
    def ensure_artifacts():
        os.makedirs("artifacts", exist_ok=True)

    @staticmethod
    def loud_banner(msg: str):
        bar = "=" * max(36, len(msg) + 10)
        print(f"\n{bar}\n*** {msg} ***\n{bar}\n")

    @staticmethod
    def _sha1(b: bytes) -> str:
        return hashlib.sha1(b).hexdigest()

    @staticmethod
    def _normalize_text_for_bucket(s: str) -> str:
        s = re.sub(r"[A-Za-z]:(?:\\[^\\\r\n]+)+", "PATH", s)
        s = re.sub(r"0x[0-9A-Fa-f]+", "0xADDR", s)
        s = re.sub(r"\b\d{5,}\b", "NUM", s)
        s = re.sub(r"\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\b", "TIME", s)
        return "\n".join(s.splitlines()[:12]).strip()

    @staticmethod
    def _env_list(name: str) -> List[str]:
        val = os.environ.get(name, "")
        if not val:
            return []
        try:
            j = json.loads(val)
            if isinstance(j, list):
                return [str(x) for x in j]
        except Exception:
            pass
        return [p for p in val.split() if p]

    # ---------------- Seeds & Auto-config ----------------
    @staticmethod
    def load_seeds_from_jsonl(path: str) -> Tuple[List[bytes], List[str]]:
        seeds, labels = [], []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line: continue
                rec = json.loads(line)
                if "data_b64" in rec:
                    seeds.append(base64.b64decode(rec["data_b64"]))
                    labels.append(rec.get("label", ""))
        return seeds, labels

    @staticmethod
    def load_seeds_from_json(path: str) -> Tuple[List[bytes], List[str]]:
        blob = json.load(open(path, "r", encoding="utf-8"))
        recs = blob.get("seeds")
        if recs is None and isinstance(blob, list):
            recs = blob
        if recs is None:
            recs = []
        seeds, labels = [], []
        for r in recs:
            if "data_b64" in r:
                seeds.append(base64.b64decode(r["data_b64"]))
                labels.append(r.get("label", ""))
        return seeds, labels

    @staticmethod
    def load_seeds_from_directory(dir_path: str) -> Tuple[List[bytes], List[str]]:
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

    @classmethod
    def load_seeds_any(cls, path: str) -> Tuple[List[bytes], List[str]]:
        if os.path.isdir(path):
            return cls.load_seeds_from_directory(path)
        ext = os.path.splitext(path)[1].lower()
        if ext == ".jsonl":
            return cls.load_seeds_from_jsonl(path)
        return cls.load_seeds_from_json(path)

    @staticmethod
    def dedupe_bytes_with_labels(seeds: List[bytes], labels: List[str]) -> Tuple[List[bytes], List[str]]:
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

    @staticmethod
    def maybe_autoconfig_transport_from_labels(labels: List[str]) -> None:
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
            prefix = r"\\.\pipe\\"
            p = pipe_name.replace("/", "\\")
            if not p.lower().startswith(prefix.lower()):
                p = prefix + p.lstrip("\\")
            os.environ["FUZZ_PID_PIPE_NAME"] = p
            print(f"[auto] FUZZ_PID_MODE=pipe FUZZ_PID_PIPE_NAME={os.environ['FUZZ_PID_PIPE_NAME']}")
            return

        os.environ["FUZZ_PID_MODE"] = "file"
        os.environ.setdefault("FUZZ_PID_DROP_DIR", os.path.join("artifacts", "deliveries"))
        AsyncFuzzInspector.ensure_outdir(os.environ["FUZZ_PID_DROP_DIR"])
        print(f"[auto] effective FUZZ_PID_MODE={os.environ['FUZZ_PID_MODE']!r}")

    # ---------------- Data Templating ----------------
    @staticmethod
    def with_file_template(payload: bytes, kind: Optional[str]) -> bytes:
        if not kind: return payload
        k = kind.lower()
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
                s = repr(payload)
            s_trunc = s[:4000]
            return json.dumps({"data": s_trunc}).encode("utf-8", "ignore")
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
        if k == "gif":
            return b"GIF89a" + payload[:4096]
        if k in ("jpg","jpeg"):
            return b"\xFF\xD8\xFF" + payload[:4096] + b"\xFF\xD9"
        if k == "pdf":
            return b"%PDF-1.4\n" + payload[:8000] + b"\n%%EOF\n"
        if k == "tar":
            return b"\x00" * 512 + payload[:16384]
        if k == "7z":
            return b"7z\xBC\xAF\x27\x1C" + payload[:8192]
        return payload

    # ---------------- Token Harvest ----------------
    _token_rgx = re.compile(r"[A-Za-z0-9_]{4,32}")

    @classmethod
    def harvest_tokens_from_stderr(cls, stderr: bytes) -> List[bytes]:
        s = (stderr or b"").decode("utf-8", errors="ignore")
        toks = set()
        for m in cls._token_rgx.findall(s):
            if m.lower() in ("error","fatal","exception","warning","failed","invalid","stack","heap"):
                continue
            toks.add(m.encode("latin-1", "ignore"))
        return list(toks)

    # ---------------- Smart CLI payloads ----------------
    @staticmethod
    def _rand_from(seq):
        return seq[random.randrange(len(seq))]

    @classmethod
    def _mk_url(cls, seed_hash:int)->bytes:
        sch  = cls._rand_from(_URL_SCHEMES)
        host = cls._rand_from(_URL_HOSTS)
        path = cls._rand_from(_URL_PATHS)
        q    = b"?q=" + (b"A" * ((seed_hash % 16)+1))
        return sch + b"://" + host + path + q

    @classmethod
    def _mk_header(cls, seed_hash:int)->bytes:
        k = cls._rand_from(_HDR_KEYS)
        v = b"A" * ((seed_hash % 48) + 1)
        return k + b": " + v

    @staticmethod
    def _looks_like_cli(_s: bytes)->bool:
        return True

    @classmethod
    def _splice_weighted(cls, base: bytes, dict_tokens: list, seed_hash:int)->bytes:
        if not dict_tokens:
            return base
        pool = []
        seen = {}
        for t in dict_tokens:
            L = max(1, len(t))
            seen[L] = seen.get(L, 0) + 1
        for t in dict_tokens:
            w = max(1, len(t) // 8) + (1 if t.startswith(b"--") else 0)
            pool.extend([t] * min(8, w))
        tok = cls._rand_from(pool)
        pos = seed_hash % (len(base)+1)
        return base[:pos] + tok + base[pos:]

    @classmethod
    def _mk_cli_like_payload(cls, seed_hash:int)->bytes:
        strat = seed_hash % 5
        if strat == 0:  # URL
            return cls._mk_url(seed_hash)
        if strat == 1:  # method + URL
            return cls._rand_from(_METHODS) + b" " + cls._mk_url(seed_hash)
        if strat == 2:  # flag + int edge
            return cls._rand_from(_FLAGS_LIKE) + b" " + cls._rand_from(_INT_EDGES)
        if strat == 3:  # header
            return cls._mk_header(seed_hash)
        return cls._rand_from(_FLAGS_LIKE) + b" " + cls._mk_header(seed_hash)

    # ---------------- Mutator + Schedules ----------------
    @staticmethod
    def _length_schedule(iter_idx: int, base_len: int, max_growth: int) -> int:
        B = [32, 48, 64, 80, 96, 128, 160, 192, 224, 256, 384, 512, 768, 1024, 1536, 2048]
        wave = B[(iter_idx // 7) % len(B)]
        soft_cap = min(base_len + max_growth, 4096)
        return max(1, min(soft_cap, wave))

    def _mutate_spawn(self, seed: bytes, iteration: int) -> bytes:
        def xorshift32(x: int) -> int:
            x ^= (x << 13) & 0xFFFFFFFF
            x ^= (x >> 17) & 0xFFFFFFFF
            x ^= (x << 5)  & 0xFFFFFFFF
            return x & 0xFFFFFFFF

        def sanitize(buf: bytearray, avoid: set) -> bytearray:
            if not avoid: return buf
            st = 0xDEADBEEF
            for i, b in enumerate(buf):
                if b in avoid:
                    st = xorshift32(st)
                    rep = st & 0xFF
                    while rep in avoid:
                        rep = (rep + 1) & 0xFF
                    buf[i] = rep
            return buf

        s  = seed or b"A"
        it = max(0, int(iteration))
        seed_hash = ((len(s) & 0xFFFF) << 16) ^ (it & 0xFFFF) or 0xBEEFCAFE

        if self._looks_like_cli(s) and (it % 10 in (0,2,5,8)):
            base = self._mk_cli_like_payload(seed_hash)
            if self.tokens:
                base = self._splice_weighted(base, self.tokens, seed_hash)
            grow = min(self.max_growth, (seed_hash & 0x3F))
            out  = (base * ((len(base)+grow)//max(1,len(base))))[:len(base)+grow]
        else:
            strat = it % 8
            if strat == 0:
                out = bytes(sanitize(bytearray(s), set()))
            elif strat == 1:
                buf = bytearray(s)
                pos = (seed_hash % max(1, len(buf)))
                bit = (seed_hash >> 5) & 7
                buf[pos] ^= (1 << bit)
                out = bytes(sanitize(buf, set()))
            elif strat == 2:
                interesting = [0x00,0xFF,0x7F,0x80,0x20,0x0A,0x0D,0x09,0x41,0x61,0x2F,0x5C]
                buf = bytearray(s)
                pos = seed_hash % max(1, len(buf))
                buf[pos] = interesting[it % len(interesting)]
                out = bytes(sanitize(buf, set()))
            elif strat == 3:
                buf = bytearray(s)
                win_len = min(max(2, (it % 7) + 2), max(1, len(buf)))
                start_max = max(1, len(buf) - win_len + 1)
                start = seed_hash % start_max
                delta = ((it & 3) - 1)
                for i in range(start, start + win_len):
                    buf[i] = (buf[i] + delta) & 0xFF
                out = bytes(sanitize(buf, set()))
            elif strat == 4:
                cap = min(len(s) + max(16, min(256, len(s) or 64)), len(s) + self.max_growth)
                base = s or b"A"
                rep  = (cap + len(base) - 1) // len(base)
                buf  = bytearray((base * rep)[:cap])
                if buf:
                    pos = seed_hash % len(buf)
                    buf[pos] = (buf[pos] ^ (it & 0x7F)) & 0xFF
                out = bytes(sanitize(buf, set()))
            elif strat == 5 and self.tokens:
                out = self._splice_weighted(s, self.tokens, seed_hash)
            elif strat == 6:
                m = re.search(rb"\d+", s)
                if m:
                    start, end = m.span()
                    out = s[:start] + random.choice(_INT_EDGES) + s[end:]
                else:
                    out = s + b"=" + random.choice(_INT_EDGES)
            else:
                mid = len(s) // 2
                out = (s[:mid] + s[:mid-1:-1]) if s else b"A"

        target_len = self._length_schedule(it, len(s), self.max_growth)
        if len(out) < target_len:
            out = (out + out[::-1] + b"A" * target_len)[:target_len]
        elif len(out) > target_len:
            head = target_len // 2
            tail = target_len - head
            out = out[:head] + out[-tail:]
        return out

    def _mutate_pid(self, seed: bytes, iteration: int, avoid_set: set) -> bytes:
        def xorshift32(x: int) -> int:
            x ^= (x << 13) & 0xFFFFFFFF
            x ^= (x >> 17) & 0xFFFFFFFF
            x ^= (x << 5)  & 0xFFFFFFFF
            return x & 0xFFFFFFFF

        def sanitize(buf: bytearray) -> bytearray:
            if not avoid_set:
                return buf
            st = 0xDEADBEEF
            for i, b in enumerate(buf):
                if b in avoid_set:
                    st = xorshift32(st)
                    rep = st & 0xFF
                    if rep in avoid_set:
                        rep = (rep + 1) & 0xFF
                        while rep in avoid_set:
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

        target_len = self._length_schedule(it, len(s), self.max_growth)
        if len(out) < target_len:
            out = (out + out[::-1] + b"A"*target_len)[:target_len]
        elif len(out) > target_len:
            head = target_len // 2
            tail = target_len - head
            out = out[:head] + out[-tail:]
        return bytes(out)

    # ---------------- Minimizer (async) ----------------
    async def minimize_payload_async(self, payload: bytes, predicate, time_budget_ms: int = 1200) -> bytes:
        start = time.perf_counter()
        best = payload
        step = max(8, len(best)//8)
        while step >= 8 and (time.perf_counter()-start)*1000 < time_budget_ms:
            changed = False; i = 0
            while i < len(best) and (time.perf_counter()-start)*1000 < time_budget_ms:
                j = min(len(best), i+step)
                cand = best[:i] + best[j:]
                if len(cand) >= 1 and await predicate(cand):
                    best = cand; changed = True
                else:
                    i += step
                await asyncio.sleep(0)
            if not changed: step //= 2
        step = max(4, len(best)//16)
        for bval in (0x41, 0x00, 0xFF, 0x20):
            if (time.perf_counter()-start)*1000 >= time_budget_ms: break
            i = 0
            while i < len(best) and (time.perf_counter()-start)*1000 < time_budget_ms:
                j = min(len(best), i+step)
                cand = bytearray(best)
                for k in range(i, j): cand[k] = bval
                cand = bytes(cand)
                if await predicate(cand): best = cand
                i += step
                await asyncio.sleep(0)
        return best

    # ---------------- Heuristics / Novelty / Buckets / Artifacts ----------------
    class HeuristicSignals:
        def __init__(self):
            self.lat_ms = []
            self.stderr_lens = []
            self.rc_hist = {}

        def update_and_score(self, *, dt_ms: float, stderr_len: int, rc: Optional[int]) -> Tuple[bool, List[str], float]:
            reasons = []
            self.lat_ms.append(dt_ms); self.lat_ms = self.lat_ms[-200:]
            self.stderr_lens.append(stderr_len); self.stderr_lens = self.stderr_lens[-200:]
            if rc is not None:
                self.rc_hist[rc] = self.rc_hist.get(rc, 0) + 1
                if rc in (3, -1073741819, 0xC0000005):
                    reasons.append(f"rc:{rc}")

            def mean(xs): return sum(xs)/len(xs) if xs else 0.0
            def stdev(xs):
                if len(xs) < 2: return 0.0
                m = mean(xs); return (sum((x-m)*(x-m) for x in xs)/(len(xs)-1))**0.5

            lat_m, lat_s = mean(self.lat_ms), stdev(self.lat_ms)
            sd_m, sd_s   = mean(self.stderr_lens), stdev(self.stderr_lens)
            z_lat = (dt_ms - lat_m) / (lat_s if lat_s > 1e-6 else 1e9)
            z_sd  = (stderr_len - sd_m) / (sd_s if sd_s > 1e-6 else 1e9)
            score = max(z_lat, z_sd)
            if z_lat > 4.0: reasons.append("latency_spike")
            if z_sd  > 4.0: reasons.append("stderr_spike")
            return bool(reasons), reasons, score

    class CrashBucketer:
        def __init__(self):
            self._seen = set()
        def _key(self, rc: Optional[int], stderr: bytes) -> str:
            s = (stderr or b"").decode("utf-8", errors="ignore")
            s = AsyncFuzzInspector._normalize_text_for_bucket(s)
            return f"{rc}|{AsyncFuzzInspector._sha1(s.encode('utf-8', 'ignore'))}"
        def seen_before(self, rc: Optional[int], stderr: bytes) -> bool:
            k = self._key(rc, stderr)
            if k in self._seen: return True
            self._seen.add(k); return False

    class NoveltyMap:
        def __init__(self):
            self._keys = set()
        def _vec(self, *, rc: Optional[int], dt_ms: float, stdout: bytes, stderr: bytes) -> bytes:
            se = len(stderr or b""); so = len(stdout or b"")
            rc_mod = (rc or 0) & 0xFF
            latb = int(max(0, min(9999, dt_ms))) // 10
            se_b = se // 64; so_b = so // 64
            norm = AsyncFuzzInspector._normalize_text_for_bucket((stderr or b"").decode("utf-8", "ignore"))
            lines = norm.splitlines()[:4]
            fp = AsyncFuzzInspector._sha1("\n".join(lines).encode("utf-8", "ignore"))[:12]
            return f"{se_b}:{so_b}:{rc_mod}:{latb}:{fp}".encode()
        def accept(self, *, rc: Optional[int], dt_ms: float, stdout: bytes, stderr: bytes) -> bool:
            key = AsyncFuzzInspector._sha1(self._vec(rc=rc, dt_ms=dt_ms, stdout=stdout, stderr=stderr))
            if key in self._keys: return False
            self._keys.add(key); return True

    class CorpusManager:
        def __init__(self, root="artifacts/corpus", cap=500):
            self.root = root; self.cap = cap
            AsyncFuzzInspector.ensure_outdir(self.root); self._count = 0
        def save(self, payload: bytes, tag: str = "novel") -> str:
            self._count += 1
            if self._count > self.cap: return ""
            fn = os.path.join(self.root, f"{tag}_{AsyncFuzzInspector.now_stamp()}.bin")
            with open(fn, "wb") as f: f.write(payload)
            return fn

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

    class ReproScriptBuilder:
        def __init__(self, out_dir: str = "crashes"):
            self.out_dir = out_dir
            AsyncFuzzInspector.ensure_outdir(self.out_dir)

        def _script_body(
            self,
            target: str,
            surface: str,
            payload_bin: str,
            timeout: Optional[float],
            arg_index: Optional[int],
            env_overrides: Optional[Dict[str, str]],
            file_arg_index: Optional[int],
        ) -> str:
            lines = [
                "#!/usr/bin/env python3",
                "import os, sys, subprocess, time",
                "",
                f"TARGET = {json.dumps(os.path.abspath(target))}",
                f"SURFACE = {json.dumps(surface)}",
                f"PAYLOAD_BIN = {json.dumps(os.path.abspath(payload_bin))}",
                f"TIMEOUT = {repr(timeout) if timeout is not None else 'None'}",
                f"ARG_INDEX = {arg_index if arg_index is not None else 'None'}",
                f"FILE_ARG_INDEX = {file_arg_index if file_arg_index is not None else 'None'}",
                f"ENV_OVERRIDES = {json.dumps(env_overrides or {})}",
                "",
                "def _resolve_surface():",
                "    if SURFACE != 'auto':",
                "        return SURFACE",
                "    if ARG_INDEX is not None and ARG_INDEX >= 1:",
                "        return 'argv'",
                "    if FILE_ARG_INDEX is not None and FILE_ARG_INDEX >= 1:",
                "        return 'file'",
                "    return 'stdin'",
                "",
                "def _safe_arg_index():",
                "    if ARG_INDEX is None: return None",
                "    return 1 if ARG_INDEX < 1 else ARG_INDEX",
                "",
                "def main():",
                "    script_dir = os.path.dirname(os.path.abspath(__file__))",
                "    if script_dir: os.chdir(script_dir)",
                "    with open(PAYLOAD_BIN, 'rb') as f:",
                "        payload = f.read()",
                "    env = os.environ.copy()",
                "    env.update(ENV_OVERRIDES or {})",
                "    surface = _resolve_surface()",
                "    if surface == 'argv':",
                "        idx = _safe_arg_index()",
                "        if idx is None:",
                "            print('[repro] ARG_INDEX required for argv'); sys.exit(2)",
                "        argv = [TARGET] + ['DUMMY'] * idx",
                "        argv[idx] = payload.decode('latin-1', errors='ignore')",
                "        t0 = time.perf_counter()",
                "        cp = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=TIMEOUT)",
                "    elif surface == 'stdin':",
                "        t0 = time.perf_counter()",
                "        cp = subprocess.run([TARGET], input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=TIMEOUT)",
                "    elif surface == 'env':",
                "        env2 = env.copy(); env2['PAYLOAD'] = payload.decode('latin-1', errors='ignore')",
                "        t0 = time.perf_counter()",
                "        cp = subprocess.run([TARGET], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env2, timeout=TIMEOUT)",
                "    elif surface == 'file':",
                "        idx = FILE_ARG_INDEX",
                "        if idx is None or idx < 1:",
                "            print('[repro] FILE_ARG_INDEX (>=1) required for file'); sys.exit(2)",
                "        tmp_path = os.path.join(os.path.dirname(PAYLOAD_BIN), 'input_' + str(int(time.time()*1e6)) + '.dat')",
                "        with open(PAYLOAD_BIN, 'rb') as fsrc, open(tmp_path, 'wb') as fdst:",
                "            fdst.write(fsrc.read())",
                "        argv = [TARGET] + ['DUMMY'] * idx",
                "        argv[idx] = tmp_path",
                "        t0 = time.perf_counter()",
                "        cp = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=TIMEOUT)",
                "    else:",
                "        print('[repro] Unknown surface:', surface); sys.exit(2)",
                "    dt_ms = (time.perf_counter()-t0)*1000.0",
                "    print('[repro] target:', TARGET)",
                "    print('[repro] surface:', surface)",
                "    print('[repro] returncode:', cp.returncode, 'dt_ms=%.1f' % dt_ms)",
                "    if cp.stdout: print('[repro] --- stdout ---\\n' + cp.stdout.decode('utf-8', errors='replace'))",
                "    if cp.stderr: print('[repro] --- stderr ---\\n' + cp.stderr.decode('utf-8', errors='replace'))",
                "",
                "if __name__ == '__main__':",
                "    main()",
                "",
            ]
            return "\n".join(lines)

        def _write_payload_files(self, base: str, payload: bytes) -> Tuple[str, str]:
            bin_path = os.path.join(self.out_dir, base + ".bin")
            txt_path = os.path.join(self.out_dir, base + ".txt")
            with open(bin_path, "wb") as f: f.write(payload)
            with open(txt_path, "w", encoding="utf-8", errors="ignore") as f:
                f.write(payload.decode("latin-1", errors="replace"))
            return bin_path, txt_path

        def build_and_optionally_run(
            self,
            *,
            target_path: str,
            surface: str,
            payload: bytes,
            timeout: Optional[float] = 2.0,
            arg_index: Optional[int] = None,
            env_overrides: Optional[Dict[str, str]] = None,
            file_arg_index: Optional[int] = None,
            run_after_write: bool = True
        ) -> Dict[str, str]:
            base = f"overflow_{AsyncFuzzInspector.now_stamp()}"
            bin_path, txt_path = self._write_payload_files(base, payload)
            script_path = os.path.join(self.out_dir, base + ".py")
            script = self._script_body(target_path, surface, bin_path, timeout, arg_index, env_overrides, file_arg_index)
            with open(script_path, "w", encoding="utf-8") as f: f.write(script)
            try:
                os.chmod(script_path, 0o755)
            except Exception:
                pass
            if run_after_write:
                try:
                    import subprocess
                    subprocess.run([sys.executable, script_path], check=False)
                except Exception as e:
                    print(f"[repro] Error re-running: {e}")
            return {"payload_bin": bin_path, "payload_txt": txt_path, "reproducer_py": script_path}

    # ---------------- Win32 IAT Inspector (read-only) ----------------
    class ProcessImportsInspector:
        def __init__(self, pid: int):
            import ctypes as C, ctypes.wintypes as W  # Windows only
            kernel32 = C.WinDLL("kernel32", use_last_error=True)
            psapi    = C.WinDLL("psapi",    use_last_error=True)

            self.C, self.W = C, W
            self.kernel32, self.psapi = kernel32, psapi
            self.pid = pid
            self.LIST_MODULES_ALL = AsyncFuzzInspector.LIST_MODULES_ALL
            self.MAX_PATH = AsyncFuzzInspector.MAX_PATH

            # prototypes
            self.EnumProcessModulesEx = psapi.EnumProcessModulesEx
            self.EnumProcessModulesEx.argtypes = [W.HANDLE, C.POINTER(W.HMODULE), W.DWORD, C.POINTER(W.DWORD), W.DWORD]
            self.EnumProcessModulesEx.restype  = W.BOOL

            self.GetModuleFileNameExW = psapi.GetModuleFileNameExW
            self.GetModuleFileNameExW.argtypes = [W.HANDLE, W.HMODULE, W.LPWSTR, W.DWORD]
            self.GetModuleFileNameExW.restype  = W.DWORD

            class MODULEINFO(C.Structure):
                _fields_ = [("lpBaseOfDll", W.LPVOID),
                            ("SizeOfImage", W.DWORD),
                            ("EntryPoint", W.LPVOID)]
            self.MODULEINFO = MODULEINFO

            self.GetModuleInformation = psapi.GetModuleInformation
            self.GetModuleInformation.argtypes = [W.HANDLE, W.HMODULE, C.POINTER(MODULEINFO), W.DWORD]
            self.GetModuleInformation.restype  = W.BOOL

            self.OpenProcess = kernel32.OpenProcess
            self.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
            self.OpenProcess.restype  = W.HANDLE

            self.CloseHandle = kernel32.CloseHandle
            self.CloseHandle.argtypes = [W.HANDLE]
            self.CloseHandle.restype  = W.BOOL

            self.ReadProcessMemory = kernel32.ReadProcessMemory
            self.ReadProcessMemory.argtypes = [W.HANDLE, W.LPCVOID, W.LPVOID, C.c_size_t, C.POINTER(C.c_size_t)]
            self.ReadProcessMemory.restype  = W.BOOL

            # PE structs
            class IMAGE_DOS_HEADER(C.Structure):
                _fields_ = [
                    ("e_magic", W.WORD), ("e_cblp", W.WORD), ("e_cp", W.WORD), ("e_crlc", W.WORD),
                    ("e_cparhdr", W.WORD), ("e_minalloc", W.WORD), ("e_maxalloc", W.WORD), ("e_ss", W.WORD),
                    ("e_sp", W.WORD), ("e_csum", W.WORD), ("e_ip", W.WORD), ("e_cs", W.WORD),
                    ("e_lfarlc", W.WORD), ("e_ovno", W.WORD), ("e_res", W.WORD * 4), ("e_oemid", W.WORD),
                    ("e_oeminfo", W.WORD), ("e_res2", W.WORD * 10), ("e_lfanew", W.LONG),
                ]
            self.IMAGE_DOS_HEADER = IMAGE_DOS_HEADER

            class IMAGE_FILE_HEADER(C.Structure):
                _fields_ = [("Machine", W.WORD), ("NumberOfSections", W.WORD), ("TimeDateStamp", W.DWORD),
                            ("PointerToSymbolTable", W.DWORD), ("NumberOfSymbols", W.DWORD),
                            ("SizeOfOptionalHeader", W.WORD), ("Characteristics", W.WORD)]
            self.IMAGE_FILE_HEADER = IMAGE_FILE_HEADER

            class IMAGE_DATA_DIRECTORY(C.Structure):
                _fields_ = [("VirtualAddress", W.DWORD), ("Size", W.DWORD)]
            self.IMAGE_DATA_DIRECTORY = IMAGE_DATA_DIRECTORY
            IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16

            class IMAGE_OPTIONAL_HEADER64(C.Structure):
                _fields_ = [
                    ("Magic", W.WORD), ("MajorLinkerVersion", C.c_ubyte), ("MinorLinkerVersion", C.c_ubyte),
                    ("SizeOfCode", W.DWORD), ("SizeOfInitializedData", W.DWORD), ("SizeOfUninitializedData", W.DWORD),
                    ("AddressOfEntryPoint", W.DWORD), ("BaseOfCode", W.DWORD), ("ImageBase", C.c_uint64),
                    ("SectionAlignment", W.DWORD), ("FileAlignment", W.DWORD),
                    ("MajorOperatingSystemVersion", W.WORD), ("MinorOperatingSystemVersion", W.WORD),
                    ("MajorImageVersion", W.WORD), ("MinorImageVersion", W.WORD),
                    ("MajorSubsystemVersion", W.WORD), ("MinorSubsystemVersion", W.WORD),
                    ("Win32VersionValue", W.DWORD), ("SizeOfImage", W.DWORD), ("SizeOfHeaders", W.DWORD),
                    ("CheckSum", W.DWORD), ("Subsystem", W.WORD), ("DllCharacteristics", W.WORD),
                    ("SizeOfStackReserve", C.c_uint64), ("SizeOfStackCommit", C.c_uint64),
                    ("SizeOfHeapReserve", C.c_uint64), ("SizeOfHeapCommit", C.c_uint64),
                    ("LoaderFlags", W.DWORD), ("NumberOfRvaAndSizes", W.WORD),
                    ("DataDirectory", IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
                ]
            self.IMAGE_OPTIONAL_HEADER64 = IMAGE_OPTIONAL_HEADER64

            class IMAGE_NT_HEADERS64(C.Structure):
                _fields_ = [("Signature", W.DWORD),
                            ("FileHeader", IMAGE_FILE_HEADER),
                            ("OptionalHeader", IMAGE_OPTIONAL_HEADER64)]
            self.IMAGE_NT_HEADERS64 = IMAGE_NT_HEADERS64

            class IMAGE_IMPORT_DESCRIPTOR(C.Structure):
                _fields_ = [("OriginalFirstThunk", W.DWORD), ("TimeDateStamp", W.DWORD), ("ForwarderChain", W.DWORD),
                            ("Name", W.DWORD), ("FirstThunk", W.DWORD)]
            self.IMAGE_IMPORT_DESCRIPTOR = IMAGE_IMPORT_DESCRIPTOR

            class IMAGE_THUNK_DATA64(C.Union):
                _fields_ = [("ForwarderString", C.c_uint64), ("Function", C.c_uint64), ("Ordinal", C.c_uint64), ("AddressOfData", C.c_uint64)]
            self.IMAGE_THUNK_DATA64 = IMAGE_THUNK_DATA64

            class IMAGE_IMPORT_BY_NAME(C.Structure):
                _fields_ = [("Hint", W.WORD)]
            self.IMAGE_IMPORT_BY_NAME = IMAGE_IMPORT_BY_NAME

            access = (AsyncFuzzInspector.PROCESS_QUERY_LIMITED_INFORMATION |
                      AsyncFuzzInspector.PROCESS_VM_READ |
                      AsyncFuzzInspector.PROCESS_CREATE_THREAD |
                      AsyncFuzzInspector.PROCESS_VM_WRITE |
                      AsyncFuzzInspector.PROCESS_VM_OPERATION)
            self.hProcess = self.OpenProcess(access, False, pid)
            if not self.hProcess:
                raise OSError(f"OpenProcess failed for PID {pid} (WinErr={C.get_last_error()})")

        def close(self):
            if self.hProcess:
                self.CloseHandle(self.hProcess)
                self.hProcess = None

        def _rpm(self, addr: int, size: int) -> bytes:
            C, W = self.C, self.W
            buf = (C.c_ubyte * size)()
            read = C.c_size_t(0)
            ok = self.ReadProcessMemory(self.hProcess, C.c_void_p(addr), buf, size, C.byref(read))
            if not ok or read.value != size:
                raise OSError(f"ReadProcessMemory failed at 0x{addr:016X} size {size} (WinErr={C.get_last_error()})")
            return bytes(buf)

        def _rpm_struct(self, addr: int, cstruct_type):
            C = self.C
            size = C.sizeof(cstruct_type)
            data = self._rpm(addr, size)
            inst = cstruct_type()
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

        def list_modules(self) -> List[Dict]:
            C, W = self.C, self.W
            needed = W.DWORD(0)
            self.EnumProcessModulesEx(self.hProcess, None, 0, C.byref(needed), self.LIST_MODULES_ALL)
            count = needed.value // C.sizeof(W.HMODULE)
            arr = (W.HMODULE * count)()
            ok = self.EnumProcessModulesEx(self.hProcess, arr, needed, C.byref(needed), self.LIST_MODULES_ALL)
            if not ok:
                raise OSError("EnumProcessModulesEx failed")
            mods = []
            for i in range(count):
                hmod = arr[i]
                path_buf = C.create_unicode_buffer(self.MAX_PATH * 4)
                self.GetModuleFileNameExW(self.hProcess, hmod, path_buf, len(path_buf))
                mi = self.MODULEINFO()
                if not self.GetModuleInformation(self.hProcess, hmod, C.byref(mi), C.sizeof(mi)):
                    raise OSError("GetModuleInformation failed")
                base = int(C.cast(mi.lpBaseOfDll, W.LPVOID).value)
                mods.append({"hmodule": hmod, "base": base, "size": mi.SizeOfImage, "path": path_buf.value})
            return mods

        def enumerate_imports_for_base(self, image_base: int) -> List[Dict]:
            dos = self._rpm_struct(image_base, self.IMAGE_DOS_HEADER)
            if dos.e_magic != 0x5A4D:  # 'MZ'
                return []
            nt_addr = image_base + dos.e_lfanew
            nt = self._rpm_struct(nt_addr, self.IMAGE_NT_HEADERS64)
            if nt.Signature != 0x4550:  # 'PE\0\0'
                return []
            opt = nt.OptionalHeader
            dir_import = opt.DataDirectory[1]
            import_rva = dir_import.VirtualAddress
            import_size = dir_import.Size
            if import_rva == 0 or import_size == 0:
                return []

            imports = []
            desc_size = self.C.sizeof(self.IMAGE_IMPORT_DESCRIPTOR)
            idx = 0
            while True:
                desc_addr = image_base + import_rva + idx * desc_size
                desc = self._rpm_struct(desc_addr, self.IMAGE_IMPORT_DESCRIPTOR)
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
                    iat_entry_va = image_base + ft_rva + thunk_index * self.C.sizeof(self.IMAGE_THUNK_DATA64)
                    t_ft = self._rpm_struct(iat_entry_va, self.IMAGE_THUNK_DATA64)
                    if t_ft.Function == 0:
                        break
                    func_name = None; hint_val = None; ordinal_val = None
                    if oft_rva:
                        int_entry_va = image_base + oft_rva + thunk_index * self.C.sizeof(self.IMAGE_THUNK_DATA64)
                        t_oft = self._rpm_struct(int_entry_va, self.IMAGE_THUNK_DATA64)
                        if (t_oft.Ordinal & (1 << 63)) != 0:
                            ordinal_val = t_oft.Ordinal & 0xFFFF
                        else:
                            ibn_addr = image_base + t_oft.AddressOfData
                            hint_raw = self._rpm(ibn_addr, 2)
                            hint_val = int.from_bytes(hint_raw, "little", signed=False)
                            func_name = self._read_c_string(ibn_addr + 2)
                    imports.append({
                        "dll": dll_name, "func": func_name, "ordinal": ordinal_val, "hint": hint_val,
                        "iat_entry_va": iat_entry_va, "resolved_ptr": t_ft.Function, "image_base": image_base,
                    })
                    thunk_index += 1
                idx += 1
            return imports

        def enumerate_imports_main_only(self) -> List[Dict]:
            mods = self.list_modules()
            if not mods: return []
            return self.enumerate_imports_for_base(mods[0]["base"])

    # ---------------- IAT Helpers / Artifacts ----------------
    @staticmethod
    def filter_entries(entries: List[Dict], dll_rgx: Optional[str], func_rgx: Optional[str], only_ordinal: bool) -> List[Dict]:
        dr = re.compile(dll_rgx, re.I) if dll_rgx else None
        fr = re.compile(func_rgx, re.I) if func_rgx else None
        out = []
        for e in entries:
            if dr and not dr.search(e["dll"] or ""): continue
            if only_ordinal and e.get("ordinal") is None: continue
            if fr:
                fname = e.get("func") or ""
                if not fr.search(fname): continue
            out.append(e)
        return out

    @staticmethod
    def write_artifacts(base: str, entries: List[Dict]) -> Dict[str, str]:
        AsyncFuzzInspector.ensure_artifacts()
        json_path = os.path.join("artifacts", base + ".json")
        csv_path  = os.path.join("artifacts", base + ".csv")
        with open(json_path, "w", encoding="utf-8") as f: json.dump(entries, f, indent=2)
        cols = ["dll", "func", "ordinal", "hint", "iat_entry_va", "resolved_ptr", "image_base"]
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f); w.writerow(cols)
            for e in entries: w.writerow([e.get(c, "") for c in cols])
        return {"json": json_path, "csv": csv_path}

    @staticmethod
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

    @classmethod
    def get_exe_path_from_pid(cls, pid: int) -> str:
        insp = cls.ProcessImportsInspector(pid)
        try:
            mods = insp.list_modules()
            if not mods:
                raise RuntimeError(f"No modules found for PID {pid}")
            return mods[0]["path"]
        finally:
            insp.close()

    # ---------------- Spawn Runner (async) ----------------
    async def _execute_spawn(self, *, target_path: str, payload: bytes, surface: str, timeout: float, arg_index: Optional[int], file_arg_index: Optional[int], env_overrides: Dict[str, str]) -> Tuple[Optional[int], bytes, bytes, float]:
        env = os.environ.copy(); env.update(env_overrides or {})
        t0 = time.perf_counter()

        def _would_exceed_windows_cmdline(argv_list: List[str]) -> bool:
            joined = " ".join(argv_list)
            return len(joined) > 32000  # conservative guard

        try:
            if surface == "argv":
                if arg_index is None:
                    raise ValueError("argv surface requires --arg-index (auto)")
                max_idx = max(arg_index, 1)
                argv = [target_path] + list(self.pre_args) + ["DUMMY"] * max_idx + list(self.post_args)
                argv[len(self.pre_args) + arg_index] = payload.decode("latin-1", errors="ignore")
                if os.name == "nt" and _would_exceed_windows_cmdline(argv):
                    # Auto-fallback if command line too long
                    fb_surface = "file" if file_arg_index is not None else "stdin"
                    return await self._execute_spawn(
                        target_path=target_path, payload=payload, surface=fb_surface, timeout=timeout,
                        arg_index=arg_index, file_arg_index=file_arg_index, env_overrides=env_overrides
                    )
                proc = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env)
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                except asyncio.TimeoutError:
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
                    dt_ms = (time.perf_counter() - t0) * 1000.0
                    return None, b"", b"[FuzzSkeleton] TimeoutExpired\n", dt_ms
                dt_ms = (time.perf_counter() - t0) * 1000.0
                return proc.returncode or 0, stdout or b"", stderr or b"", dt_ms

            if surface == "stdin":
                proc = await asyncio.create_subprocess_exec(target_path, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, stdin=asyncio.subprocess.PIPE, env=env)
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(self.stdin_prefix + payload), timeout=timeout)
                except asyncio.TimeoutError:
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
                    dt_ms = (time.perf_counter() - t0) * 1000.0
                    return None, b"", b"[FuzzSkeleton] TimeoutExpired\n", dt_ms
                dt_ms = (time.perf_counter() - t0) * 1000.0
                return proc.returncode or 0, stdout or b"", stderr or b"", dt_ms

            if surface == "env":
                env2 = env.copy()
                env2["PAYLOAD"] = payload.decode("latin-1", errors="ignore")
                proc = await asyncio.create_subprocess_exec(target_path, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env2)
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                except asyncio.TimeoutError:
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
                    dt_ms = (time.perf_counter() - t0) * 1000.0
                    return None, b"", b"[FuzzSkeleton] TimeoutExpired\n", dt_ms
                dt_ms = (time.perf_counter() - t0) * 1000.0
                return proc.returncode or 0, stdout or b"", stderr or b"", dt_ms

            if surface == "file":
                if file_arg_index is None:
                    raise ValueError("file surface requires --file-arg-index (auto)")
                out_dir = "crashes"
                self.ensure_outdir(out_dir)
                tmp = os.path.join(out_dir, f"input_{self.now_stamp()}.dat")
                to_write = self.with_file_template(payload, self.file_template)
                with open(tmp, "wb") as f:
                    f.write(to_write)
                max_idx = max(file_arg_index, 1)
                argv = [target_path] + list(self.pre_args) + ["DUMMY"] * max_idx + list(self.post_args)
                argv[len(self.pre_args) + file_arg_index] = tmp
                proc = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env)
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                except asyncio.TimeoutError:
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
                    dt_ms = (time.perf_counter() - t0) * 1000.0
                    return None, b"", b"[FuzzSkeleton] TimeoutExpired\n", dt_ms
                dt_ms = (time.perf_counter() - t0) * 1000.0
                return proc.returncode or 0, stdout or b"", stderr or b"", dt_ms

        except Exception as e:
            dt_ms = (time.perf_counter() - t0) * 1000.0
            return 1, b"", f"[FuzzSkeleton] execution error: {e}\n".encode(), dt_ms

        raise ValueError(f"unknown surface: {surface}")

    # ---------------- Surface Chooser ----------------
    @staticmethod
    def _choose_surface_for_payload(requested_surface: str, payload: bytes, arg_index: Optional[int], file_arg_index: Optional[int]) -> Tuple[str, Optional[int], Optional[int]]:
        if requested_surface != "auto":
            return requested_surface, arg_index, file_arg_index
        if arg_index is not None and b"\x00" not in payload:
            return "argv", arg_index, None
        if file_arg_index is not None:
            return "file", None, file_arg_index
        return "stdin", None, None

    # ---------------- Spawned-process Fuzzer ----------------
    async def fuzz_spawn(self, *, target_path: str, surface: str, base_timeout: float, arg_index: Optional[int], file_arg_index: Optional[int], env_overrides: Dict[str, str], seeds: List[bytes], max_iters: int, max_concurrency: int, require_stable: bool) -> None:
        if not seeds:
            print("[fuzz] No seeds provided; nothing to do.")
            return
        print(f"[fuzz] Skeleton started | target={target_path} | surface={surface} | iters={max_iters} | seeds={len(seeds)}")
        corpus = self.CorpusManager()
        repro  = self.ReproScriptBuilder(out_dir="crashes")
        adaptive = AdaptiveTimeout(base=base_timeout)

        async def do_iteration(seed: bytes, it: int):
            payload = self._mutate_spawn(seed, it)
            chosen_surface, arg_idx, file_idx = self._choose_surface_for_payload(surface, payload, arg_index, file_arg_index)
            to = adaptive.next_timeout()
            rc, stdout, stderr, dt_ms = await self._execute_spawn(
                target_path=target_path, payload=payload, surface=chosen_surface, timeout=to,
                arg_index=arg_idx, file_arg_index=file_idx, env_overrides=env_overrides
            )
            adaptive.observe(dt_ms)
            return payload, chosen_surface, arg_idx, file_idx, rc, stdout, stderr, dt_ms

        for si, seed in enumerate(seeds):
            print(f"[fuzz] seed {si+1}/{len(seeds)} (len={len(seed)})")
            it = 0
            while it < max_iters:
                # pause support
                while os.environ.get("FUZZ_PAUSED", "0") == "1":
                    await asyncio.sleep(0.1)

                # batch size for concurrency
                batch = min(max_concurrency, max_iters - it)
                tasks = [asyncio.create_task(do_iteration(seed, it + j)) for j in range(batch)]
                results = await asyncio.gather(*tasks, return_exceptions=False)

                for payload, chosen_surface, arg_idx, file_idx, rc, stdout, stderr, dt_ms in results:
                    # WER marker
                    wer_new = self.wer.poll_new()
                    if wer_new:
                        print(f"[wer] new crash dumps detected: {len(wer_new)}")
                        stderr = (stderr or b"") + b"\nWER_CRASH_DUMP_DETECTED\n"

                    # tokens from stderr
                    new_toks = self.harvest_tokens_from_stderr(stderr)
                    for t in new_toks:
                        if t not in self.tokens:
                            self.tokens.append(t)
                    if new_toks:
                        print(f"[dict] harvested {len(new_toks)} tokens from stderr (total {len(self.tokens)})")

                    # novelty -> corpus
                    if self.novelty.accept(rc=rc, dt_ms=dt_ms, stdout=stdout, stderr=stderr):
                        saved = corpus.save(payload, tag="novel")
                        if saved:
                            print(f"[corpus] novel behavior -> saved {saved}")

                    suspicious, h_reasons, _h_score = self.hsig.update_and_score(dt_ms=dt_ms, stderr_len=len(stderr or b""), rc=rc)
                    is_overflow, indicators = self.classifier.classify(rc, stderr)
                    crashed = is_overflow
                    if not crashed and os.environ.get("FUZZ_PROMOTE_HEUR", "0") == "1" and suspicious:
                        crashed = True
                        indicators = (indicators or []) + [f"heur:{'+'.join(h_reasons)}"]

                    if not crashed:
                        continue

                    # Stability re-check (same payload, once more)
                    if require_stable:
                        to2 = adaptive.next_timeout()
                        rc2, _so2, se2, _dt2 = await self._execute_spawn(
                            target_path=target_path, payload=payload, surface=chosen_surface, timeout=to2,
                            arg_index=arg_idx, file_arg_index=file_idx, env_overrides=env_overrides
                        )
                        ok2, _ = self.classifier.classify(rc2, se2)
                        if not ok2:
                            print("[crash] unstable (second run did not reproduce); skipping")
                            continue

                    if self.crash_buckets.seen_before(rc, stderr):
                        print("[crash] duplicate bucket; skipping repro bundle")
                        continue

                    # Minimization (optional)
                    do_min = os.environ.get("FUZZ_MINIMIZE", "1") == "1"
                    min_ms = int(os.environ.get("FUZZ_MINIMIZE_BUDGET_MS", "1200"))
                    if do_min:
                        async def pred(b: bytes) -> bool:
                            to3 = adaptive.next_timeout()
                            rc3, _so3, se3, _dt3 = await self._execute_spawn(
                                target_path=target_path, payload=b, surface=chosen_surface, timeout=to3,
                                arg_index=arg_idx, file_arg_index=file_idx, env_overrides=env_overrides
                            )
                            ok3, _ = self.classifier.classify(rc3, se3)
                            if ok3: return True
                            if os.environ.get("FUZZ_PROMOTE_HEUR", "0") == "1":
                                hs_tmp = self.HeuristicSignals()
                                hs_tmp.lat_ms = list(self.hsig.lat_ms)
                                hs_tmp.stderr_lens = list(self.hsig.stderr_lens)
                                hs_tmp.rc_hist = dict(self.hsig.rc_hist)
                                suspicious3, _r, _s = hs_tmp.update_and_score(dt_ms=_dt3, stderr_len=len(se3 or b""), rc=rc3)
                                return suspicious3
                            return False
                        payload_min = await self.minimize_payload_async(payload, pred, time_budget_ms=min_ms)
                        if len(payload_min) < len(payload):
                            print(f"[min] shrank payload {len(payload)} -> {len(payload_min)} bytes")
                            payload = payload_min

                    # Save crash + meta
                    saved = corpus.save(payload, tag="crash")
                    if saved:
                        print(f"[crash] saved payload -> {saved}")
                        try:
                            meta = {
                                "target": target_path, "surface": chosen_surface, "rc": rc, "dt_ms": dt_ms,
                                "indicators": indicators, "arg_index": arg_idx, "file_arg_index": file_idx,
                                "pre_args": self.pre_args, "post_args": self.post_args, "ts": self.now_stamp(),
                            }
                            with open(saved + ".json", "w", encoding="utf-8") as mf:
                                json.dump(meta, mf, indent=2)
                        except Exception:
                            pass

                    print("\n=== PROBABLE VULN (spawned) ===")
                    print("Indicators:", ", ".join(indicators))
                    paths = repro.build_and_optionally_run(
                        target_path=target_path, surface=chosen_surface, payload=payload, timeout=adaptive.next_timeout(),
                        arg_index=arg_idx, env_overrides=env_overrides, file_arg_index=file_idx, run_after_write=True
                    )
                    print("[fuzz] Repro bundle:", json.dumps(paths, indent=2))

                it += batch

        print("[fuzz] Completed.")

    # ---------------- PID Delivery ----------------
    async def _deliver_to_pid(self, *, payload: bytes, timeout: float) -> None:
        mode = (os.environ.get("FUZZ_PID_MODE", "noop") or "noop").strip().lower()
        drop_dir = (os.environ.get("FUZZ_PID_DROP_DIR", os.path.join("artifacts", "deliveries")) or "").strip() or os.path.join("artifacts", "deliveries")
        tcp_addr = (os.environ.get("FUZZ_PID_TCP_ADDR", "127.0.0.1") or "127.0.0.1").strip()
        tcp_port = int((os.environ.get("FUZZ_PID_TCP_PORT", "0") or "0").strip() or "0")
        pipe_name = (os.environ.get("FUZZ_PID_PIPE_NAME", "") or "").strip() or None

        self.ensure_outdir(drop_dir)

        if mode == "noop":
            print(f"[fuzz-pid] (noop) would deliver {len(payload)} bytes")
            return

        if mode == "file":
            stamp = self.now_stamp()
            out_path = os.path.join(drop_dir, f"payload_{stamp}.bin")
            to_write = self.with_file_template(payload, self.file_template)
            def _write():
                with open(out_path, "wb") as f:
                    f.write(to_write)
                with open(out_path + ".meta.json", "w", encoding="utf-8") as mf:
                    json.dump({"bytes": len(to_write), "timestamp": stamp}, mf, indent=2)
            await asyncio.to_thread(_write)
            print(f"[fuzz-pid] (file) wrote payload -> {out_path}")
            return

        if mode == "file+notify":
            stamp = self.now_stamp()
            out_path = os.path.join(drop_dir, f"payload_{stamp}.bin")
            def _write2():
                with open(out_path, "wb") as w:
                    w.write(payload)
                open(out_path + ".trig","wb").close()
            await asyncio.to_thread(_write2)
            print(f"[fuzz-pid] (file+notify) wrote {out_path} and trigger file")
            return

        if mode == "tcp":
            if not tcp_port:
                raise RuntimeError("FUZZ_PID_TCP_PORT not set or zero for tcp mode")
            def _send():
                attempts = 3
                for i in range(attempts):
                    try:
                        with socket.create_connection((tcp_addr, tcp_port), timeout=timeout) as sock:
                            sock.sendall(payload)
                            if os.environ.get("FUZZ_PID_TCP_APPEND_NL") == "1":
                                sock.sendall(b"\n")
                        return True
                    except Exception:
                        if i == attempts - 1:
                            raise
                        time.sleep(0.05 * (i + 1))
                return False

            await asyncio.to_thread(_send)
            print(f"[fuzz-pid] (tcp) sent {len(payload)} bytes to {tcp_addr}:{tcp_port}")
            return

        if mode == "pipe":
            # Windows Named Pipe write via ctypes in a thread
            import ctypes as C, ctypes.wintypes as W
            kernel32 = C.WinDLL("kernel32", use_last_error=True)
            CreateFileW = kernel32.CreateFileW
            CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE]
            CreateFileW.restype  = W.HANDLE
            WaitNamedPipeW = kernel32.WaitNamedPipeW
            WaitNamedPipeW.argtypes = [W.LPCWSTR, W.DWORD]
            WaitNamedPipeW.restype  = W.BOOL
            WriteFile = kernel32.WriteFile
            WriteFile.argtypes = [W.HANDLE, W.LPCVOID, W.DWORD, C.POINTER(W.DWORD), W.LPVOID]
            WriteFile.restype  = W.BOOL

            if not pipe_name:
                raise RuntimeError("FUZZ_PID_PIPE_NAME is required for pipe mode, e.g. \\.\pipe\MyPipe")
            wait_ms = int(float(os.environ.get("FUZZ_PID_PIPE_WAIT_MS", str(int(timeout * 1000)))) or 0)
            def _pipe_write():
                if wait_ms > 0:
                    WaitNamedPipeW(pipe_name, wait_ms)
                GENERIC_WRITE = AsyncFuzzInspector.GENERIC_WRITE
                OPEN_EXISTING = AsyncFuzzInspector.OPEN_EXISTING
                h = CreateFileW(pipe_name, GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None)
                if int(h) == 0 or int(h) == C.c_void_p(-1).value:
                    raise OSError(f"CreateFileW on pipe failed: {pipe_name} (WinErr={C.get_last_error()})")
                try:
                    n_written = W.DWORD(0)
                    ok = WriteFile(h, payload, len(payload), C.byref(n_written), None)
                    if not ok or n_written.value != len(payload):
                        raise OSError(f"WriteFile to pipe incomplete: {n_written.value}/{len(payload)} (WinErr={C.get_last_error()})")
                finally:
                    kernel32.CloseHandle(h)
            await asyncio.to_thread(_pipe_write)
            print(f"[fuzz-pid] (pipe) wrote {len(payload)} bytes to {pipe_name}")
            return

        if mode == "wmcopydata":
            import ctypes as C, ctypes.wintypes as W
            user32 = C.WinDLL("user32", use_last_error=True)
            FindWindowW = user32.FindWindowW
            FindWindowW.argtypes = [W.LPCWSTR, W.LPCWSTR]
            FindWindowW.restype = W.HWND
            SendMessageW = user32.SendMessageW
            SendMessageW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM]
            SendMessageW.restype = W.LRESULT
            class COPYDATASTRUCT(C.Structure):
                _fields_=[("dwData", W.ULONG_PTR), ("cbData", W.DWORD), ("lpData", W.LPVOID)]
            target_class = os.environ.get("FUZZ_PID_WNDCLASS","")
            target_caption = os.environ.get("FUZZ_PID_WNDCAPTION","")
            hwnd = FindWindowW(target_class or None, target_caption or None)
            if not hwnd:
                raise OSError("target window not found (set FUZZ_PID_WNDCLASS / FUZZ_PID_WNDCAPTION)")
            buf = C.create_string_buffer(payload)
            cds = COPYDATASTRUCT(0, len(payload), C.cast(buf, W.LPVOID))
            WM_COPYDATA = 0x004A
            SendMessageW(hwnd, WM_COPYDATA, 0, C.byref(cds))
            print(f"[fuzz-pid] (wmcopydata) sent {len(payload)} bytes")
            return

        raise ValueError(f"Unknown FUZZ_PID_MODE='{mode}' (expected noop|file|file+notify|tcp|pipe|wmcopydata)")

    async def _collect_signals(self, *, timeout: float) -> Tuple[Optional[int], bytes]:
        rc: Optional[int] = None
        log_path = (os.environ.get("FUZZ_PID_MONITOR_LOG", "") or "").strip() or None
        if not log_path:
            await asyncio.sleep(min(0.02, max(0.0, timeout / 200.0)))
            return rc, b""
        p = Path(log_path)
        if not p.exists() or not p.is_file():
            await asyncio.sleep(min(0.02, max(0.0, timeout / 200.0)))
            return rc, b""
        data = await asyncio.to_thread(p.read_bytes)
        await asyncio.sleep(min(0.02, max(0.0, timeout / 200.0)))
        return rc, data

    # ---------------- PID Fuzzer ----------------
    async def fuzz_pid(self, *, pid: int, target_path_for_repro: str, surface: str, base_timeout: float, arg_index: Optional[int], file_arg_index: Optional[int], env_overrides: Dict[str, str], seeds: List[bytes], labels: List[str], max_iters: int, require_stable: bool) -> None:
        avoid_hex  = os.environ.get("FUZZ_PID_AVOID_HEX", "")
        avoid_set = {int(t, 16) & 0xFF for t in re.split(r"[,\s]+", avoid_hex) if t} if avoid_hex else set()

        print(f"[fuzz-pid] Skeleton started | pid={pid} | surface={surface} | iters={max_iters} | seeds={len(seeds)}")

        if seeds:
            by = {"tcp": 0, "pipe": 0, "generic": 0, "other": 0}
            for lab in labels:
                if isinstance(lab, str) and lab.startswith("tcp:"): by["tcp"] += 1
                elif isinstance(lab, str) and lab.startswith("pipe:"): by["pipe"] += 1
                elif lab == "generic": by["generic"] += 1
                else: by["other"] += 1
            print(f"[fuzz-pid] Seeds loaded: {len(seeds)}  (tcp={by['tcp']}, pipe={by['pipe']}, generic={by['generic']}, other={by['other']})")

        corpus = self.CorpusManager()
        repro  = self.ReproScriptBuilder(out_dir="crashes")
        adaptive = AdaptiveTimeout(base=base_timeout)

        for si, seed in enumerate(seeds or [b"A"]):
            print(f"[fuzz-pid] seed {si+1}/{max(1,len(seeds))} (len={len(seed)})")
            for it in range(max(1, max_iters)):
                while os.environ.get("FUZZ_PAUSED", "0") == "1":
                    await asyncio.sleep(0.1)

                try:
                    payload = self._mutate_pid(seed, it, avoid_set)
                except Exception as e:
                    print(f"[fuzz-pid] mutation error at iter {it}: {e}")
                    continue

                try:
                    t0 = time.perf_counter()
                    await self._deliver_to_pid(payload=payload, timeout=adaptive.next_timeout())
                    rc, stderr = await self._collect_signals(timeout=adaptive.next_timeout())
                    dt_ms = (time.perf_counter() - t0) * 1000.0
                    stdout = b""
                    adaptive.observe(dt_ms)
                except Exception as e:
                    print(f"[fuzz-pid] delivery error at iter {it}: {e}")
                    continue

                wer_new = self.wer.poll_new()
                if wer_new:
                    print(f"[wer] new crash dumps detected: {len(wer_new)}")
                    stderr = (stderr or b"") + b"\nWER_CRASH_DUMP_DETECTED\n"

                new_toks = self.harvest_tokens_from_stderr(stderr)
                for t in new_toks:
                    if t not in self.tokens:
                        self.tokens.append(t)
                if new_toks:
                    print(f"[dict] harvested {len(new_toks)} tokens from stderr (total {len(self.tokens)})")

                if self.novelty.accept(rc=rc, dt_ms=dt_ms, stdout=stdout, stderr=stderr):
                    saved = corpus.save(payload, tag="novel")
                    if saved:
                        print(f"[corpus] novel behavior -> saved {saved}")

                suspicious, h_reasons, _h_score = self.hsig.update_and_score(dt_ms=dt_ms, stderr_len=len(stderr or b""), rc=rc)

                is_overflow, indicators = self.classifier.classify(rc, stderr)
                crashed = is_overflow
                if not crashed and os.environ.get("FUZZ_PROMOTE_HEUR", "0") == "1" and suspicious:
                    crashed = True
                    indicators = (indicators or []) + [f"heur:{'+'.join(h_reasons)}"]

                if not crashed:
                    continue

                # Stability re-check
                if require_stable:
                    t1 = time.perf_counter()
                    await self._deliver_to_pid(payload=payload, timeout=adaptive.next_timeout())
                    rc2, se2 = await self._collect_signals(timeout=adaptive.next_timeout())
                    _dt2 = (time.perf_counter() - t1) * 1000.0
                    ok2, _ = self.classifier.classify(rc2, se2)
                    if not ok2:
                        print("[crash] unstable (second run did not reproduce); skipping")
                        continue

                if self.crash_buckets.seen_before(rc, stderr):
                    print("[crash] duplicate bucket; skipping repro bundle")
                    continue

                # Minimization (optional)
                do_min = os.environ.get("FUZZ_MINIMIZE", "1") == "1"
                min_ms = int(os.environ.get("FUZZ_MINIMIZE_BUDGET_MS", "1200"))
                if do_min:
                    async def pred(b: bytes) -> bool:
                        t0 = time.perf_counter()
                        await self._deliver_to_pid(payload=b, timeout=adaptive.next_timeout())
                        rc2, se2 = await self._collect_signals(timeout=adaptive.next_timeout())
                        dt2 = (time.perf_counter() - t0) * 1000.0
                        ok2, _ = self.classifier.classify(rc2, se2)
                        if ok2:
                            return True
                        if os.environ.get("FUZZ_PROMOTE_HEUR", "0") == "1":
                            hs_tmp = self.HeuristicSignals()
                            hs_tmp.lat_ms = list(self.hsig.lat_ms)
                            hs_tmp.stderr_lens = list(self.hsig.stderr_lens)
                            hs_tmp.rc_hist = dict(self.hsig.rc_hist)
                            suspicious2, _r, _s = hs_tmp.update_and_score(
                                dt_ms=dt2, stderr_len=len(se2 or b""), rc=rc2
                            )
                            return suspicious2
                        return False

                    payload_min = await self.minimize_payload_async(payload, pred, time_budget_ms=min_ms)
                    if len(payload_min) < len(payload):
                        print(f"[min] shrank payload {len(payload)} -> {len(payload_min)} bytes")
                        payload = payload_min

                # Save artifacts & meta
                saved = corpus.save(payload, tag="crash")
                if saved:
                    print(f"[crash] saved payload -> {saved}")
                    try:
                        meta = {
                            "mode": (os.environ.get("FUZZ_PID_MODE", "noop") or "noop"),
                            "pid": pid,
                            "target_for_repro": target_path_for_repro,
                            "rc": rc,
                            "dt_ms": dt_ms,
                            "indicators": indicators,
                            "ts": self.now_stamp(),
                            "tcp_addr": os.environ.get("FUZZ_PID_TCP_ADDR", "127.0.0.1"),
                            "tcp_port": int(os.environ.get("FUZZ_PID_TCP_PORT", "0") or "0"),
                            "pipe_name": os.environ.get("FUZZ_PID_PIPE_NAME", ""),
                            "drop_dir": os.environ.get("FUZZ_PID_DROP_DIR", os.path.join("artifacts", "deliveries")),
                        }
                        with open(saved + ".json", "w", encoding="utf-8") as mf:
                            json.dump(meta, mf, indent=2)
                    except Exception:
                        pass

                    # Build a runnable "deliver" script to replay the same PID transport
                    def _build_pid_repro(payload_path: str) -> str:
                        mode = (os.environ.get("FUZZ_PID_MODE", "noop") or "noop").strip().lower()
                        drop_dir = (os.environ.get("FUZZ_PID_DROP_DIR", os.path.join("artifacts", "deliveries")) or "").strip()
                        tcp_addr = (os.environ.get("FUZZ_PID_TCP_ADDR", "127.0.0.1") or "127.0.0.1").strip()
                        tcp_port = int((os.environ.get("FUZZ_PID_TCP_PORT", "0") or "0").strip() or "0")
                        pipe_name = (os.environ.get("FUZZ_PID_PIPE_NAME", "") or "").strip()
                        append_nl = os.environ.get("FUZZ_PID_TCP_APPEND_NL", "0") == "1"

                        script = f"""#!/usr/bin/env python3
import os, sys, time, socket
mode={mode!r}
payload_path={os.path.abspath(payload_path)!r}
drop_dir={drop_dir!r}
tcp_addr={tcp_addr!r}
tcp_port={tcp_port}
pipe_name={pipe_name!r}
append_nl={str(append_nl)}

def main():
    with open(payload_path, "rb") as f:
        data = f.read()

    if mode == "file":
        os.makedirs(drop_dir, exist_ok=True)
        stamp = str(int(time.time()*1e6))
        out_path = os.path.join(drop_dir, "payload_" + stamp + ".bin")
        with open(out_path, "wb") as w:
            w.write(data)
        with open(out_path + ".meta.json", "w", encoding="utf-8") as mf:
            mf.write('{{"bytes":%d,"timestamp":"%s"}}' % (len(data), stamp))
        print("[repro-pid] wrote", out_path)
        return

    if mode == "file+notify":
        os.makedirs(drop_dir, exist_ok=True)
        stamp = str(int(time.time()*1e6))
        out_path = os.path.join(drop_dir, "payload_" + stamp + ".bin")
        with open(out_path, "wb") as w:
            w.write(data)
        open(out_path + ".trig","wb").close()
        print("[repro-pid] wrote", out_path, "and trigger file")
        return

    if mode == "tcp":
        if not tcp_port:
            print("[repro-pid] tcp port not set"); sys.exit(2)
        with socket.create_connection((tcp_addr, tcp_port), timeout=5.0) as s:
            s.sendall(data)
            if append_nl:
                s.sendall(b"\\n")
        print(f"[repro-pid] sent {{len(data)}} bytes to {{tcp_addr}}:{{tcp_port}}")
        return

    if mode == "pipe":
        import ctypes as C, ctypes.wintypes as W
        kernel32 = C.WinDLL("kernel32", use_last_error=True)
        CreateFileW = kernel32.CreateFileW
        CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE]
        CreateFileW.restype  = W.HANDLE
        WriteFile = kernel32.WriteFile
        WriteFile.argtypes = [W.HANDLE, W.LPCVOID, W.DWORD, C.POINTER(W.DWORD), W.LPVOID]
        WriteFile.restype  = W.BOOL

        if not pipe_name:
            print("[repro-pid] pipe name not set"); sys.exit(2)

        h = CreateFileW(pipe_name, 0x40000000, 0, None, 3, 0, None)  # GENERIC_WRITE, OPEN_EXISTING
        if int(h) == 0 or int(h) == C.c_void_p(-1).value:
            raise OSError(f"CreateFileW failed on {{pipe_name}} (WinErr={{C.get_last_error()}})")
        try:
            n = W.DWORD(0)
            ok = WriteFile(h, data, len(data), C.byref(n), None)
            if not ok or n.value != len(data):
                raise OSError(f"WriteFile to pipe incomplete: {{n.value}}/{{len(data)}} (WinErr={{C.get_last_error()}})")
        finally:
            kernel32.CloseHandle(h)
        print(f"[repro-pid] wrote {{len(data)}} bytes to {{pipe_name}}")
        return

    print(f"[repro-pid] noop: would deliver {{len(data)}} bytes")

if __name__ == "__main__":
    main()
"""
                        out_dir = "crashes"
                        self.ensure_outdir(out_dir)
                        out_path = os.path.join(out_dir, f"deliver_{self.now_stamp()}.py")
                        with open(out_path, "w", encoding="utf-8") as f:
                            f.write(script)
                        try:
                            os.chmod(out_path, 0o755)
                        except Exception:
                            pass
                        return out_path

                    repro_py = _build_pid_repro(saved)

                    print("\n=== PROBABLE VULN (pid) ===")
                    print("Indicators:", ", ".join(indicators))
                    print("[fuzz-pid] Repro bundle:", json.dumps({
                        "payload_bin": saved,
                        "reproducer_py": repro_py
                    }, indent=2))

        print("[fuzz-pid] Completed.")


# ---------------- CLI ----------------
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Async Fuzz + IAT Inspector (Windows)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("fuzz-spawn", help="Fuzz a spawned process")
    sp.add_argument("--target", required=True, help="Path to target executable")
    sp.add_argument("--surface", default="auto", choices=["auto","argv","stdin","env","file"])
    sp.add_argument("--timeout", type=float, default=2.0)
    sp.add_argument("--arg-index", type=int, help="1-based argv index when using argv surface")
    sp.add_argument("--file-arg-index", type=int, help="1-based argv index (path) when using file surface")
    sp.add_argument("--env", action="append", default=[], help="KEY=VALUE (repeatable)")
    sp.add_argument("--iters", type=int, default=64)
    sp.add_argument("--seeds", help="Path to directory (.bin files) or JSON/JSONL with data_b64")
    sp.add_argument("--file-template", choices=["png","zip","json","xml","bmp","wav","gif","jpg","jpeg","pdf","tar","7z"])
    sp.add_argument("--argv-pre", action="append", default=[], help="Prepend fixed argv before payload (repeatable)")
    sp.add_argument("--argv-post", action="append", default=[], help="Append fixed argv after payload (repeatable)")
    sp.add_argument("--promote-heur", action="store_true", help="Promote heuristic spikes to 'probable' crashes")
    sp.add_argument("--no-minimize", action="store_true", help="Disable on-crash minimization")
    sp.add_argument("--profile", help="Target profile JSON (path or URL)")
    sp.add_argument("--max-concurrency", type=int, default=1, help="Concurrent iterations per seed (spawn mode)")

    pp = sub.add_parser("fuzz-pid", help="Fuzz an already-running PID via transports (noop/file/file+notify/tcp/pipe/wmcopydata)")
    pp.add_argument("--pid", type=int, required=True)
    pp.add_argument("--target-for-repro", required=True, help="Local executable to run in generated repro script")
    pp.add_argument("--surface", default="auto", choices=["auto","argv","stdin","env","file"], help="Surface for repro runs")
    pp.add_argument("--timeout", type=float, default=2.0)
    pp.add_argument("--arg-index", type=int)
    pp.add_argument("--file-arg-index", type=int)
    pp.add_argument("--env", action="append", default=[], help="KEY=VALUE (repeatable) passed to repro")
    pp.add_argument("--iters", type=int, default=64)
    pp.add_argument("--seeds", help="Path to directory (.bin files) or JSON/JSONL with data_b64")
    pp.add_argument("--file-template", choices=["png","zip","json","xml","bmp","wav","gif","jpg","jpeg","pdf","tar","7z"])
    pp.add_argument("--autoconfig", action="store_true", help="Infer FUZZ_PID_MODE (tcp/pipe/file) from seed labels")
    pp.add_argument("--avoid-hex", default="", help="Comma/space separated hex bytes to avoid (e.g. '00,0a,0d')")
    pp.add_argument("--profile", help="Target profile JSON (path or URL) for repro hints")

    iat = sub.add_parser("iat", help="List IAT entries for a PID and write artifacts")
    iat.add_argument("--pid", type=int, required=True)
    iat.add_argument("--dll-rgx", help="Regex to filter DLL names")
    iat.add_argument("--func-rgx", help="Regex to filter function names")
    iat.add_argument("--only-ordinal", action="store_true", help="Only imports-by-ordinal")
    iat.add_argument("--base-name", help="Artifacts base name (default auto)")
    iat.add_argument("--preview", type=int, default=50, help="Preview up to N entries")

    eop = sub.add_parser("exe-of-pid", help="Resolve executable path for a PID")
    eop.add_argument("--pid", type=int, required=True)

    return p

def apply_layered_config(args, af: "AsyncFuzzInspector"):
    """
    Builds layered config from files + profile + CLI flags,
    applies it to env/runtime, starts hot-reload, and returns
    (cfg_obj, base_timeout, require_stable).
    """
    profile_blob = load_target_profile(getattr(args, "profile", "")) if getattr(args, "profile", None) else {}

    # What the user typed on CLI should win over files
    cli_over = {}
    if getattr(args, "file_template", None): cli_over["file_template"] = args.file_template
    if getattr(args, "promote_heur", False): cli_over["promote_heur"] = True
    if getattr(args, "no_minimize", False):  cli_over["minimize"] = False
    if getattr(args, "argv_pre", None) is not None:  cli_over["argv_pre"] = args.argv_pre
    if getattr(args, "argv_post", None) is not None: cli_over["argv_post"] = args.argv_post

    cfgm = ConfigManager(live_path="fuzz_config.json",
                         extra_paths=[getattr(args, "profile", None)])
    cfg  = cfgm.load_layers(profile=profile_blob,
                            env_overrides={}, cli_overrides=cli_over)
    cfgm.apply_to_runtime(af)
    cfgm.write_effective_snapshot()
    cfgm.start_hot_reload(profile=profile_blob,
                          env_overrides={}, cli_overrides=cli_over)

    base_timeout   = float(os.environ.get("FUZZ_TIMEOUT_BASE", cfg.timeout))
    require_stable = bool(cfg.require_stable)
    if cfg.promote_heur:
        os.environ["FUZZ_PROMOTE_HEUR"] = "1"

    # If profile suggested a default surface and user left "auto", honor it
    if getattr(args, "surface", "auto") == "auto" and cfg.default_surface:
        args.surface = cfg.default_surface

    return cfg, base_timeout, require_stable


async def main_async(argv: List[str]) -> None:
    args = build_arg_parser().parse_args(argv)

    # Live hotkeys (keep your P/H/M/Arrows) + layered config
    live_cfg = LiveConfig("fuzz_config.json")
    start_hotkeys_thread(live_cfg)
    af = AsyncFuzzInspector()

    cfg, base_timeout, require_stable = apply_layered_config(args, af)

    # Common env toggles
    if getattr(args, "file_template", None):
        os.environ["FUZZ_FILE_TEMPLATE"] = args.file_template
        af.file_template = args.file_template
    if getattr(args, "promote_heur", False):
        os.environ["FUZZ_PROMOTE_HEUR"] = "1"
    if getattr(args, "no_minimize", False):
        os.environ["FUZZ_MINIMIZE"] = "0"

    if getattr(args, "argv_pre", None) is not None:
        os.environ["FUZZ_ARGV_PRE"] = json.dumps(args.argv_pre or [])
        af.pre_args = args.argv_pre or []
    if getattr(args, "argv_post", None) is not None:
        os.environ["FUZZ_ARGV_POST"] = json.dumps(args.argv_post or [])
        af.post_args = args.argv_post or []

    # Profiles (target-aware flags/headers/env/RCs/defaults)
    prof = {}
    prof_src = getattr(args, "profile", None)
    if prof_src:
        prof = load_target_profile(prof_src)
        if prof.get("ignore_rcs") or prof.get("warn_rcs"):
            af.classifier.set_target_overrides(ignore_rcs=set(prof.get("ignore_rcs", [])), warn_rcs=set(prof.get("warn_rcs", [])))
        for fl in prof.get("flags", []) or []:
            b = fl.encode() if isinstance(fl, str) else fl
            if b not in _FLAGS_LIKE: _FLAGS_LIKE.append(b)
        for hk in prof.get("headers", []) or []:
            b = hk.encode() if isinstance(hk, str) else hk
            if b not in _HDR_KEYS: _HDR_KEYS.append(b)
        for ek in prof.get("env_keys", []) or []:
            tok = f"{ek}=".encode()
            if tok not in af.tokens: af.tokens.append(tok)
        if not getattr(args, "file_template", None) and prof.get("file_templates"):
            os.environ["FUZZ_FILE_TEMPLATE"] = prof["file_templates"][0]; af.file_template = prof["file_templates"][0]
        if getattr(args, "surface", "auto") == "auto" and prof.get("default_surface"):
            args.surface = prof["default_surface"]

    # Adaptive timeout base (live-configurable)
    base_timeout = float(os.environ.get("FUZZ_TIMEOUT_BASE", live_cfg.get("timeout", getattr(args, "timeout", 2.0))))

    # Probe help (spawn target or repro target) to harvest flags/headers/env keys
    try:
        if args.cmd == "fuzz-spawn":
            h = probe_cli_help(args.target)
        elif args.cmd == "fuzz-pid":
            h = probe_cli_help(args.target_for_repro)
        else:
            h = {"flags": [], "headers": [], "envs": []}
        for fl in h["flags"]:
            b = fl.encode()
            if b not in _FLAGS_LIKE: _FLAGS_LIKE.append(b)
        for hk in h["headers"]:
            b = hk.encode()
            if b not in _HDR_KEYS: _HDR_KEYS.append(b)
        for ev in h["envs"]:
            tok = f"{ev}=".encode()
            if tok not in af.tokens:
                af.tokens.append(tok)
    except Exception as e:
        print(f"[help-scrape] skipped: {e}")

    # Load and dedupe seeds
    seeds: List[bytes] = []
    labels: List[str] = []
    if getattr(args, "seeds", None):
        try:
            seeds, labels = AsyncFuzzInspector.load_seeds_any(args.seeds)
        except Exception as e:
            print(f"[seeds] failed to load {args.seeds}: {e}")
    if not seeds:
        # Reasonable defaults if no seeds provided
        seeds = [
            b"A" * 64,
            b"--help",
            b"-v",
            b"GET http://localhost/ HTTP/1.1",
            b"Host: localhost",
            b"http://127.0.0.1/?q=AAAA",
        ]
        labels = ["generic"] * len(seeds)
    seeds, labels = AsyncFuzzInspector.dedupe_bytes_with_labels(seeds, labels)

    # Honor live-config flags (if present)
    require_stable = bool(live_cfg.get("require_stable", True))
    # Allow runtime promotion tuning via live cfg
    if live_cfg.get("promote_heur") is True:
        os.environ["FUZZ_PROMOTE_HEUR"] = "1"
    if live_cfg.get("minimize") is False:
        os.environ["FUZZ_MINIMIZE"] = "0"

    # Dispatch commands
    if args.cmd == "fuzz-spawn":
        # Merge env overrides
        env_overrides = parse_env_kv(args.env or [])
        # Update argv pre/post from args already set above
        # Optionally set file template (already applied)
        max_conc = max(1, int(getattr(args, "max_concurrency", 1)))
        await af.fuzz_spawn(
            target_path=args.target,
            surface=args.surface,
            base_timeout=base_timeout,
            arg_index=args.arg_index,
            file_arg_index=args.file_arg_index,
            env_overrides=env_overrides,
            seeds=seeds,
            max_iters=int(args.iters),
            max_concurrency=max_conc,
            require_stable=require_stable,
        )
        return

    if args.cmd == "fuzz-pid":
        # Apply avoid-hex to environment so _mutate_pid can read it
        if args.avoid_hex:
            os.environ["FUZZ_PID_AVOID_HEX"] = args.avoid_hex

        # Profile hints (already loaded into 'prof'); autoconfig transport from labels if asked
        if args.autoconfig:
            AsyncFuzzInspector.maybe_autoconfig_transport_from_labels(labels)

        env_overrides = parse_env_kv(args.env or [])
        await af.fuzz_pid(
            pid=int(args.pid),
            target_path_for_repro=args.target_for_repro,
            surface=args.surface,
            base_timeout=base_timeout,
            arg_index=args.arg_index,
            file_arg_index=args.file_arg_index,
            env_overrides=env_overrides,
            seeds=seeds,
            labels=labels,
            max_iters=int(args.iters),
            require_stable=require_stable,
        )
        return

    if args.cmd == "iat":
        pid = int(args.pid)
        base_name = args.base_name or f"iat_{pid}_{AsyncFuzzInspector.now_stamp()}"
        insp = AsyncFuzzInspector.ProcessImportsInspector(pid)
        try:
            entries = insp.enumerate_imports_main_only()
        finally:
            insp.close()

        entries = AsyncFuzzInspector.filter_entries(
            entries,
            dll_rgx=args.dll_rgx,
            func_rgx=args.func_rgx,
            only_ordinal=bool(args.only_ordinal),
        )
        out_paths = AsyncFuzzInspector.write_artifacts(base_name, entries)
        AsyncFuzzInspector.print_preview(entries, limit=int(args.preview))
        print(f"[iat] wrote: {out_paths['json']} and {out_paths['csv']}")
        return

    if args.cmd == "exe-of-pid":
        pid = int(args.pid)
        try:
            path = AsyncFuzzInspector.get_exe_path_from_pid(pid)
            print(path)
        except Exception as e:
            print(f"[exe-of-pid] error: {e}")
        return


def main() -> None:
    try:
        asyncio.run(main_async(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")


if __name__ == "__main__":
    main()
