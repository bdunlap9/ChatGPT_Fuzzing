#!/usr/bin/env python3
# Windows-only helper to build a "seed bin" based on a PID's observed IPC surfaces.
# - Detects TCP listeners for the PID (via psutil or netstat fallback)
# - Generates deterministic, varied payloads per port
# - Emits a seeds/ directory tree + a seeds_manifest.json that maps seeds -> surfaces
# - Optionally exports a single import file (--export-jsonl / --export-json) suitable for --seeds <file>
#
# Usage:
#   python seed_generator.py <PID> [--out seeds] [--per-port 16] [--max-grow 1024] [--http-guess]
#        [--avoid-hex "00,0a,0d"] [--export-jsonl out.jsonl] [--export-json out.json]
#
# Notes:
# - Named pipes are not enumerated here; generic seeds are provided for pipe/file delivery.
# - No injection or process writes are performed.

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# -------- optional psutil import --------
try:
    import psutil  # type: ignore
    HAVE_PSUTIL = True
except Exception:
    HAVE_PSUTIL = False

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

# -------- discover TCP listeners for a PID --------
def discover_listeners_psutil(pid: int) -> List[int]:
    ports: List[int] = []
    for c in psutil.net_connections(kind="tcp"):
        if c.pid == pid and str(getattr(c, "status", "")).upper() == "LISTEN":
            laddr = getattr(c, "laddr", None)
            if laddr and hasattr(laddr, "port"):
                ports.append(int(laddr.port))
    return sorted(list(set(ports)))

def discover_listeners_netstat(pid: int) -> List[int]:
    """
    Fallback: parse `netstat -ano` (Windows). Collect TCP LISTENING rows for this PID.
    """
    try:
        out = subprocess.check_output(["netstat", "-ano"], text=True, stderr=subprocess.DEVNULL, encoding="utf-8", errors="ignore")
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

# -------- seed generation --------
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
    Deterministic, length-bounded mutations (mirrors your skeleton styles).
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

def canned_seeds(http_like: bool=False) -> List[bytes]:
    seeds: List[bytes] = []
    if http_like:
        seeds += [
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            b"POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nAAAA",
            b"HEAD /aaaa HTTP/1.1\r\nHost: localhost\r\n\r\n",
        ]
    seeds += [
        b"A"*16, b"A"*64, b"A"*256,
        b"\x00"*16, b"\xff"*32,
        b"%x%x%x%n", b"{0}{1}{2}",
        ("𝔸" * 16).encode("utf-8"),           # <-- fixed (no stray space)
        b"\x01\x02\x7f\xff/\x5c..%$'\"\x00\x0a\x0d",
    ]
    body = b"B"*32
    seeds.append(len(body).to_bytes(2,"big")+body)  # simple length-prefixed
    return seeds

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
    ap.add_argument("--per-port", type=int, default=16, help="Mutated seeds per discovered port")
    ap.add_argument("--max-grow", type=int, default=1024, help="Max growth per mutation")
    ap.add_argument("--avoid-hex", default="", help="Comma/space-separated hex bytes to avoid (e.g. '00,0a,0d')")
    ap.add_argument("--http-guess", action="store_true", help="If a port looks like HTTP (80/8080/8000/443/3000), add HTTP-ish seeds")
    ap.add_argument("--export-jsonl", default=None, help="Write a single JSONL seeds file (one record per line).")
    ap.add_argument("--export-json",  default=None, help="Write a single JSON seeds file with a 'seeds' array.")
    args = ap.parse_args()

    if os.name != "nt":
        print("[!] This helper is intended for Windows.")
        # Not exiting so it can still write seeds if run elsewhere.

    out_root = Path(args.out)
    ensure_dir(out_root)

    # discover surfaces (TCP listeners)
    ports = discover_tcp_listeners(args.pid)

    # parse avoid set
    avoid_set = {int(t, 16) & 0xFF for t in re.split(r"[,\s]+", args.avoid_hex) if t} if args.avoid_hex else set()

    manifest: Dict = {
        "pid": args.pid,
        "created_at": now_stamp(),
        "out_root": str(out_root.resolve()),
        "ports": [],
        "generic": [],
        "notes": [
            "Seeds are deterministic across runs for the same (seed, iteration).",
            "Named pipes not auto-discovered; use generic seeds for pipe/file fuzzing.",
            "HTTP-like seeds added if --http-guess and port is commonly HTTP."
        ]
    }

    # Per-port seeds
    for port in ports:
        httpish = args.http_guess and port in (80, 8080, 8000, 443, 3000)
        bucket = out_root / f"pid_{args.pid}" / "tcp" / f"port_{port}"
        ensure_dir(bucket)

        # Start with canned seeds
        base = canned_seeds(http_like=httpish)

        # Mutate each canned seed deterministically
        mutated: List[bytes] = []
        # evenly fill to per-port count
        per = max(1, args.per_port)
        idx = 0
        while len(mutated) < per:
            s = base[idx % len(base)]
            it = idx  # simple increasing iteration
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

    # Generic seeds for pipe/file/stdin surfaces
    generic_bucket = out_root / f"pid_{args.pid}" / "generic"
    ensure_dir(generic_bucket)
    gen_seeds = canned_seeds(http_like=False)
    # add deterministic mutations of the first generic seed
    extra = [mutate(gen_seeds[0], i, args.max_grow, avoid_set) for i in range(12)]
    gen_paths = write_seed_files(generic_bucket, "generic", gen_seeds + extra)
    manifest["generic"] = {
        "surface": ["pipe", "file", "stdin"],
        "dir": str(generic_bucket.resolve()),
        "count": len(gen_paths),
        "seeds": [p.name for p in gen_paths],
    }

    # Write manifest
    manifest_path = out_root / f"pid_{args.pid}" / "seeds_manifest.json"
    ensure_dir(manifest_path.parent)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    # Collect all seeds we just wrote into records for optional export
    records = []
    for port_info in manifest["ports"]:
        port_dir = Path(port_info["dir"])
        for name in port_info["seeds"]:
            records.append(seed_record(port_dir / name, f"tcp:{port_info['port']}"))

    gen_dir = Path(manifest["generic"]["dir"])
    for name in manifest["generic"]["seeds"]:
        records.append(seed_record(gen_dir / name, "generic"))

    meta = {
        "pid": args.pid,
        "created_at": manifest["created_at"],
        "note": "base64-encoded seeds; 'label' hints surface (tcp:<port> or generic)"
    }

    print("\n[+] Seed bin created")
    print(f"    PID: {args.pid}")
    print(f"    Root: {out_root.resolve()}")
    if ports:
        print(f"    TCP listeners discovered: {', '.join(map(str, ports))}")
    else:
        print("    TCP listeners discovered: (none)")
    print(f"    Manifest: {manifest_path.resolve()}")

    if args.export_jsonl:
        write_jsonl(records, Path(args.export_jsonl))
        print(f"    Exported JSONL: {Path(args.export_jsonl).resolve()}")

    if args.export_json:
        write_json(records, Path(args.export_json), meta)
        print(f"    Exported JSON : {Path(args.export_json).resolve()}")

    print("    Use the 'generic' seeds for named pipes or file-drop delivery.\n")

if __name__ == "__main__":
    main()
