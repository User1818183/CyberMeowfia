#!/usr/bin/env python3
import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


KIMAGE_TEXT_BASE = 0xFFFFFFC080000000


# canonical_name -> possible real symbol names in different kernel versions
SYMBOL_ALIASES = {
    "copy_splice_read": [
        "copy_splice_read",
        "direct_splice_read",   # older kernels
    ],

    "filemap_splice_read": [
        "filemap_splice_read",
        "generic_file_splice_read",  # older kernels
    ],

    "do_splice": [
        "do_splice",
    ],

    "splice_file_to_pipe": [
        "splice_file_to_pipe",
    ],

    "iter_file_splice_write": [
        "iter_file_splice_write",
    ],

    "seq_read_iter": [
        "seq_read_iter",
    ],

    "configfs_detach_prep": [
        "configfs_detach_prep",
    ],
}


REQUIRED_SYMBOLS = [
    "copy_splice_read",
    "filemap_splice_read",
    "do_splice",
    "splice_file_to_pipe",
    "iter_file_splice_write",
    "seq_read_iter",
    "configfs_detach_prep",
]


def log(msg):
    print(msg, flush=True)


def die(msg, code=1):
    print(f"[-] Error: {msg}", file=sys.stderr, flush=True)
    sys.exit(code)


def run_cmd(cmd):
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"{cmd[0]} not found"


def find_tool(names):
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    return None


def validate_vmlinux(path: Path):
    if not path.exists():
        die(f"vmlinux not found: {path}")

    if not path.is_file():
        die(f"not a file: {path}")

    size = path.stat().st_size
    if size < 1024 * 1024:
        die(f"vmlinux is too small: {size} bytes")

    file_tool = find_tool(["file"])
    if file_tool:
        rc, out, err = run_cmd([file_tool, str(path)])
        if rc == 0:
            log(f"[*] file: {out.strip()}")
            if "ELF" not in out:
                die("input is not an ELF file")
        else:
            log(f"[!] file check failed: {err.strip()}")

    readelf = find_tool(["readelf", "llvm-readelf"])
    if readelf:
        rc, out, err = run_cmd([readelf, "-h", str(path)])
        if rc != 0:
            die(f"readelf failed: {err.strip()}")

        if "ELF64" not in out:
            die("vmlinux is not ELF64")

        if "AArch64" not in out and "ARM aarch64" not in out:
            log("[!] Warning: ELF machine does not look like AArch64")

    log("[+] vmlinux validation passed")


def parse_nm_output(text):
    symbols = {}

    # Example:
    # ffffffc080123456 T copy_splice_read
    # 0000000000000000 t local_symbol
    rx = re.compile(r"^([0-9a-fA-F]+)\s+([a-zA-Z])\s+(\S+)$")

    for line in text.splitlines():
        line = line.strip()
        m = rx.match(line)
        if not m:
            continue

        addr_s, sym_type, name = m.groups()

        try:
            addr = int(addr_s, 16)
        except ValueError:
            continue

        symbols[name] = {
            "addr": addr,
            "type": sym_type,
        }

    return symbols


def parse_readelf_symbols(text):
    symbols = {}

    # Example:
    # 12345: ffffffc080123456   120 FUNC GLOBAL DEFAULT 1 copy_splice_read
    rx = re.compile(
        r"^\s*\d+:\s+([0-9a-fA-F]+)\s+\d+\s+(\S+)\s+\S+\s+\S+\s+\S+\s+(\S+)$"
    )

    for line in text.splitlines():
        m = rx.match(line)
        if not m:
            continue

        addr_s, sym_type, name = m.groups()

        if sym_type not in ("FUNC", "OBJECT", "NOTYPE"):
            continue

        try:
            addr = int(addr_s, 16)
        except ValueError:
            continue

        symbols[name] = {
            "addr": addr,
            "type": sym_type,
        }

    return symbols


def extract_symbols_with_nm(vmlinux):
    tools = [
        ["llvm-nm", "-n", str(vmlinux)],
        ["aarch64-linux-gnu-nm", "-n", str(vmlinux)],
        ["nm", "-n", str(vmlinux)],
    ]

    for cmd in tools:
        if not find_tool([cmd[0]]):
            continue

        log(f"[*] Trying symbols with: {' '.join(cmd)}")
        rc, out, err = run_cmd(cmd)

        if rc != 0:
            log(f"[!] {cmd[0]} failed: {err.strip()}")
            continue

        symbols = parse_nm_output(out)

        if symbols:
            log(f"[+] Extracted {len(symbols)} symbols using {cmd[0]}")
            return symbols

        log(f"[!] {cmd[0]} returned no usable symbols")

    return {}


def extract_symbols_with_readelf(vmlinux):
    tools = [
        ["llvm-readelf", "-sW", str(vmlinux)],
        ["readelf", "-sW", str(vmlinux)],
    ]

    for cmd in tools:
        if not find_tool([cmd[0]]):
            continue

        log(f"[*] Trying symbols with: {' '.join(cmd)}")
        rc, out, err = run_cmd(cmd)

        if rc != 0:
            log(f"[!] {cmd[0]} failed: {err.strip()}")
            continue

        symbols = parse_readelf_symbols(out)

        if symbols:
            log(f"[+] Extracted {len(symbols)} symbols using {cmd[0]}")
            return symbols

        log(f"[!] {cmd[0]} returned no usable symbols")

    return {}


def extract_symbols(vmlinux):
    symbols = extract_symbols_with_nm(vmlinux)

    if symbols:
        return symbols

    log("[!] nm did not extract symbols, trying readelf...")
    symbols = extract_symbols_with_readelf(vmlinux)

    if symbols:
        return symbols

    die(
        "No symbols extracted from vmlinux. "
        "Make sure this is an unstripped debug vmlinux with .symtab."
    )


def resolve_symbol(symbols, canonical_name):
    aliases = SYMBOL_ALIASES.get(canonical_name, [canonical_name])

    for real_name in aliases:
        if real_name in symbols:
            return real_name, symbols[real_name]["addr"]

    return None, None


def symbol_to_define_name(symbol):
    return symbol.upper() + "_OFF"


def calc_offset(addr, base):
    if addr < base:
        # Some vmlinux builds may already use low linked addresses.
        # In that case keep raw address as offset-like value.
        return addr

    return addr - base


def generate_header(found, missing, base):
    lines = []

    lines.append("/* Auto-generated by extract_kernel_offsets.py */")
    lines.append("#pragma once")
    lines.append("")
    lines.append(f"#define KIMAGE_TEXT_BASE 0x{base:x}UL")
    lines.append("")

    for item in found:
        canonical = item["canonical"]
        real = item["real"]
        addr = item["addr"]
        off = item["offset"]
        define = symbol_to_define_name(canonical)

        lines.append(f"/* {canonical} resolved as {real} @ 0x{addr:x} */")
        lines.append(f"#define {define} 0x{off:x}UL")
        lines.append("")

    if missing:
        lines.append("/* Missing symbols:")
        for name in missing:
            aliases = ", ".join(SYMBOL_ALIASES.get(name, [name]))
            lines.append(f" * {name}: tried {aliases}")
        lines.append(" */")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Extract required kernel symbol offsets from debug vmlinux"
    )

    parser.add_argument(
        "vmlinux",
        help="Path to unstripped debug vmlinux",
    )

    parser.add_argument(
        "output",
        help="Output header path, for example extracted_offsets.h",
    )

    parser.add_argument(
        "--base",
        default=hex(KIMAGE_TEXT_BASE),
        help=f"Kernel text base, default {hex(KIMAGE_TEXT_BASE)}",
    )

    parser.add_argument(
        "--allow-missing",
        action="store_true",
        help="Generate header even if some symbols are missing",
    )

    args = parser.parse_args()

    vmlinux = Path(args.vmlinux)
    output = Path(args.output)

    try:
        base = int(str(args.base), 0)
    except ValueError:
        die(f"invalid --base value: {args.base}")

    log(f"[*] Extracting offsets from: {vmlinux}")
    log(f"[*] Using KIMAGE_TEXT_BASE: 0x{base:x}")

    validate_vmlinux(vmlinux)

    symbols = extract_symbols(vmlinux)

    found = []
    missing = []

    for canonical in REQUIRED_SYMBOLS:
        real, addr = resolve_symbol(symbols, canonical)

        if real is None:
            log(f"[-] Missing symbol: {canonical}")
            missing.append(canonical)
            continue

        off = calc_offset(addr, base)

        log(
            f"[+] {canonical}: resolved as {real}, "
            f"addr=0x{addr:x}, off=0x{off:x}"
        )

        found.append({
            "canonical": canonical,
            "real": real,
            "addr": addr,
            "offset": off,
        })

    if missing and not args.allow_missing:
        log("")
        log("[-] Missing required symbols:")
        for name in missing:
            aliases = ", ".join(SYMBOL_ALIASES.get(name, [name]))
            log(f"    {name}: tried {aliases}")

        die("required symbols missing. Use --allow-missing only if this is expected.")

    output.parent.mkdir(parents=True, exist_ok=True)

    header = generate_header(found, missing, base)
    output.write_text(header + "\n", encoding="utf-8")

    log("")
    log(f"[+] Wrote header: {output}")
    log(f"[+] Found symbols: {len(found)}")
    log(f"[+] Missing symbols: {len(missing)}")


if __name__ == "__main__":
    main()
