#!/usr/bin/env python3
"""
Steganography Comparison Utility
Compares original and encoded images to show the steganography is invisible.

CMU Heinz College - 95-759 Malicious Code Analysis
Group Project: Steganography-Based C2 Channel

Usage:
    python compare.py <original_image> <encoded_image>

Example:
    python compare.py images/original.png images/encoded.png
"""

import argparse
import hashlib
import os
import sys

from PIL import Image


def compute_hash(filepath, algorithm='md5'):
    """Compute a hash of a file."""
    h = hashlib.new(algorithm)
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def compare_images(original_path, encoded_path):
    """Compare original and encoded images with forensic detail."""

    # Verify files exist
    for path in [original_path, encoded_path]:
        if not os.path.exists(path):
            print(f"[-] ERROR: File not found: {path}")
            sys.exit(1)

    # ===== FILE SIZE COMPARISON =====
    size1 = os.path.getsize(original_path)
    size2 = os.path.getsize(encoded_path)
    size_diff = abs(size2 - size1)

    print("[*] FILE SIZE COMPARISON")
    print("=" * 60)
    print(f"  Original: {original_path} ({size1:,} bytes)")
    print(f"  Encoded:  {encoded_path} ({size2:,} bytes)")
    print(f"  Size difference: {size_diff:,} bytes")
    print()

    # ===== HASH COMPARISON =====
    md5_orig = compute_hash(original_path, 'md5')
    md5_enc = compute_hash(encoded_path, 'md5')
    sha256_orig = compute_hash(original_path, 'sha256')
    sha256_enc = compute_hash(encoded_path, 'sha256')

    print("[*] HASH COMPARISON")
    print("=" * 60)
    print(f"  Original MD5:    {md5_orig}")
    print(f"  Encoded  MD5:    {md5_enc}")
    print(f"  MD5 Match: {'YES' if md5_orig == md5_enc else 'NO (expected - bits were modified)'}")
    print()
    print(f"  Original SHA256: {sha256_orig}")
    print(f"  Encoded  SHA256: {sha256_enc}")
    print(f"  SHA256 Match: {'YES' if sha256_orig == sha256_enc else 'NO (expected - bits were modified)'}")
    print()

    # ===== PIXEL-LEVEL COMPARISON =====
    img1 = Image.open(original_path).convert('RGB')
    img2 = Image.open(encoded_path).convert('RGB')

    if img1.size != img2.size:
        print("[-] WARNING: Images have different dimensions!")
        print(f"    Original: {img1.size}")
        print(f"    Encoded:  {img2.size}")
        return

    pixels1 = img1.load()
    pixels2 = img2.load()
    width, height = img1.size
    total_pixels = width * height

    changed_pixels = 0
    max_channel_diff = 0
    total_channel_diff = 0
    channels_changed = 0

    for y in range(height):
        for x in range(width):
            r1, g1, b1 = pixels1[x, y]
            r2, g2, b2 = pixels2[x, y]

            pixel_changed = False
            for c1, c2 in [(r1, r2), (g1, g2), (b1, b2)]:
                diff = abs(c2 - c1)
                if diff > 0:
                    pixel_changed = True
                    channels_changed += 1
                    total_channel_diff += diff
                    max_channel_diff = max(max_channel_diff, diff)

            if pixel_changed:
                changed_pixels += 1

    pct_changed = (changed_pixels / total_pixels) * 100 if total_pixels > 0 else 0
    avg_diff = total_channel_diff / channels_changed if channels_changed > 0 else 0

    print("[*] PIXEL-LEVEL COMPARISON")
    print("=" * 60)
    print(f"  Image dimensions: {width}x{height}")
    print(f"  Total pixels: {total_pixels:,}")
    print(f"  Pixels modified: {changed_pixels:,} / {total_pixels:,} ({pct_changed:.4f}%)")
    print(f"  Channels modified: {channels_changed:,} / {total_pixels * 3:,}")
    print(f"  Max channel difference: {max_channel_diff} (out of 255)")
    print(f"  Avg channel difference: {avg_diff:.2f}")
    print()

    if max_channel_diff <= 1:
        print("  [+] VERDICT: Changes are imperceptible to the human eye.")
        print("      Maximum difference of 1 in any channel is invisible.")
    else:
        print(f"  [!] WARNING: Max channel difference is {max_channel_diff}.")
        print("      This should be 0 or 1 for proper LSB steganography.")
    print()

    # ===== GENERATE DIFFERENCE IMAGE =====
    print("[*] GENERATING DIFFERENCE IMAGE")
    print("=" * 60)

    diff_img = Image.new('RGB', (width, height), (0, 0, 0))
    diff_pixels = diff_img.load()

    for y in range(height):
        for x in range(width):
            r1, g1, b1 = pixels1[x, y]
            r2, g2, b2 = pixels2[x, y]

            # Amplify differences by 128x so they're visible
            dr = min(abs(r2 - r1) * 128, 255)
            dg = min(abs(g2 - g1) * 128, 255)
            db = min(abs(b2 - b1) * 128, 255)

            diff_pixels[x, y] = (dr, dg, db)

    # Save difference image
    diff_path = os.path.join(os.path.dirname(encoded_path), "difference.png")
    diff_img.save(diff_path, 'PNG')
    print(f"  [+] Difference image saved: {diff_path}")
    print("      (Pixel differences amplified 128x for visibility)")
    print("      White/bright pixels = modified, black = unchanged")


def main():
    parser = argparse.ArgumentParser(
        description="Compare original and encoded steganography images",
        epilog="Example: python compare.py images/original.png images/encoded.png"
    )
    parser.add_argument("original", help="Path to the original (clean) image")
    parser.add_argument("encoded", help="Path to the encoded (stego) image")

    args = parser.parse_args()

    print()
    print("=" * 60)
    print("  STEGANOGRAPHY COMPARISON - Forensic Analysis")
    print("=" * 60)
    print()

    compare_images(args.original, args.encoded)

    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
