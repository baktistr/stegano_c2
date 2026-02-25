#!/usr/bin/env python3
"""
Steganography Detector - Blue Team Analysis Tool
Detects both LSB steganography and EOF payload appending in PNG images.

This demonstrates detection techniques that defenders can use to identify
steganographic C2 channels. Shows why each technique works AND how it
can be caught.

Detection Methods:
  1. EOF Analysis: Check for data appended after PNG IEND chunk
  2. LSB Statistical Analysis: Chi-squared test on LSB distribution
  3. Entropy Analysis: Detect unusual randomness in LSB plane
  4. File Structure Validation: Verify PNG chunk integrity

CMU Heinz College - 95-759 Malicious Code Analysis
Group Project: Steganography-Based C2 Channel

Usage:
    python stego_detector.py <image_path> [--verbose]

Examples:
    python stego_detector.py images/original.png
    python stego_detector.py images/encoded.png --verbose
    python stego_detector.py images/embedded_eof.png
"""

import argparse
import hashlib
import math
import os
import struct
import sys
from collections import Counter

from PIL import Image


# PNG constants
PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'
PNG_IEND_MARKER = b'\x00\x00\x00\x00IEND\xaeB`\x82'


def analyze_eof(image_data, verbose=False):
    """Check for data appended after the PNG IEND chunk."""
    print("\n[1] EOF ANALYSIS (Detects: hide-payload-in-images / Adaptix C2 technique)")
    print("-" * 60)

    if image_data[:8] != PNG_SIGNATURE:
        print("  [-] Not a valid PNG file")
        return False

    iend_pos = image_data.find(PNG_IEND_MARKER)
    if iend_pos == -1:
        print("  [-] No IEND chunk found (corrupted PNG?)")
        return False

    iend_end = iend_pos + len(PNG_IEND_MARKER)
    total_size = len(image_data)
    trailing_bytes = total_size - iend_end

    print(f"  IEND chunk ends at: byte {iend_end}")
    print(f"  Total file size:    {total_size:,} bytes")
    print(f"  Trailing bytes:     {trailing_bytes}")

    if trailing_bytes > 0:
        print()
        print(f"  [!!] DETECTED: {trailing_bytes:,} bytes found AFTER IEND chunk!")
        print(f"  [!!] This is a strong indicator of EOF payload embedding.")

        # Try to read size header
        if trailing_bytes >= 4:
            potential_size = struct.unpack('<I', image_data[iend_end:iend_end + 4])[0]
            if 0 < potential_size <= trailing_bytes - 4:
                print(f"  [!!] Size header detected: payload claims {potential_size:,} bytes")
                print(f"  [!!] Matches hide-payload-in-images embedding format!")

        if verbose:
            # Show hex dump of trailing data
            preview = image_data[iend_end:iend_end + min(64, trailing_bytes)]
            print(f"\n  Hex dump of trailing data (first {len(preview)} bytes):")
            for i in range(0, len(preview), 16):
                hex_part = ' '.join(f'{b:02x}' for b in preview[i:i+16])
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in preview[i:i+16])
                print(f"    {i:04x}: {hex_part:<48s} {ascii_part}")

        return True
    else:
        print("  [OK] No data after IEND chunk.")
        return False


def analyze_lsb_statistics(image_path, verbose=False):
    """Statistical analysis of LSB plane to detect LSB steganography."""
    print("\n[2] LSB STATISTICAL ANALYSIS (Detects: LSB steganography / encoder.py technique)")
    print("-" * 60)

    img = Image.open(image_path).convert('RGB')
    pixels = img.load()
    width, height = img.size

    # Collect LSBs from all channels
    lsb_values = []
    channel_lsbs = {'R': [], 'G': [], 'B': []}

    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            lsb_values.extend([r & 1, g & 1, b & 1])
            channel_lsbs['R'].append(r & 1)
            channel_lsbs['G'].append(g & 1)
            channel_lsbs['B'].append(b & 1)

    total = len(lsb_values)
    ones = sum(lsb_values)
    zeros = total - ones

    # Expected: natural images have roughly 50/50 LSB distribution
    # but with slight bias. Stego images tend to be extremely close to 50/50
    ratio = ones / total if total > 0 else 0

    print(f"  Total LSBs analyzed: {total:,}")
    print(f"  LSB=0: {zeros:,} ({zeros/total*100:.2f}%)")
    print(f"  LSB=1: {ones:,} ({ones/total*100:.2f}%)")
    print(f"  Ratio (1s/total): {ratio:.6f}")

    # Chi-squared test for uniformity
    expected = total / 2
    chi_sq = ((ones - expected) ** 2 / expected) + ((zeros - expected) ** 2 / expected)
    print(f"  Chi-squared statistic: {chi_sq:.4f}")

    # Per-channel analysis
    if verbose:
        print("\n  Per-channel LSB distribution:")
        for channel_name, lsbs in channel_lsbs.items():
            ch_total = len(lsbs)
            ch_ones = sum(lsbs)
            ch_ratio = ch_ones / ch_total if ch_total > 0 else 0
            print(f"    {channel_name}: {ch_ones}/{ch_total} ones ({ch_ratio:.4f})")

    # Detect anomalies
    # A perfectly random (embedded) LSB plane will have ratio very close to 0.5
    # Natural images typically show slight bias
    suspicious = False
    if chi_sq < 0.5:
        print(f"\n  [!!] SUSPICIOUS: LSB distribution is unusually uniform (chi²={chi_sq:.4f})")
        print(f"  [!!] Natural images typically show more LSB bias.")
        print(f"  [!!] This may indicate LSB steganography embedding.")
        suspicious = True
    else:
        print(f"\n  [OK] LSB distribution appears natural (chi²={chi_sq:.4f})")

    return suspicious


def analyze_lsb_entropy(image_path, block_size=1000, verbose=False):
    """Measure entropy of LSB plane in blocks to detect embedding regions."""
    print("\n[3] LSB ENTROPY ANALYSIS (Detects: partial embedding patterns)")
    print("-" * 60)

    img = Image.open(image_path).convert('RGB')
    pixels = img.load()
    width, height = img.size

    # Collect all LSBs in pixel order (same as encoder)
    all_lsbs = []
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            all_lsbs.extend([r & 1, g & 1, b & 1])

    total_lsbs = len(all_lsbs)

    # Calculate entropy in blocks
    block_entropies = []
    for start in range(0, total_lsbs, block_size):
        block = all_lsbs[start:start + block_size]
        if len(block) < block_size // 2:
            break

        ones = sum(block)
        zeros = len(block) - ones
        total = len(block)

        # Shannon entropy
        entropy = 0
        for count in [ones, zeros]:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)

        block_entropies.append(entropy)

    if not block_entropies:
        print("  Image too small for block analysis.")
        return False

    avg_entropy = sum(block_entropies) / len(block_entropies)
    max_entropy = max(block_entropies)
    min_entropy = min(block_entropies)

    # Check for entropy discontinuity (embedded region vs natural region)
    # The first N blocks covering the embedded message will have different
    # entropy than the remaining natural blocks
    print(f"  Block size: {block_size} LSBs")
    print(f"  Total blocks: {len(block_entropies)}")
    print(f"  Entropy range: {min_entropy:.4f} - {max_entropy:.4f}")
    print(f"  Average entropy: {avg_entropy:.4f}")
    print(f"  Max possible entropy: 1.0000 (perfectly random)")

    # Look for entropy transition point
    if verbose and len(block_entropies) > 5:
        print("\n  Block entropy samples (first 10, last 5):")
        for i, e in enumerate(block_entropies[:10]):
            marker = " <<<" if e > 0.99 else ""
            print(f"    Block {i:4d}: {e:.4f}{marker}")
        if len(block_entropies) > 15:
            print("    ...")
        for i in range(max(10, len(block_entropies) - 5), len(block_entropies)):
            marker = " <<<" if block_entropies[i] > 0.99 else ""
            print(f"    Block {i:4d}: {block_entropies[i]:.4f}{marker}")

    # Detect entropy DISCONTINUITIES (sign of partial embedding).
    # Natural images have relatively consistent LSB entropy throughout.
    # LSB steganography creates a sharp transition: embedded region has
    # maximum entropy, then it drops to natural entropy.
    # We look for a significant entropy variance or step change.
    suspicious = False

    if len(block_entropies) > 10:
        # Check for a sharp transition (step change) in entropy
        diffs = [abs(block_entropies[i+1] - block_entropies[i]) for i in range(len(block_entropies) - 1)]
        max_step = max(diffs) if diffs else 0
        avg_step = sum(diffs) / len(diffs) if diffs else 0

        # Also check variance: uniform entropy = natural or fully embedded
        mean_e = sum(block_entropies) / len(block_entropies)
        variance = sum((e - mean_e) ** 2 for e in block_entropies) / len(block_entropies)

        if verbose:
            print(f"\n  Entropy variance: {variance:.6f}")
            print(f"  Max step change: {max_step:.4f}")
            print(f"  Avg step change: {avg_step:.6f}")

        if max_step > 0.15 and variance > 0.005:
            # Sharp step + high variance = partial embedding
            step_idx = diffs.index(max_step)
            print(f"\n  [!!] SUSPICIOUS: Sharp entropy transition at block {step_idx}")
            print(f"  [!!] Step magnitude: {max_step:.4f} (threshold: 0.15)")
            print(f"  [!!] This pattern suggests partial LSB embedding ended at that point.")
            suspicious = True
        elif variance < 0.0001 and mean_e > 0.95:
            print(f"\n  [OK] Uniformly high LSB entropy (typical of natural photos).")
        else:
            print(f"\n  [OK] Entropy distribution appears natural (variance={variance:.6f}).")

    return suspicious


def analyze_file_metadata(image_path, verbose=False):
    """Basic file metadata analysis."""
    print("\n[4] FILE METADATA ANALYSIS")
    print("-" * 60)

    file_size = os.path.getsize(image_path)
    img = Image.open(image_path)

    print(f"  File path: {image_path}")
    print(f"  File size: {file_size:,} bytes")
    print(f"  Image format: {img.format}")
    print(f"  Image mode: {img.mode}")
    print(f"  Image size: {img.size[0]}x{img.size[1]}")

    # Hash
    with open(image_path, 'rb') as f:
        data = f.read()
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()

    print(f"  MD5:    {md5}")
    print(f"  SHA256: {sha256}")

    if verbose:
        # Check pixel capacity for LSB steganography
        w, h = img.size
        capacity_bits = w * h * 3
        capacity_bytes = capacity_bits // 8
        print(f"\n  LSB steganography capacity: {capacity_bytes:,} bytes ({capacity_bits:,} bits)")

    return False


def main():
    parser = argparse.ArgumentParser(
        description="Steganography Detector - Detect LSB and EOF steganography in PNG images",
        epilog="Example: python stego_detector.py images/encoded.png --verbose"
    )
    parser.add_argument("image", help="Path to the PNG image to analyze")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed analysis")

    args = parser.parse_args()

    if not os.path.exists(args.image):
        print(f"[-] ERROR: File not found: {args.image}")
        sys.exit(1)

    print()
    print("=" * 60)
    print("  STEGANOGRAPHY DETECTOR - Blue Team Analysis Tool")
    print("=" * 60)
    print(f"\n  Target: {args.image}")

    # Read raw file data for EOF analysis
    with open(args.image, 'rb') as f:
        image_data = f.read()

    findings = []

    # Run all detection methods
    if analyze_eof(image_data, args.verbose):
        findings.append("EOF payload appending (hide-payload-in-images technique)")

    if analyze_lsb_statistics(args.image, args.verbose):
        findings.append("LSB distribution anomaly (possible LSB steganography)")

    if analyze_lsb_entropy(args.image, verbose=args.verbose):
        findings.append("LSB entropy anomaly (possible partial LSB embedding)")

    analyze_file_metadata(args.image, args.verbose)

    # Summary
    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)

    if findings:
        print(f"\n  [!!] {len(findings)} potential indicator(s) detected:\n")
        for i, finding in enumerate(findings, 1):
            print(f"    {i}. {finding}")
        print()
        print("  Recommendation: Further manual analysis recommended.")
        print("  Compare against known-clean version of this image if available.")
    else:
        print("\n  [OK] No steganography indicators detected.")
        print("  Note: Absence of indicators does not guarantee image is clean.")
        print("  Advanced techniques may evade these basic detection methods.")

    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
