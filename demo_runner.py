#!/usr/bin/env python3
"""
Full Demo Runner - Side-by-side comparison of both steganography techniques.

Runs the complete pipeline for both methods and shows detection results.
Perfect for the live presentation - one script, full demo.

Technique 1 (LSB): encoder.py → server.py → decoder.py
Technique 2 (EOF): payload_embedder.py → server.py → payload_extractor.py

CMU Heinz College - 95-759 Malicious Code Analysis
Group Project: Steganography-Based C2 Channel

Usage:
    python demo_runner.py [--command COMMAND]
"""

import argparse
import os
import subprocess
import sys
import time


def banner(text):
    print()
    print("█" * 64)
    print(f"█  {text:^58s}  █")
    print("█" * 64)
    print()


def run(cmd, label=None):
    """Run a command and show its output."""
    if label:
        print(f"\n{'─'*60}")
        print(f"  $ {cmd}")
        print(f"{'─'*60}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
    if result.stdout:
        print(result.stdout)
    if result.stderr and "WARNING" not in result.stderr:
        print(result.stderr, file=sys.stderr)
    return result.returncode


def main():
    parser = argparse.ArgumentParser(description="Full Steganography C2 Demo Runner")
    parser.add_argument("--command", "-c", default="whoami",
                        help="Command to embed (default: whoami)")
    parser.add_argument("--xor-key", "-x", default="0x4D",
                        help="XOR key for EOF technique (default: 0x4D)")
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    cmd = args.command
    xor_key = args.xor_key

    # Ensure test image exists
    if not os.path.exists("images/original.png"):
        print("[*] Generating test image...")
        run("python generate_test_image.py")

    # ════════════════════════════════════════════════════════════
    banner("TECHNIQUE 1: LSB Steganography (encoder.py)")
    # ════════════════════════════════════════════════════════════
    print("Hides data INSIDE pixel values by modifying least significant bits.")
    print("Used by: Turla, APT32/OceanLotus, Worok, Lumma Stealer")
    print()

    run(f'python encoder.py images/original.png "{cmd}" images/encoded.png', label=True)

    print("\n[*] Forensic checks:")
    run('file images/original.png images/encoded.png', label=True)
    run(f'strings images/encoded.png | grep -i "{cmd}" || echo "[+] Command NOT found in strings output (hidden!)"', label=True)

    run('python compare.py images/original.png images/encoded.png', label=True)

    print("\n[*] Extracting hidden command (simulating implant):")
    run('python decoder.py images/encoded.png --no-execute', label=True)

    # ════════════════════════════════════════════════════════════
    banner("TECHNIQUE 2: EOF Appending (hide-payload-in-images)")
    # ════════════════════════════════════════════════════════════
    print("Appends data AFTER the PNG IEND chunk. Image renders normally")
    print("because PNG readers stop at IEND. Hidden data lives beyond it.")
    print(f"Uses XOR encryption (key={xor_key}) to obfuscate the payload.")
    print()
    print("Used by: Adaptix C2 campaigns, EDR-bypassing loaders")
    print("Tool:    github.com/WafflesExploits/hide-payload-in-images")
    print()

    run(f'python payload_embedder.py images/original.png "{cmd}" images/embedded_eof.png --xor-key {xor_key}', label=True)

    print("\n[*] Forensic checks:")
    run('file images/original.png images/embedded_eof.png', label=True)
    run(f'strings images/embedded_eof.png | grep -i "{cmd}" || echo "[+] Command NOT found in strings output (XOR encrypted!)"', label=True)

    # Show file size difference is more obvious with EOF
    run('ls -la images/original.png images/encoded.png images/embedded_eof.png', label=True)

    print("\n[*] Extracting hidden command (simulating C loader):")
    run(f'python payload_extractor.py images/embedded_eof.png --xor-key {xor_key}', label=True)

    # ════════════════════════════════════════════════════════════
    banner("DETECTION: Blue Team Analysis")
    # ════════════════════════════════════════════════════════════
    print("Running stego_detector.py against all three images...\n")

    print("─" * 60)
    print("  Scanning: ORIGINAL (clean) image")
    print("─" * 60)
    run('python stego_detector.py images/original.png')

    print("\n" + "─" * 60)
    print("  Scanning: LSB ENCODED image")
    print("─" * 60)
    run('python stego_detector.py images/encoded.png')

    print("\n" + "─" * 60)
    print("  Scanning: EOF EMBEDDED image")
    print("─" * 60)
    run('python stego_detector.py images/embedded_eof.png')

    # ════════════════════════════════════════════════════════════
    banner("TECHNIQUE COMPARISON")
    # ════════════════════════════════════════════════════════════

    print("""
  ┌────────────────────┬──────────────────────┬──────────────────────┐
  │                    │  LSB Steganography   │  EOF Appending       │
  ├────────────────────┼──────────────────────┼──────────────────────┤
  │ Data location      │ Inside pixel values  │ After IEND chunk     │
  │ File size change   │ Identical            │ Increases by payload │
  │ Visual difference  │ None (1-bit change)  │ None                 │
  │ strings detection  │ No                   │ No (if XOR'd)        │
  │ file cmd detection │ No                   │ No                   │
  │ Capacity           │ 3 bits/pixel         │ Unlimited            │
  │ Robustness         │ Fragile (recompress) │ Robust               │
  │ EOF analysis       │ Clean                │ DETECTABLE           │
  │ LSB statistics     │ DETECTABLE           │ Clean                │
  │ Real-world use     │ Turla, APT32, Worok  │ Adaptix C2, loaders  │
  │ Complexity         │ Moderate             │ Simple               │
  │ EDR bypass         │ Yes                  │ Yes (with C loader)  │
  └────────────────────┴──────────────────────┴──────────────────────┘

  Key insight: Each technique evades the detection method that catches
  the other. A comprehensive defense needs BOTH detection approaches.
""")


if __name__ == "__main__":
    main()
