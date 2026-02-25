#!/usr/bin/env python3
"""
Steganography Encoder - Attacker-side tool
Embeds a plaintext command into a PNG image using LSB steganography.

CMU Heinz College - 95-759 Malicious Code Analysis
Group Project: Steganography-Based C2 Channel

Usage:
    python encoder.py <input_image> <command> <output_image>

Example:
    python encoder.py images/original.png "whoami" images/encoded.png
"""

import argparse
import sys
from PIL import Image


def text_to_bits(text):
    """Convert a text string to a binary bit string (8 bits per character)."""
    bits = ""
    for char in text:
        bits += format(ord(char), '08b')
    return bits


def encode(image_path, command, output_path):
    """Embed a command string into a PNG image using LSB steganography."""

    # Step 1: Load image
    print(f"[*] Loading image: {image_path}")
    try:
        img = Image.open(image_path)
    except FileNotFoundError:
        print(f"[-] ERROR: Image not found: {image_path}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] ERROR: Could not open image: {e}")
        sys.exit(1)

    # Convert to RGB to handle RGBA or other modes
    img = img.convert('RGB')
    pixels = img.load()
    width, height = img.size

    print(f"[*] Image size: {width}x{height} ({width * height} pixels)")
    max_bits = width * height * 3
    print(f"[*] Maximum capacity: {max_bits} bits ({max_bits // 8} bytes)")

    # Step 2: Convert command to bits
    print(f"[*] Command to embed: {command}")
    message_bits = text_to_bits(command)
    print(f"[*] Command length: {len(command)} characters ({len(message_bits)} bits)")

    # Step 3: Create 32-bit length header
    header = format(len(message_bits), '032b')
    all_bits = header + message_bits
    total_bits = len(all_bits)
    print(f"[*] Total bits to embed: {total_bits} (32 header + {len(message_bits)} message)")

    # Step 4: Check capacity
    if total_bits > max_bits:
        print(f"[-] ERROR: Image too small for this message!")
        print(f"[-] Need {total_bits} bits but image only has {max_bits} bit capacity.")
        sys.exit(1)

    # Step 5: Embed bits into pixel LSBs
    print("[*] Embedding bits into pixel LSBs...")
    bit_index = 0

    for y in range(height):
        for x in range(width):
            if bit_index >= total_bits:
                break

            r, g, b = pixels[x, y]

            # Modify R channel
            if bit_index < total_bits:
                r = (r & 0xFE) | int(all_bits[bit_index])
                bit_index += 1

            # Modify G channel
            if bit_index < total_bits:
                g = (g & 0xFE) | int(all_bits[bit_index])
                bit_index += 1

            # Modify B channel
            if bit_index < total_bits:
                b = (b & 0xFE) | int(all_bits[bit_index])
                bit_index += 1

            pixels[x, y] = (r, g, b)

        if bit_index >= total_bits:
            break

    # Step 6: Save encoded image
    img.save(output_path, 'PNG')

    # Print summary
    capacity_pct = (total_bits / max_bits) * 100
    pixels_modified = (total_bits + 2) // 3  # ceil division
    print(f"[+] Done! Encoded image saved to: {output_path}")
    print(f"[+] Capacity used: {total_bits} / {max_bits} bits ({capacity_pct:.3f}%)")
    print(f"[+] Pixels modified: {pixels_modified} / {width * height}")


def main():
    parser = argparse.ArgumentParser(
        description="Steganography Encoder - Hide commands in PNG images using LSB steganography",
        epilog="Example: python encoder.py images/original.png \"whoami\" images/encoded.png"
    )
    parser.add_argument("input_image", help="Path to the source PNG image")
    parser.add_argument("command", help="Command string to hide in the image")
    parser.add_argument("output_image", help="Path for the output encoded image")

    args = parser.parse_args()

    print("=" * 60)
    print("  STEGANOGRAPHY ENCODER - LSB Command Embedding")
    print("=" * 60)
    print()

    encode(args.input_image, args.command, args.output_image)

    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
