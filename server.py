#!/usr/bin/env python3
"""
C2 Image Server - Simulated attacker infrastructure
A simple Flask web server that hosts encoded steganography images.

CMU Heinz College - 95-759 Malicious Code Analysis
Group Project: Steganography-Based C2 Channel

Usage:
    python server.py [--port PORT]

Default: http://localhost:8080
"""

import argparse
import os
from datetime import datetime

from flask import Flask, send_from_directory, request

app = Flask(__name__)

# Directory containing the images (relative to this script)
IMAGE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'images')


@app.route('/<filename>')
def serve_image(filename):
    """Serve an image file from the images directory."""
    timestamp = datetime.now().strftime('%H:%M:%S')
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')

    print(f"[{timestamp}] Serving '{filename}' to {client_ip}")
    print(f"           User-Agent: {user_agent}")

    return send_from_directory(IMAGE_DIR, filename)


@app.route('/')
def index():
    """List available images (for convenience during demo)."""
    files = []
    if os.path.isdir(IMAGE_DIR):
        files = [f for f in os.listdir(IMAGE_DIR) if f.lower().endswith('.png')]
        files.sort()

    file_list = "\n".join(f"  - /{f}" for f in files) if files else "  (no PNG files found)"

    return (
        f"C2 Image Server\n"
        f"Available images:\n{file_list}\n\n"
        f"Usage: GET /<filename>\n"
    ), 200, {'Content-Type': 'text/plain'}


def main():
    parser = argparse.ArgumentParser(
        description="C2 Image Server - Host encoded steganography images"
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=8080,
        help="Port to listen on (default: 8080)"
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("  C2 IMAGE SERVER - Steganography Demo")
    print("=" * 60)
    print()
    print(f"[*] Image directory: {IMAGE_DIR}")

    if os.path.isdir(IMAGE_DIR):
        pngs = [f for f in os.listdir(IMAGE_DIR) if f.lower().endswith('.png')]
        print(f"[*] PNG files available: {len(pngs)}")
        for f in sorted(pngs):
            size = os.path.getsize(os.path.join(IMAGE_DIR, f))
            print(f"    - {f} ({size:,} bytes)")
    else:
        print(f"[!] WARNING: Image directory not found: {IMAGE_DIR}")
        print(f"[!] Create it and add PNG images before running the decoder.")

    print()
    print(f"[*] Starting server on http://{args.host}:{args.port}")
    print(f"[*] Press Ctrl+C to stop")
    print()

    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
