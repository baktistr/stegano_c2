#!/usr/bin/env python3
"""Generate a visually interesting test PNG image for the demo.
Includes random noise for realistic LSB distribution (avoids false positives in stego analysis)."""
import math
import random
from PIL import Image

random.seed(42)  # reproducible
width, height = 400, 300
img = Image.new('RGB', (width, height))
pixels = img.load()

for y in range(height):
    for x in range(width):
        # Create a colorful gradient/plasma-like pattern with natural noise
        r = int((math.sin(x * 0.03) + 1) * 80 + (math.cos(y * 0.05) + 1) * 47 + random.randint(-15, 15))
        g = int((math.sin(y * 0.04 + 1) + 1) * 60 + (math.cos(x * 0.02 + 2) + 1) * 55 + random.randint(-15, 15))
        b = int((math.sin((x + y) * 0.025) + 1) * 70 + (math.cos(x * 0.03 - y * 0.02) + 1) * 45 + random.randint(-15, 15))
        r = max(0, min(255, r))
        g = max(0, min(255, g))
        b = max(0, min(255, b))
        pixels[x, y] = (r, g, b)

img.save('images/original.png', 'PNG')
print(f"[+] Generated test image: images/original.png ({width}x{height})")
print(f"[+] TIP: For best demo results, replace with a real photograph!")
