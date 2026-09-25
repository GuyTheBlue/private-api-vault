#!/usr/bin/env python3
"""Render logo.jpg as truecolor half-block terminal art.

Each terminal cell holds TWO source pixels (top/bottom) drawn as one Unicode
half-block with ANSI truecolor fg=top, bg=bottom. This preserves the logo's
color, gradients, and wordmark — unlike 1-bit grayscale ASCII. 2:1 ratio keeps
cells square-ish so the keyhole isn't stretched.

Usage:  python3 emit_art.py [width_chars]
Outputs the ANSI-colored art to stdout (timing: reprint the last line for a
Terminal.app-safe 'hold the image')."""
import sys
from PIL import Image

SRC = '/Volumes/Secure/private_api_vault/logo.jpg'

def render(width_chars, height_chars):
    im = Image.open(SRC).convert('RGB')
    im = im.resize((width_chars, height_chars), Image.LANCZOS)
    px = im.load()
    out = []
    for y in range(0, height_chars, 2):           # two source rows per cell
        line = []
        for x in range(width_chars):
            top = px[x, y]
            bot = px[x, y + 1] if y + 1 < height_chars else (0, 0, 0)
            # fg = top pixel, bg = bottom pixel, glyph = lower-half block
            line.append(f"\033[38;2;{top[0]};{top[1]};{top[2]}m"
                        f"\033[48;2;{bot[0]};{bot[1]};{bot[2]}m\u2584")
        out.append(''.join(line) + "\033[0m")
    return out

# height = width * (h/w) / 2  (halved because 2 px/cell); keep ~aspect
w = int(sys.argv[1]) if len(sys.argv) > 1 else 100
h = max(4, int(w * 508 / 663 / 2))
art = render(w, h)
for line in art:
    print(line)
# HALF-BLOCK to show on scrollback that isn't full-height: not needed in terminal
print("\033[0m")