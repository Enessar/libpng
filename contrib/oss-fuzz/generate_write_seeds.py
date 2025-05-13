#!/usr/bin/env python3
"""
generate_write_seeds.py

This script:
 1. Finds all PNG files under $SRC/libpng (excluding any path containing "crashers").
 2. Converts each PNG to a binary seed of the form [width][height][RGBA bytes], clamping dimensions to ≤64×64.
 3. Generates synthetic pattern seeds at power-of-two sizes.
 4. Packages all .bin seeds into libpng_write_fuzzer_seed_corpus.zip for OSS-Fuzz, placing it alongside this script.

Usage:
  1. Place this file in contrib/oss-fuzz/ alongside your build.sh.
  2. Ensure Pillow is installed in your fuzzer Docker environment.
  3. During build, run: python3 generate_write_seeds.py
  4. Copy the resulting ZIP from this folder into $OUT in build.sh.
"""
import os
import struct
import random
import zipfile
from pathlib import Path
from PIL import Image


def png_to_seed(png_path: Path, out_path: Path, max_dim: int = 64):
    """
    Load a PNG, clamp dimensions to max_dim×max_dim, and write:
      [4-byte BE width][4-byte BE height][raw RGBA bytes]
    """
    with Image.open(png_path) as img:
        img = img.convert("RGBA")
        w, h = img.size
        if w > max_dim or h > max_dim:
            img = img.resize((min(w, max_dim), min(h, max_dim)), Image.LANCZOS)
            w, h = img.size
        data = struct.pack('>I', w) + struct.pack('>I', h) + img.tobytes()
    out_path.write_bytes(data)


def make_pattern_seed(w: int, h: int, kind: str, out_path: Path):
    """
    Generate synthetic pattern seeds:
      black, white, checkerboard, horizontal/vertical gradient, noise
    at width w and height h.
    """
    buf = bytearray()
    buf += struct.pack('>I', w) + struct.pack('>I', h)
    for y in range(h):
        for x in range(w):
            if kind == 'black':
                pix = (0, 0, 0, 255)
            elif kind == 'white':
                pix = (255, 255, 255, 255)
            elif kind == 'checker':
                v = 255 if ((x // 8 + y // 8) % 2) == 0 else 0
                pix = (v, v, v, 255)
            elif kind == 'hgrad':
                v = int(255 * x / max(1, w - 1))
                pix = (v, v, v, 255)
            elif kind == 'vgrad':
                v = int(255 * y / max(1, h - 1))
                pix = (v, v, v, 255)
            elif kind == 'noise':
                pix = (
                    random.randrange(256),
                    random.randrange(256),
                    random.randrange(256),
                    random.randrange(256)
                )
            buf.extend(pix)
    out_path.write_bytes(buf)


def main():
    # Determine directories
    script_dir = Path(__file__).resolve().parent
    SRC = Path(os.environ.get("SRC", "."))
    input_dir = SRC / "libpng"

    # Output folder for .bin seeds
    out_dir = script_dir / "write_seed_bins"
    out_dir.mkdir(exist_ok=True)

    # 1) Find all .png files under src/libpng, excluding 'crashers'
    png_paths = [p for p in input_dir.rglob("*.png") if "crashers" not in str(p)]

    # 2) Convert each PNG to a .bin seed
    for idx, png_path in enumerate(png_paths):
        seed_file = out_dir / f"png_{idx}.bin"
        try:
            png_to_seed(png_path, seed_file)
        except Exception as e:
            print(f"Skipping {png_path}: {e}")

    # 3) Generate synthetic pattern seeds at power-of-two sizes
    sizes = [1, 2, 4, 8, 16, 32, 64]
    kinds = ['black', 'white', 'checker', 'hgrad', 'vgrad', 'noise']
    for w in sizes:
        for h in sizes:
            for kind in kinds:
                out_file = out_dir / f"{w}x{h}_{kind}.bin"
                make_pattern_seed(w, h, kind, out_file)

    # 4) Zip all .bin files into the final seed corpus alongside this script
    zip_name = script_dir / "libpng_write_fuzzer_seed_corpus.zip"
    with zipfile.ZipFile(zip_name, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        for seed in sorted(out_dir.iterdir()):
            zf.write(seed, seed.name)

    print(f"Generated {zip_name} with {len(list(out_dir.iterdir()))} seeds.")


if __name__ == "__main__":
    main()
