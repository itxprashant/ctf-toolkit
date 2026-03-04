#!/usr/bin/env python3
"""
steg_basic.py - CTF Basic Steganography Toolkit

LSB extraction, bit plane analysis, image comparison, and channel separation.
Useful for image-based steganography challenges in CTFs.

Requires: Pillow (pip install Pillow)

Usage:
    python3 steg_basic.py lsb <image>
    python3 steg_basic.py lsb <image> --bits 2 --channel R
    python3 steg_basic.py bitplane <image> --bit 0 --channel R
    python3 steg_basic.py compare <image1> <image2>
    python3 steg_basic.py channels <image>
"""

import argparse
import os
import sys

try:
    from PIL import Image
except ImportError:
    print("Error: Pillow is required. Install with: pip install Pillow", file=sys.stderr)
    sys.exit(1)

# ANSI colors
class C:
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN    = '\033[96m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    RESET   = '\033[0m'


def print_header(text):
    print(f"\n{C.BOLD}{C.CYAN}{'─' * 60}")
    print(f"  {text}")
    print(f"{'─' * 60}{C.RESET}")


def print_field(label, value, color=C.GREEN):
    print(f"  {C.BOLD}{label + ':':20s}{C.RESET} {color}{value}{C.RESET}")


# ─── LSB Extraction ──────────────────────────────────────────────────────────

def extract_lsb(image_path, num_bits=1, channels='RGB', output=None, row_order=True):
    """Extract least-significant bits from image channels."""
    img = Image.open(image_path)
    if img.mode not in ('RGB', 'RGBA', 'L'):
        img = img.convert('RGB')

    pixels = img.load()
    width, height = img.size

    print_header(f"LSB Extraction: {os.path.basename(image_path)}")
    print_field('Image Size', f'{width} x {height}')
    print_field('Mode', img.mode)
    print_field('Bits Extracted', str(num_bits))
    print_field('Channels', channels)

    # Map channel names to indices
    mode_channels = list(img.mode)
    channel_indices = []
    for ch in channels:
        if ch in mode_channels:
            channel_indices.append(mode_channels.index(ch))
        else:
            print(f"  {C.YELLOW}Warning: Channel '{ch}' not in image mode '{img.mode}'{C.RESET}")

    if not channel_indices:
        print(f"  {C.RED}Error: No valid channels selected.{C.RESET}")
        return

    # Extract bits
    bits = []
    mask = (1 << num_bits) - 1

    if row_order:
        coords = ((x, y) for y in range(height) for x in range(width))
    else:
        coords = ((x, y) for x in range(width) for y in range(height))

    for x, y in coords:
        pixel = pixels[x, y]
        if isinstance(pixel, int):  # Grayscale
            pixel = (pixel,)
        for ci in channel_indices:
            if ci < len(pixel):
                val = pixel[ci] & mask
                for bit_pos in range(num_bits - 1, -1, -1):
                    bits.append((val >> bit_pos) & 1)

    # Convert bits to bytes
    extracted_bytes = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        extracted_bytes.append(byte)

    # Try to decode as text
    try:
        text = extracted_bytes.decode('ascii', errors='replace')
        # Find the first null terminator
        null_idx = text.find('\x00')
        if null_idx > 0:
            text_preview = text[:null_idx]
        else:
            text_preview = text[:200]

        # Clean for display
        printable = ''.join(c if 32 <= ord(c) < 127 else '.' for c in text_preview)

        print(f"\n  {C.BOLD}Extracted Text Preview:{C.RESET}")
        print(f"  {C.GREEN}{printable}{C.RESET}")

        # Check for flags
        import re
        flag_patterns = [r'flag\{[^}]+\}', r'ctf\{[^}]+\}', r'CTF\{[^}]+\}',
                         r'FLAG\{[^}]+\}', r'picoCTF\{[^}]+\}', r'HTB\{[^}]+\}']
        for pattern in flag_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                print(f"\n  {C.RED}{C.BOLD}⚑ FLAG FOUND:{C.RESET}")
                for m in matches:
                    print(f"  {C.RED}{C.BOLD}  → {m}{C.RESET}")

    except Exception:
        pass

    # Save output
    if output:
        with open(output, 'wb') as f:
            f.write(bytes(extracted_bytes))
        print(f"\n  {C.GREEN}Raw bytes saved to: {output}{C.RESET}")
        print(f"  {C.DIM}Total: {len(extracted_bytes)} bytes{C.RESET}")
    else:
        # Show hex preview of first 64 bytes
        hex_preview = ' '.join(f'{b:02x}' for b in extracted_bytes[:64])
        print(f"\n  {C.BOLD}Raw Hex Preview (first 64 bytes):{C.RESET}")
        print(f"  {C.DIM}{hex_preview}{C.RESET}")
        print(f"\n  {C.DIM}Use --output <file> to save all extracted bytes{C.RESET}")

    print()
    return extracted_bytes


# ─── Bit Plane Analysis ──────────────────────────────────────────────────────

def extract_bitplane(image_path, bit=0, channel='R', output=None):
    """Extract a specific bit plane from an image channel and save as image."""
    img = Image.open(image_path)
    if img.mode not in ('RGB', 'RGBA'):
        img = img.convert('RGB')

    print_header(f"Bit Plane: {os.path.basename(image_path)}")
    print_field('Channel', channel)
    print_field('Bit', str(bit))

    mode_channels = list(img.mode)
    if channel not in mode_channels:
        print(f"  {C.RED}Error: Channel '{channel}' not in image mode '{img.mode}'{C.RESET}")
        return

    ch_idx = mode_channels.index(channel)
    pixels = img.load()
    width, height = img.size

    # Create bit plane image
    bp_img = Image.new('L', (width, height))
    bp_pixels = bp_img.load()

    for y in range(height):
        for x in range(width):
            pixel = pixels[x, y]
            if isinstance(pixel, int):
                pixel = (pixel,)
            val = (pixel[ch_idx] >> bit) & 1
            bp_pixels[x, y] = val * 255

    if output is None:
        base = os.path.splitext(os.path.basename(image_path))[0]
        output = f'{base}_bitplane_{channel}_bit{bit}.png'

    bp_img.save(output)
    print(f"  {C.GREEN}Bit plane saved to: {output}{C.RESET}\n")
    return bp_img


# ─── Image Comparison ────────────────────────────────────────────────────────

def compare_images(image1_path, image2_path, output=None, amplify=10):
    """Compare two images pixel-by-pixel and highlight differences."""
    img1 = Image.open(image1_path).convert('RGB')
    img2 = Image.open(image2_path).convert('RGB')

    print_header("Image Comparison")
    print_field('Image 1', f'{os.path.basename(image1_path)} ({img1.size[0]}x{img1.size[1]})')
    print_field('Image 2', f'{os.path.basename(image2_path)} ({img2.size[0]}x{img2.size[1]})')

    if img1.size != img2.size:
        print(f"  {C.YELLOW}Warning: Images have different sizes. "
              f"Comparing overlapping region.{C.RESET}")

    min_w = min(img1.size[0], img2.size[0])
    min_h = min(img1.size[1], img2.size[1])

    px1 = img1.load()
    px2 = img2.load()

    diff_img = Image.new('RGB', (min_w, min_h))
    diff_pixels = diff_img.load()

    diff_count = 0
    total_diff = 0
    diff_positions = []

    for y in range(min_h):
        for x in range(min_w):
            p1 = px1[x, y]
            p2 = px2[x, y]

            if p1 != p2:
                diff_count += 1
                dr = abs(p1[0] - p2[0])
                dg = abs(p1[1] - p2[1])
                db = abs(p1[2] - p2[2])
                total_diff += dr + dg + db

                # Amplify differences for visibility
                diff_pixels[x, y] = (
                    min(255, dr * amplify),
                    min(255, dg * amplify),
                    min(255, db * amplify)
                )

                if len(diff_positions) < 20:
                    diff_positions.append((x, y, p1, p2))
            else:
                diff_pixels[x, y] = (0, 0, 0)

    total_pixels = min_w * min_h
    print_field('Different Pixels', f'{diff_count:,} / {total_pixels:,} '
                f'({diff_count / total_pixels * 100:.2f}%)')

    if diff_count == 0:
        print(f"  {C.GREEN}Images are identical!{C.RESET}\n")
        return

    print_field('Amplification', f'{amplify}x')

    # Show some diff positions
    if diff_positions:
        print(f"\n  {C.BOLD}First differences:{C.RESET}")
        for x, y, p1, p2 in diff_positions[:10]:
            print(f"    ({x:4d}, {y:4d}): {C.DIM}{p1}{C.RESET} → {C.YELLOW}{p2}{C.RESET}")

    # Try extracting data from LSB differences
    diff_bits = []
    for y in range(min_h):
        for x in range(min_w):
            p1 = px1[x, y]
            p2 = px2[x, y]
            if p1 != p2:
                # Extract LSB difference from red channel
                diff_bits.append(p2[0] & 1)

    if diff_bits:
        diff_bytes = bytearray()
        for i in range(0, len(diff_bits) - 7, 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | diff_bits[i + j]
            diff_bytes.append(byte)

        try:
            text = diff_bytes[:100].decode('ascii', errors='replace')
            printable = ''.join(c if 32 <= ord(c) < 127 else '.' for c in text)
            if any(32 <= ord(c) < 127 for c in text[:20]):
                print(f"\n  {C.BOLD}LSB diff as text:{C.RESET}")
                print(f"  {C.GREEN}{printable}{C.RESET}")
        except Exception:
            pass

    if output is None:
        output = 'diff_result.png'

    diff_img.save(output)
    print(f"\n  {C.GREEN}Diff image saved to: {output}{C.RESET}\n")


# ─── Channel Separation ──────────────────────────────────────────────────────

def separate_channels(image_path, output_dir=None):
    """Split an image into its individual color channels."""
    img = Image.open(image_path)
    if img.mode not in ('RGB', 'RGBA'):
        img = img.convert('RGB')

    print_header(f"Channel Separation: {os.path.basename(image_path)}")
    print_field('Mode', img.mode)
    print_field('Size', f'{img.size[0]} x {img.size[1]}')

    if output_dir is None:
        output_dir = '.'

    os.makedirs(output_dir, exist_ok=True)
    base = os.path.splitext(os.path.basename(image_path))[0]

    channels = img.split()
    channel_names = list(img.mode)

    for ch, name in zip(channels, channel_names):
        out_path = os.path.join(output_dir, f'{base}_{name}.png')
        ch.save(out_path)
        print(f"  {C.GREEN}Saved: {out_path}{C.RESET}")

        # Also create a colorized version
        if name in 'RGBA':
            color_img = Image.new('RGB', img.size, (0, 0, 0))
            color_pixels = color_img.load()
            ch_pixels = ch.load()
            w, h = img.size

            color_map = {'R': 0, 'G': 1, 'B': 2, 'A': None}
            ch_idx = color_map.get(name)

            if ch_idx is not None:
                for y in range(h):
                    for x in range(w):
                        pixel = [0, 0, 0]
                        pixel[ch_idx] = ch_pixels[x, y]
                        color_pixels[x, y] = tuple(pixel)

                colored_path = os.path.join(output_dir, f'{base}_{name}_colored.png')
                color_img.save(colored_path)
                print(f"  {C.GREEN}Saved: {colored_path} (colorized){C.RESET}")

    print()


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='CTF Steganography Toolkit — LSB, bit planes, comparison, channels',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s lsb secret.png
  %(prog)s lsb secret.png --bits 2 --channel R --output hidden.bin
  %(prog)s bitplane image.png --bit 0 --channel G
  %(prog)s compare original.png modified.png --amplify 20
  %(prog)s channels mystery.png --output-dir ./channels
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Steganography operation')

    # LSB subcommand
    lsb_parser = subparsers.add_parser('lsb', help='Extract least-significant bits')
    lsb_parser.add_argument('image', help='Input image')
    lsb_parser.add_argument('--bits', '-b', type=int, default=1,
                            help='Number of LSBs to extract (default: 1)')
    lsb_parser.add_argument('--channel', '-c', type=str, default='RGB',
                            help='Channels to extract from (default: RGB)')
    lsb_parser.add_argument('--output', '-o', type=str,
                            help='Output file for raw extracted bytes')
    lsb_parser.add_argument('--column-order', action='store_true',
                            help='Read pixels column-by-column instead of row-by-row')
    lsb_parser.add_argument('--no-color', action='store_true', help='Disable colored output')

    # Bit plane subcommand
    bp_parser = subparsers.add_parser('bitplane', help='Extract bit plane as image')
    bp_parser.add_argument('image', help='Input image')
    bp_parser.add_argument('--bit', type=int, default=0,
                           help='Bit number to extract 0-7 (default: 0, LSB)')
    bp_parser.add_argument('--channel', '-c', type=str, default='R',
                           help='Channel to analyze (default: R)')
    bp_parser.add_argument('--output', '-o', type=str,
                           help='Output image path')
    bp_parser.add_argument('--no-color', action='store_true', help='Disable colored output')

    # Compare subcommand
    cmp_parser = subparsers.add_parser('compare', help='Compare two images')
    cmp_parser.add_argument('image1', help='First image')
    cmp_parser.add_argument('image2', help='Second image')
    cmp_parser.add_argument('--output', '-o', type=str,
                            help='Output diff image path')
    cmp_parser.add_argument('--amplify', '-a', type=int, default=10,
                            help='Difference amplification factor (default: 10)')
    cmp_parser.add_argument('--no-color', action='store_true', help='Disable colored output')

    # Channel separation subcommand
    ch_parser = subparsers.add_parser('channels', help='Separate color channels')
    ch_parser.add_argument('image', help='Input image')
    ch_parser.add_argument('--output-dir', '-o', type=str,
                           help='Output directory for channel images')
    ch_parser.add_argument('--no-color', action='store_true', help='Disable colored output')

    args = parser.parse_args()

    if getattr(args, 'no_color', False):
        for attr in dir(C):
            if not attr.startswith('_'):
                setattr(C, attr, '')

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == 'lsb':
        extract_lsb(args.image, args.bits, args.channel, args.output,
                     not args.column_order)

    elif args.command == 'bitplane':
        extract_bitplane(args.image, args.bit, args.channel, args.output)

    elif args.command == 'compare':
        compare_images(args.image1, args.image2, args.output, args.amplify)

    elif args.command == 'channels':
        separate_channels(args.image, args.output_dir)


if __name__ == '__main__':
    main()
