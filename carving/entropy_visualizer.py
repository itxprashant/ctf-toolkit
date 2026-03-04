#!/usr/bin/env python3
"""
entropy_visualizer.py - CTF Entropy Analysis Tool

Generates block-by-block entropy analysis to identify compressed,
encrypted, or hidden data regions. ASCII heatmap in terminal,
optional PNG graph output.

Usage:
    python3 entropy_visualizer.py <file>
    python3 entropy_visualizer.py firmware.bin --block-size 1024
    python3 entropy_visualizer.py mystery.dat --png entropy_graph.png
    python3 entropy_visualizer.py blob.bin --threshold 7.5
"""

import argparse
import math
import os
import struct
import sys

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
    print(f"\n{C.BOLD}{C.CYAN}{'─' * 70}")
    print(f"  {text}")
    print(f"{'─' * 70}{C.RESET}")


def print_field(label, value, color=C.GREEN):
    print(f"  {C.BOLD}{label + ':':20s}{C.RESET} {color}{value}{C.RESET}")


def shannon_entropy(data):
    """Calculate Shannon entropy (0.0 - 8.0)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def classify_entropy(entropy):
    """Classify an entropy value."""
    if entropy < 1.0:
        return 'null/empty', C.DIM
    elif entropy < 3.5:
        return 'text/code', C.GREEN
    elif entropy < 5.5:
        return 'data/binary', C.BLUE
    elif entropy < 7.0:
        return 'structured', C.YELLOW
    elif entropy < 7.5:
        return 'compressed?', C.MAGENTA
    else:
        return 'encrypted/compressed', C.RED


def entropy_bar(value, width=40):
    """Create a colored entropy bar."""
    filled = int((value / 8.0) * width)
    _, color = classify_entropy(value)
    bar = color + '█' * filled + C.DIM + '░' * (width - filled) + C.RESET
    return bar


def analyze_entropy(data, block_size=256):
    """Calculate per-block entropy."""
    blocks = []
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        ent = shannon_entropy(block)
        blocks.append({
            'offset': i,
            'entropy': ent,
            'size': len(block),
        })
    return blocks


def find_regions(blocks, threshold_high=7.0, threshold_low=1.0):
    """Find contiguous regions of high/low entropy."""
    regions = []
    current_type = None
    start_block = 0

    for i, block in enumerate(blocks):
        ent = block['entropy']
        if ent >= threshold_high:
            block_type = 'high'
        elif ent <= threshold_low:
            block_type = 'low'
        else:
            block_type = 'normal'

        if block_type != current_type:
            if current_type in ('high', 'low') and i > start_block:
                regions.append({
                    'type': current_type,
                    'start_offset': blocks[start_block]['offset'],
                    'end_offset': block['offset'],
                    'block_count': i - start_block,
                    'avg_entropy': sum(b['entropy'] for b in blocks[start_block:i]) / (i - start_block),
                })
            current_type = block_type
            start_block = i

    # Close final region
    if current_type in ('high', 'low') and len(blocks) > start_block:
        regions.append({
            'type': current_type,
            'start_offset': blocks[start_block]['offset'],
            'end_offset': blocks[-1]['offset'] + blocks[-1]['size'],
            'block_count': len(blocks) - start_block,
            'avg_entropy': sum(b['entropy'] for b in blocks[start_block:]) / (len(blocks) - start_block),
        })

    return regions


def generate_ascii_heatmap(blocks, width=70):
    """Generate an ASCII entropy heatmap."""
    lines = []
    chars_per_block = max(1, width // min(len(blocks), width))
    blocks_per_char = max(1, len(blocks) // width)

    row = []
    for i in range(0, len(blocks), blocks_per_char):
        chunk = blocks[i:i + blocks_per_char]
        avg_ent = sum(b['entropy'] for b in chunk) / len(chunk)

        # Map entropy to character
        if avg_ent < 0.5:
            char, color = ' ', C.DIM
        elif avg_ent < 1.5:
            char, color = '░', C.DIM
        elif avg_ent < 3.0:
            char, color = '▒', C.GREEN
        elif avg_ent < 5.0:
            char, color = '▓', C.BLUE
        elif avg_ent < 6.5:
            char, color = '█', C.YELLOW
        elif avg_ent < 7.5:
            char, color = '█', C.MAGENTA
        else:
            char, color = '█', C.RED

        row.append(f"{color}{char}{C.RESET}")

        if len(row) >= width:
            lines.append(''.join(row))
            row = []

    if row:
        lines.append(''.join(row))

    return lines


def generate_png(blocks, output_path, width=800, height=300):
    """Generate a PNG entropy graph using Pillow."""
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        print(f"{C.YELLOW}Warning: Pillow required for PNG output. "
              f"Install with: pip install Pillow{C.RESET}")
        return False

    img = Image.new('RGB', (width, height), (20, 20, 30))
    draw = ImageDraw.Draw(img)

    # Draw graph
    num_blocks = len(blocks)
    x_scale = width / num_blocks
    y_scale = (height - 40) / 8.0  # 8.0 = max entropy

    # Grid lines
    for e in range(0, 9):
        y = height - 20 - int(e * y_scale)
        draw.line([(0, y), (width, y)], fill=(40, 40, 50))

    # Threshold line at 7.0
    y_thresh = height - 20 - int(7.0 * y_scale)
    draw.line([(0, y_thresh), (width, y_thresh)], fill=(200, 60, 60))

    # Entropy bars
    for i, block in enumerate(blocks):
        x = int(i * x_scale)
        bar_width = max(1, int(x_scale))
        ent = block['entropy']
        bar_height = int(ent * y_scale)
        y_top = height - 20 - bar_height

        # Color based on entropy
        if ent < 1.0:
            color = (60, 60, 80)
        elif ent < 3.5:
            color = (50, 180, 80)
        elif ent < 5.5:
            color = (50, 120, 200)
        elif ent < 7.0:
            color = (220, 180, 50)
        elif ent < 7.5:
            color = (180, 80, 200)
        else:
            color = (220, 50, 50)

        draw.rectangle([(x, y_top), (x + bar_width, height - 20)], fill=color)

    img.save(output_path)
    return True


def main():
    parser = argparse.ArgumentParser(
        description='CTF Entropy Visualizer — identify encrypted/compressed regions',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Entropy interpretation:
  0.0 - 1.0   Null / empty data (uniform bytes)
  1.0 - 3.5   Plain text, source code, ASCII
  3.5 - 5.5   Binary data, structured formats
  5.5 - 7.0   Mixed/structured binary
  7.0 - 7.5   Likely compressed data
  7.5 - 8.0   Likely encrypted or very compressed

Examples:
  %(prog)s firmware.bin
  %(prog)s firmware.bin --block-size 1024
  %(prog)s mystery.dat --png entropy.png
  %(prog)s blob.bin --threshold 7.5 --regions
  %(prog)s binary --json
        """
    )
    parser.add_argument('file', help='File to analyze')
    parser.add_argument('--block-size', '-b', type=int, default=256,
                        help='Block size in bytes (default: 256)')
    parser.add_argument('--threshold', '-t', type=float, default=7.0,
                        help='High entropy threshold (default: 7.0)')
    parser.add_argument('--regions', '-r', action='store_true',
                        help='Show detected high/low entropy regions')
    parser.add_argument('--png', '-p', type=str,
                        help='Save entropy graph as PNG (requires Pillow)')
    parser.add_argument('--compact', '-c', action='store_true',
                        help='Compact heatmap display only')
    parser.add_argument('--json', '-j', action='store_true',
                        help='Output as JSON')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    args = parser.parse_args()

    if args.no_color:
        for attr in dir(C):
            if not attr.startswith('_'):
                setattr(C, attr, '')

    if not os.path.isfile(args.file):
        print(f"{C.RED}Error: '{args.file}' not found.{C.RESET}", file=sys.stderr)
        sys.exit(1)

    with open(args.file, 'rb') as f:
        data = f.read()

    file_size = len(data)
    overall_entropy = shannon_entropy(data)
    blocks = analyze_entropy(data, args.block_size)
    regions = find_regions(blocks, args.threshold)

    if args.json:
        import json
        output = {
            'file': os.path.abspath(args.file),
            'file_size': file_size,
            'overall_entropy': round(overall_entropy, 4),
            'block_size': args.block_size,
            'num_blocks': len(blocks),
            'blocks': [{'offset': b['offset'], 'entropy': round(b['entropy'], 4)} for b in blocks],
            'regions': regions,
        }
        print(json.dumps(output, indent=2))
        return

    # ── Header ────────────────────────────────────────────────────────────
    print_header(f"Entropy Analysis: {os.path.basename(args.file)}")
    print_field('File Size', f'{file_size:,} bytes')
    print_field('Block Size', f'{args.block_size} bytes')
    print_field('Blocks', str(len(blocks)))

    classification, color = classify_entropy(overall_entropy)
    print_field('Overall Entropy', f'{overall_entropy:.4f} / 8.0 ({color}{classification}{C.RESET})')

    # Statistics
    entropies = [b['entropy'] for b in blocks]
    print_field('Min Entropy', f'{min(entropies):.4f}')
    print_field('Max Entropy', f'{max(entropies):.4f}')
    print_field('Avg Entropy', f'{sum(entropies)/len(entropies):.4f}')

    high_count = sum(1 for e in entropies if e >= args.threshold)
    if high_count:
        print_field('High Entropy Blocks',
                    f'{C.RED}{high_count}{C.RESET} / {len(blocks)} '
                    f'({high_count/len(blocks)*100:.1f}%)')

    # ── Heatmap ───────────────────────────────────────────────────────────
    print(f"\n  {C.BOLD}Entropy Heatmap:{C.RESET}")
    print(f"  {C.DIM}Legend: {C.RESET}"
          f"{C.DIM}░null {C.GREEN}▒text {C.BLUE}▓binary "
          f"{C.YELLOW}█data {C.MAGENTA}█compressed {C.RED}█encrypted{C.RESET}")
    print()

    heatmap = generate_ascii_heatmap(blocks)
    for line in heatmap:
        print(f"  {line}")
    print()

    # ── Per-block detail ──────────────────────────────────────────────────
    if not args.compact:
        # Show a subset of blocks (up to 40 or all if small)
        display_blocks = blocks if len(blocks) <= 40 else blocks[::max(1, len(blocks)//40)]

        for block in display_blocks:
            ent = block['entropy']
            bar = entropy_bar(ent)
            label = ''
            if ent >= args.threshold:
                label = f' {C.RED}← high!{C.RESET}'
            elif ent < 1.0:
                label = f' {C.DIM}← null{C.RESET}'
            print(f"  {C.DIM}0x{block['offset']:08x}{C.RESET} {bar} {ent:.3f}{label}")

    # ── Regions ───────────────────────────────────────────────────────────
    if args.regions or regions:
        if regions:
            print_header("Detected Regions")
            for r in regions:
                size = r['end_offset'] - r['start_offset']
                if r['type'] == 'high':
                    color = C.RED
                    label = 'ENCRYPTED/COMPRESSED'
                else:
                    color = C.DIM
                    label = 'NULL/EMPTY'

                print(f"  {color}{label}{C.RESET}  "
                      f"0x{r['start_offset']:08x} — 0x{r['end_offset']:08x}  "
                      f"({size:,} bytes, avg entropy: {r['avg_entropy']:.3f})")
        else:
            print(f"\n  {C.GREEN}No significant high/low entropy regions detected.{C.RESET}")

    # ── PNG output ────────────────────────────────────────────────────────
    if args.png:
        if generate_png(blocks, args.png):
            print(f"\n  {C.GREEN}PNG graph saved to: {args.png}{C.RESET}")

    print()


if __name__ == '__main__':
    main()
