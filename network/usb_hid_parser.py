#!/usr/bin/env python3
"""
usb_hid_parser.py - CTF USB Packet Forensics Toolkit

Translates USB HID Leftover Capture Data from PCAPs:
- Reconstructs keyboard keystrokes (handles shift/caps lock/ctrl)
- Plots mouse movements to reveal drawn objects/text
- Supports raw hex file input (tshark extracted)
- Detects and labels modifier combos (Ctrl+C, Alt+Tab etc.)
"""

import argparse
import sys
import os
import re

try:
    from scapy.all import rdpcap
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

# ANSI colors
class C:
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    CYAN    = '\033[96m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    RESET   = '\033[0m'

# USB HID keyboard map
KEYBOARD_MAP = {
    4: ('a', 'A'), 5: ('b', 'B'), 6: ('c', 'C'), 7: ('d', 'D'),
    8: ('e', 'E'), 9: ('f', 'F'), 10: ('g', 'G'), 11: ('h', 'H'),
    12: ('i', 'I'), 13: ('j', 'J'), 14: ('k', 'K'), 15: ('l', 'L'),
    16: ('m', 'M'), 17: ('n', 'N'), 18: ('o', 'O'), 19: ('p', 'P'),
    20: ('q', 'Q'), 21: ('r', 'R'), 22: ('s', 'S'), 23: ('t', 'T'),
    24: ('u', 'U'), 25: ('v', 'V'), 26: ('w', 'W'), 27: ('x', 'X'),
    28: ('y', 'Y'), 29: ('z', 'Z'),
    30: ('1', '!'), 31: ('2', '@'), 32: ('3', '#'), 33: ('4', '$'),
    34: ('5', '%'), 35: ('6', '^'), 36: ('7', '&'), 37: ('8', '*'),
    38: ('9', '('), 39: ('0', ')'),
    40: ('\n', '\n'), 41: ('[ESC]', '[ESC]'),
    42: ('[BKSP]', '[BKSP]'), 43: ('\t', '\t'),
    44: (' ', ' '), 45: ('-', '_'), 46: ('=', '+'), 47: ('[', '{'),
    48: (']', '}'), 49: ('\\', '|'), 51: (';', ':'), 52: ("'", '"'),
    53: ('`', '~'), 54: (',', '<'), 55: ('.', '>'), 56: ('/', '?'),
    57: ('[CAPSLOCK]', '[CAPSLOCK]'),
    58: ('[F1]', '[F1]'), 59: ('[F2]', '[F2]'), 60: ('[F3]', '[F3]'),
    61: ('[F4]', '[F4]'), 62: ('[F5]', '[F5]'), 63: ('[F6]', '[F6]'),
    64: ('[F7]', '[F7]'), 65: ('[F8]', '[F8]'), 66: ('[F9]', '[F9]'),
    67: ('[F10]', '[F10]'), 68: ('[F11]', '[F11]'), 69: ('[F12]', '[F12]'),
    73: ('[INS]', '[INS]'), 74: ('[HOME]', '[HOME]'), 75: ('[PGUP]', '[PGUP]'),
    76: ('[DEL]', '[DEL]'), 77: ('[END]', '[END]'), 78: ('[PGDN]', '[PGDN]'),
    79: ('[RIGHT]', '[RIGHT]'), 80: ('[LEFT]', '[LEFT]'),
    81: ('[DOWN]', '[DOWN]'), 82: ('[UP]', '[UP]'),
    # Numpad
    89: ('1', '1'), 90: ('2', '2'), 91: ('3', '3'), 92: ('4', '4'),
    93: ('5', '5'), 94: ('6', '6'), 95: ('7', '7'), 96: ('8', '8'),
    97: ('9', '9'), 98: ('0', '0'), 99: ('.', '.'),
    85: ('*', '*'), 86: ('-', '-'), 87: ('+', '+'), 88: ('\n', '\n'),
}

has_matplotlib = True
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
except ImportError:
    has_matplotlib = False


def load_from_pcap(pcap_file):
    """Extract USB data from a PCAP file using tshark first, then scapy."""
    # Try tshark first (most accurate)
    data_8 = _tshark_extract(pcap_file, 'usb.capdata', 'usb.transfer_type == 0x01')
    if data_8 is None:
        data_8 = _tshark_extract(pcap_file, 'usbhid.data', '')
    if data_8 is None and HAS_SCAPY:
        data_8 = _scapy_extract(pcap_file)
    if data_8 is None:
        data_8 = []
    return data_8


def _tshark_extract(pcap_file, field, display_filter):
    """Use tshark to extract USB data fields."""
    import subprocess
    cmd = ['tshark', '-r', pcap_file, '-T', 'fields', '-e', field]
    if display_filter:
        cmd.extend(['-Y', display_filter])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return None
        lines = [l.strip() for l in result.stdout.strip().split('\n') if l.strip()]
        parsed = []
        for line in lines:
            try:
                parsed.append(bytes.fromhex(line.replace(':', '')))
            except:
                pass
        return parsed if parsed else None
    except Exception:
        return None


def _scapy_extract(pcap_file):
    """Fallback: extract from scapy raw packets."""
    packets = rdpcap(pcap_file)
    usb_data = []
    for pkt in packets:
        raw = bytes(pkt)
        if len(raw) >= 8:
            payload = raw[-8:]
            if len(payload) == 8 and payload[2] != 0:
                usb_data.append(payload)
    return usb_data


def load_from_hex_file(hex_file):
    """Load pre-extracted hex data from a text file (one packet per line)."""
    data = []
    with open(hex_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                data.append(bytes.fromhex(line.replace(':', '').replace(' ', '').replace('0x', '')))
            except:
                pass
    return data


# ─── Keyboard Parser ─────────────────────────────────────────────────────────

def parse_keyboard(data, raw_output=False):
    """Reconstruct keystrokes from USB keyboard packets."""
    print(f"\n{C.CYAN}{C.BOLD}─── USB Keyboard Keystrokes ───────────────────────────────────{C.RESET}")

    kbd_data = [d for d in data if len(d) == 8]
    if not kbd_data:
        print(f"  {C.DIM}No USB keyboard data found (need 8-byte packets).{C.RESET}")
        return ""

    output = ""
    raw_events = []
    caps_lock = False
    prev_key = 0

    for packet in kbd_data:
        mod = packet[0]
        key = packet[2]

        if key == 0 or key == prev_key:
            prev_key = key
            continue
        prev_key = key

        shift_pressed = bool(mod & 0x22)  # Left or Right Shift
        ctrl_pressed = bool(mod & 0x11)   # Left or Right Ctrl
        alt_pressed = bool(mod & 0x44)    # Left or Right Alt

        if key == 57:  # CAPS LOCK
            caps_lock = not caps_lock
            if raw_output:
                raw_events.append('[CAPSLOCK]')
            continue

        if key in KEYBOARD_MAP:
            char_tuple = KEYBOARD_MAP[key]

            # Modifier combos
            if ctrl_pressed and key in KEYBOARD_MAP:
                combo = f"[Ctrl+{char_tuple[1]}]"
                raw_events.append(combo)
                # Don't add to output for Ctrl combos
                continue
            if alt_pressed and key in KEYBOARD_MAP:
                raw_events.append(f"[Alt+{char_tuple[1]}]")
                continue

            if char_tuple[0].isalpha() and len(char_tuple[0]) == 1:
                use_upper = shift_pressed ^ caps_lock
            else:
                use_upper = shift_pressed

            char = char_tuple[1] if use_upper else char_tuple[0]

            if char == '[BKSP]':
                raw_events.append('[BKSP]')
                output = output[:-1]
            elif char == '[DEL]':
                raw_events.append('[DEL]')
            elif char.startswith('[') and char.endswith(']'):
                raw_events.append(char)
            else:
                raw_events.append(char)
                output += char
        else:
            raw_events.append(f'[0x{key:02x}]')

    if raw_output:
        print(f"\n{C.BOLD}Raw Events:{C.RESET}")
        print(''.join(raw_events))

    print(f"\n{C.BOLD}Reconstructed Text:{C.RESET}")
    print(output)

    # Check for flags
    import re
    flags = re.findall(r'(?:flag|ctf|picoctf|htb)\{[^}]+\}', output, re.IGNORECASE)
    if flags:
        for f in flags:
            print(f"\n  {C.RED}{C.BOLD}⚑ FLAG: {f}{C.RESET}")

    print()
    return output


# ─── Mouse Parser ────────────────────────────────────────────────────────────

def parse_mouse(data, out_file, show_all=False):
    """Reconstruct mouse movements and draw them."""
    print(f"\n{C.CYAN}{C.BOLD}─── USB Mouse Movements ───────────────────────────────────────{C.RESET}")

    if not has_matplotlib:
        print(f"  {C.RED}Error: matplotlib required. pip install matplotlib{C.RESET}")
        return

    mouse_data = [d for d in data if len(d) in (3, 4, 5, 6, 7, 8)]
    if not mouse_data:
        print(f"  {C.DIM}No USB mouse data found.{C.RESET}")
        return

    x_pos = 0
    y_pos = 0

    # Separate clicked vs all movement
    X_click = []
    Y_click = []
    X_all = []
    Y_all = []

    for packet in mouse_data:
        if len(packet) < 3:
            continue

        btn = packet[0]
        dx = packet[1]
        dy = packet[2]

        if dx > 127: dx -= 256
        if dy > 127: dy -= 256

        x_pos += dx
        y_pos += dy

        X_all.append(x_pos)
        Y_all.append(-y_pos)

        if btn & 1:  # Left click held
            X_click.append(x_pos)
            Y_click.append(-y_pos)

    img_path = out_file if out_file else 'mouse_movement.png'

    fig, axes = plt.subplots(1, 2 if show_all else 1, figsize=(16 if show_all else 10, 6))

    if show_all:
        ax1, ax2 = axes
        ax1.scatter(X_click, Y_click, s=3, c='blue', alpha=0.5)
        ax1.set_title('Left-Click Drawing')
        ax1.axis('off')

        ax2.plot(X_all, Y_all, linewidth=0.5, color='gray', alpha=0.3)
        ax2.scatter(X_click, Y_click, s=3, c='red', alpha=0.7)
        ax2.set_title('All Movement + Clicks')
        ax2.axis('off')
    else:
        ax = axes if not show_all else axes[0]
        if X_click:
            ax.scatter(X_click, Y_click, s=3, c='blue', alpha=0.5)
            ax.set_title('Left-Click Drawing')
        else:
            ax.plot(X_all, Y_all, linewidth=0.5, color='blue', alpha=0.5)
            ax.set_title('All Mouse Movement (no clicks detected)')
        ax.axis('off')

    plt.tight_layout()
    plt.savefig(img_path, dpi=200)
    plt.close()

    click_info = f" ({len(X_click)} click points)" if X_click else " (no clicks, showing all movement)"
    print(f"  {C.GREEN}▶ Plot saved to:{C.RESET} {img_path}{click_info}")
    print(f"  {C.DIM}Open this image to see what was drawn.{C.RESET}\n")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='CTF USB Packet Forensics Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Input formats:
  PCAP file     - Uses tshark (preferred) or scapy to extract USB data
  Hex text file - One hex packet per line (tshark pre-extracted output)

Examples:
  %(prog)s usb.pcap -k           # Keyboard keystrokes from PCAP
  %(prog)s usb.pcap -m           # Mouse movement plot
  %(prog)s usb.pcap -k --raw     # Show raw events (backspaces, modifiers)
  %(prog)s data.txt --hex -k     # From pre-extracted hex file
  %(prog)s usb.pcap -m --all     # Show both click-only and full movement plots
""")

    parser.add_argument('input', help='PCAP file or hex text file (with --hex)')
    parser.add_argument('--hex', action='store_true', help='Input is a text file with hex packets (one per line)')

    parser.add_argument('-k', '--keyboard', action='store_true', help='Reconstruct keyboard keystrokes')
    parser.add_argument('-m', '--mouse', action='store_true', help='Reconstruct mouse drawing')
    parser.add_argument('-p', '--plot', default='', help='Output file for mouse plot')
    parser.add_argument('--raw', action='store_true', help='Show raw keyboard events including modifiers')
    parser.add_argument('--all', action='store_true', help='For mouse: show both click and full movement')
    parser.add_argument('-o', '--output', help='Save keyboard output to text file')

    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"{C.RED}Error: File '{args.input}' not found.{C.RESET}")
        sys.exit(1)

    print(f"\n  {C.BOLD}Analyzing USB Capture: {args.input}{C.RESET}")

    # Load data
    if args.hex:
        data = load_from_hex_file(args.input)
    else:
        if not HAS_SCAPY:
            import subprocess
            try:
                subprocess.run(['tshark', '--version'], capture_output=True, check=True)
            except:
                print(f"{C.RED}Error: Neither scapy nor tshark available.{C.RESET}")
                print(f"Install one: pip install scapy  OR  sudo apt install tshark")
                sys.exit(1)
        data = load_from_pcap(args.input)

    if not data:
        print(f"  {C.RED}No USB HID data extracted from input.{C.RESET}")
        sys.exit(1)

    print(f"  {C.DIM}Extracted {len(data)} packets{C.RESET}")

    run_all = not (args.keyboard or args.mouse)

    if args.keyboard or run_all:
        text = parse_keyboard(data, args.raw)
        if args.output and text:
            with open(args.output, 'w') as f:
                f.write(text)
            print(f"  {C.GREEN}Saved keyboard output to: {args.output}{C.RESET}")

    if args.mouse or run_all:
        parse_mouse(data, args.plot, args.all)


if __name__ == '__main__':
    main()
