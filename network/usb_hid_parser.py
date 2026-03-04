#!/usr/bin/env python3
"""
usb_hid_parser.py - CTF USB Packet Forensics Toolkit

Translates USB HID Leftover Capture Data from PCAPs:
- Reconstructs keyboard keystrokes (handles shift/caps lock).
- Plots mouse movements to reveal drawn objects/text.
"""

import argparse
import sys
import os

try:
    from scapy.all import rdpcap
except ImportError:
    print("\033[91mError: scapy not installed.\033[0m")
    print("Please install it running: pip install scapy")
    sys.exit(1)

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

# standard USB keyboard map (HID codes)
# Maps byte code to (lowercase_char, uppercase_char)
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
    40: ('[ENTER]\n', '[ENTER]\n'), 41: ('[ESC]', '[ESC]'), 
    42: ('[BACKSPACE]', '[BACKSPACE]'), 43: ('[TAB]', '[TAB]'),
    44: (' ', ' '), 45: ('-', '_'), 46: ('=', '+'), 47: ('[', '{'),
    48: (']', '}'), 49: ('\\', '|'), 51: (';', ':'), 52: ("'", '"'),
    53: ('`', '~'), 54: (',', '<'), 55: ('.', '>'), 56: ('/', '?'),
    57: ('[CAPSLOCK]', '[CAPSLOCK]'),
    # Numpad
    89: ('1', '1'), 90: ('2', '2'), 91: ('3', '3'), 92: ('4', '4'),
    93: ('5', '5'), 94: ('6', '6'), 95: ('7', '7'), 96: ('8', '8'),
    97: ('9', '9'), 98: ('0', '0')
}

has_matplotlib = True
try:
    import matplotlib.pyplot as plt
except ImportError:
    has_matplotlib = False


def extract_usb_data(pcap_file):
    """Extract Leftover Capture Data / USB URB data from packets."""
    packets = rdpcap(pcap_file)
    usb_data = []
    
    # Simple heuristic to find USB interrupt IN payloads
    # Usually length 8 for keyboard, 4 for basic mouse
    for pkt in packets:
        raw = bytes(pkt)
        # Attempt to isolate the USB data payload at the end of the frame.
        # This is a generic approach since USB pcap encapsulations vary greatly 
        # (usb.capdata vs usb.urb_data vs usb.leftover).
        # Typically the actual HID data is the last 8 bytes or 4 bytes.
        
        # Look for length 8 (kbd) or 4 (mouse) payloads
        if len(raw) >= 8:
            # check back from end. Keyboard: 00 00 [key] 00 00 00 00 00
            if len(raw) > 27: 
                # USB URB often has 27-64 bytes header
                payload = raw[-8:] # Keyboard
                if len(payload) == 8 and payload[2] != 0:
                    usb_data.append(payload)
                elif len(raw[-4:]) == 4: # Mouse
                    usb_data.append(raw[-4:])
    
    return usb_data

def usb_tshark_extract(pcap_file, filter_str):
    """It's much more reliable to use tshark if installed for USB data."""
    import subprocess
    cmd = ['tshark', '-r', pcap_file, '-Y', filter_str, '-T', 'fields', '-e', 'usb.capdata']
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')
        # Tshark outputs hex with colons '00:00:1c:...'
        parsed = []
        for line in lines:
            if line:
                parsed.append(bytes.fromhex(line.replace(':', '')))
        return parsed
    except Exception:
        return None


def parse_keyboard(pcap_file):
    """Reconstruct keystrokes from USB keyboard packets."""
    print(f"\n{C.CYAN}{C.BOLD}─── USB Keyboard Keystrokes ───────────────────────────────────{C.RESET}")
    
    # Try tshark first as it accurately extracts exactly usb.capdata
    data = usb_tshark_extract(pcap_file, 'usb.transfer_type == 0x01 and frame.len == 35')
    if data is None:
        print(f"  {C.YELLOW}Warning: tshark not found or failed. Using loose scapy extraction.{C.RESET}")
        raw_data = extract_usb_data(pcap_file)
        data = [d for d in raw_data if len(d) == 8]
    else:
        # Filter purely for length 8 keyboard packets
        data = [d for d in data if len(d) == 8]
        
    if not data:
        print(f"  {C.DIM}No USB keyboard data found.{C.RESET}")
        return

    output = ""
    shift_pressed = False
    caps_lock = False
    
    for packet in data:
        mod = packet[0] # Modifiers byte
        key = packet[2] # Keycode byte
        
        if key == 0:
            continue
            
        # Modifiers: bit 1 = Left Shift, bit 5 = Right Shift
        shift_pressed = (mod & 0x02) or (mod & 0x20)
        
        if key in KEYBOARD_MAP:
            if key == 57: # CAPS LOCK
                caps_lock = not caps_lock
                continue
                
            char_tuple = KEYBOARD_MAP[key]
            
            # Apply shift/caps lock rules
            if char_tuple[0].isalpha():
                use_upper = shift_pressed ^ caps_lock
            else:
                use_upper = shift_pressed
                
            char = char_tuple[1] if use_upper else char_tuple[0]
            
            if char == '[BACKSPACE]':
                output = output[:-1]
            elif char in ('[ENTER]\n', '[TAB]', '[ESC]'):
                output += char
            else:
                output += char

    print(f"\n{C.BOLD}Raw Output:{C.RESET}")
    print(output)
    print()


def parse_mouse(pcap_file, out_file):
    """Reconstruct mouse movements and draw them."""
    print(f"\n{C.CYAN}{C.BOLD}─── USB Mouse Movements ───────────────────────────────────────{C.RESET}")
    
    if not has_matplotlib:
        print(f"  {C.RED}Error: matplotlib is required to plot mouse movements.{C.RESET}")
        print(f"  {C.DIM}Install it: pip install matplotlib{C.RESET}")
        return

    # Try tshark first
    data = usb_tshark_extract(pcap_file, 'usb.transfer_type == 0x01 and frame.len == 31')
    if data is None:
        raw_data = extract_usb_data(pcap_file)
        data = [d for d in raw_data if len(d) == 4]
    else:
        # Filter for length 4 mouse packets
        data = [d for d in data if len(d) == 4]

    if not data:
        print(f"  {C.DIM}No USB mouse data found.{C.RESET}")
        return

    x_pos = 0
    y_pos = 0
    
    X = []
    Y = []
    
    for packet in data:
        # standard 4-byte mouse packet
        # Byte 0: Button status (bit 0 = left click)
        # Byte 1: X movement (signed 8-bit)
        # Byte 2: Y movement (signed 8-bit)
        # Byte 3: Wheel movement
        
        btn = packet[0]
        dx = packet[1]
        dy = packet[2]
        
        # Convert to signed int
        if dx > 127: dx -= 256
        if dy > 127: dy -= 256
            
        x_pos += dx
        y_pos += dy
        
        # Only plot if left click is held down (drawing)
        if btn == 1:
            X.append(x_pos)
            # Y is inverted in screen coords vs math coords
            Y.append(-y_pos)  

    if not X:
        print(f"  {C.DIM}Mouse data found, but no 'drawing' (left-click drag) occurred.{C.RESET}")
        return

    img_path = out_file if out_file else 'mouse_movement.png'
    
    plt.figure(figsize=(10, 6))
    # Scatter plot, because lines might connect between separate letter drawing strokes
    plt.scatter(X, Y, s=5, c='blue', alpha=0.5)
    plt.axis('off')
    plt.savefig(img_path)
    
    print(f"  {C.GREEN}▶ Plot saved to:{C.RESET} {img_path}")
    print(f"  {C.DIM}Open this image to see what was drawn (often text/flags).{C.RESET}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description='CTF USB Packet Forensics Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Requires 'tshark' (from Wireshark) to be installed in your PATH for highest accuracy.
Otherwise falls back to scapy heuristic matching.
""")
    
    parser.add_argument('pcap', help='Path to USB PCAP/PCAPNG file')
    
    parser.add_argument('--keyboard', '-k', action='store_true', help='Reconstruct keyboard keystrokes')
    parser.add_argument('--mouse', '-m', action='store_true', help='Reconstruct mouse drawing')
    parser.add_argument('--plot', '-p', default='', help='Output file for mouse plot (default: mouse_movement.png)')

    args = parser.parse_args()
    
    if not os.path.isfile(args.pcap):
        print(f"{C.RED}Error: File '{args.pcap}' not found.{C.RESET}")
        sys.exit(1)

    print(f"\n  {C.BOLD}Analyzing USB Capture: {args.pcap}{C.RESET}")
    
    run_all = not (args.keyboard or args.mouse)
    
    if args.keyboard or run_all:
        parse_keyboard(args.pcap)
        
    if args.mouse or run_all:
        parse_mouse(args.pcap, args.plot)


if __name__ == '__main__':
    main()
