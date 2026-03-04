#!/usr/bin/env python3
"""
audio_steg.py - CTF Audio Forensics Toolkit

1. Generates high-res Spectrograms to reveal hidden images/flags in audio frequencies.
2. Extracts LSB/MSB steganography from WAV samples.
"""

import argparse
import sys
import os

try:
    import numpy as np
    import scipy.io.wavfile as wav
    import matplotlib.pyplot as plt
    from scipy import signal
except ImportError:
    print("\033[91mError: Missing dependencies for audio forensics.\033[0m")
    print("Please run: pip install numpy scipy matplotlib")
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


def generate_spectrogram(wav_file, out_file, cmap='magma'):
    """Generate and save a visual spectrogram of the audio."""
    print(f"\n{C.CYAN}{C.BOLD}─── Audio Spectrogram Generator ───────────────────────────────{C.RESET}")
    
    try:
        sample_rate, data = wav.read(wav_file)
    except Exception as e:
        print(f"  {C.RED}Error reading WAV file: {e}{C.RESET}")
        return

    # If stereo, average down to mono
    if len(data.shape) > 1:
        data = data.mean(axis=1)

    print(f"  {C.DIM}Analyzing sample rate: {sample_rate} Hz{C.RESET}")
    print(f"  {C.DIM}Duration: {len(data) / sample_rate:.2f} seconds{C.RESET}")

    plt.figure(figsize=(16, 6))
    
    # Generate spectrogram using scipy
    f, t, Sxx = signal.spectrogram(data, fs=sample_rate, window=('hamming'),
                                   nperseg=1024, noverlap=512)
                                   
    # Plot taking log to make faint signals (like flags) pop
    plt.pcolormesh(t, f, 10 * np.log10(Sxx + 1e-10), shading='gouraud', cmap=cmap)
    plt.ylabel('Frequency [Hz]')
    plt.xlabel('Time [sec]')
    plt.title(f'Spectrogram: {os.path.basename(wav_file)}')
    plt.colorbar(label='Intensity [dB]')
    
    plt.tight_layout()
    plt.savefig(out_file, dpi=200)
    plt.close()
    
    print(f"  {C.GREEN}▶ Spectrogram saved to:{C.RESET} {out_file}")
    print(f"  {C.YELLOW}Open this image to look for text/shapes drawn in the audio frequencies.{C.RESET}\n")


def extract_lsb(wav_file, bit_idx=0, out_file=None):
    """Extract specific bit indices from the raw 1D audio samples."""
    print(f"\n{C.CYAN}{C.BOLD}─── WAV LSB Extractor ─────────────────────────────────────────{C.RESET}")
    
    try:
        # Get raw bytes rather than normalized float data
        import wave
        with wave.open(wav_file, 'rb') as w:
            n_channels = w.getnchannels()
            sampwidth = w.getsampwidth()
            n_frames = w.getnframes()
            
            raw_data = w.readframes(n_frames)
            
        print(f"  {C.DIM}Channels: {n_channels} | Sample Width: {sampwidth} bytes{C.RESET}")
    except Exception as e:
        print(f"  {C.RED}Error reading WAV file bytes: {e}{C.RESET}")
        return

    # We treat it as an array of 8-bit integers regardless of sample width to extract specific bits
    # E.g if it's 16-bit, we treat it as two 8-bit blocks
    samples = np.frombuffer(raw_data, dtype=np.uint8)
    
    print(f"  {C.YELLOW}⟳ Extracting bit {bit_idx} from {len(samples)} bytes...{C.RESET}")
    
    # Extract
    bits = (samples >> bit_idx) & 1
    
    # Pack into bytes
    extracted = np.packbits(bits)
    
    # Look for flags in the leading bytes
    text = extracted.tobytes()
    
    # Look for magic
    if b'flag{' in text.lower() or b'ctf{' in text.lower():
        print(f"  {C.RED}{C.BOLD}⚑ FLAG PATTERN DETECTED!{C.RESET}")
        
    # Check if mostly printable
    printable = "".join(chr(c) if (32 <= c <= 126 or c in (9,10,13)) else '.' for c in text[:200])
    
    print(f"  {C.DIM}Excerpt:{C.RESET}\n  {printable}")
    
    if out_file:
        with open(out_file, 'wb') as f:
            f.write(text)
        print(f"\n  {C.GREEN}▶ Extracted binary dumped to:{C.RESET} {out_file}")


def main():
    parser = argparse.ArgumentParser(
        description='CTF Audio Forensics Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s audio.wav -s               # Generate Spectrogram
  %(prog)s audio.wav -s --cmap gray   # Grayscale spectrogram
  %(prog)s audio.wav -l               # Extract LSB data
  %(prog)s audio.wav -l --bit 1       # Extract bit 1
""")
    
    parser.add_argument('file', help='Target WAV file')
    
    parser.add_argument('-s', '--spectrogram', action='store_true', help='Generate high-res spectrogram')
    parser.add_argument('-l', '--lsb', action='store_true', help='Extract bit-level steganography')
    
    parser.add_argument('--bit', type=int, default=0, help='Bit index to extract (0=LSB, 7=MSB)')
    parser.add_argument('--cmap', default='magma', help='Colormap for spectrogram (magma, gray, viridis)')
    parser.add_argument('-o', '--out', help='Output file (for plot or binary dump)')

    args = parser.parse_args()
    
    if not os.path.isfile(args.file):
        print(f"{C.RED}Error: File '{args.file}' not found.{C.RESET}")
        sys.exit(1)

    print(f"\n  {C.BOLD}Analyzing Audio: {args.file}{C.RESET}")
    
    run_all = not (args.spectrogram or args.lsb)
    
    if args.spectrogram or run_all:
        out = args.out if args.out else 'spectrogram.png'
        generate_spectrogram(args.file, out, args.cmap)
        
    if args.lsb or run_all:
        out = args.out if args.out else 'extracted_audio.bin'
        extract_lsb(args.file, args.bit, out)
        
    print()


if __name__ == '__main__':
    main()
