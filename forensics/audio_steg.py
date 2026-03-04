#!/usr/bin/env python3
"""
audio_steg.py - CTF Audio Forensics Toolkit

1. High-res Spectrograms to reveal hidden images/flags in frequencies
2. LSB/MSB steganography extraction from WAV samples
3. DTMF tone detection (phone keypad numbers)
4. Morse code audio detection (beep patterns)
5. Reverse audio detection
6. Multi-format support via ffmpeg conversion
"""

import argparse
import sys
import os
import struct
import tempfile

try:
    import numpy as np
    import scipy.io.wavfile as wavfile
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from scipy import signal
    from scipy.fft import fft, fftfreq
except ImportError:
    print("\033[91mError: Missing dependencies.\033[0m")
    print("Please run: pip install numpy scipy matplotlib")
    sys.exit(1)

# ANSI colors
class C:
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    CYAN    = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    RESET   = '\033[0m'

# DTMF frequency pairs
DTMF_FREQS = {
    (697, 1209): '1', (697, 1336): '2', (697, 1477): '3', (697, 1633): 'A',
    (770, 1209): '4', (770, 1336): '5', (770, 1477): '6', (770, 1633): 'B',
    (852, 1209): '7', (852, 1336): '8', (852, 1477): '9', (852, 1633): 'C',
    (941, 1209): '*', (941, 1336): '0', (941, 1477): '#', (941, 1633): 'D',
}

DTMF_LOW = [697, 770, 852, 941]
DTMF_HIGH = [1209, 1336, 1477, 1633]


def convert_to_wav(input_file):
    """Convert non-WAV files to WAV using ffmpeg."""
    import subprocess
    tmp = tempfile.NamedTemporaryFile(suffix='.wav', delete=False)
    tmp.close()
    try:
        subprocess.run(
            ['ffmpeg', '-y', '-i', input_file, '-ar', '44100', '-ac', '1', tmp.name],
            capture_output=True, check=True
        )
        return tmp.name
    except FileNotFoundError:
        print(f"  {C.RED}ffmpeg not found. Cannot convert non-WAV files.{C.RESET}")
        print(f"  {C.DIM}Install: sudo apt install ffmpeg{C.RESET}")
        return None
    except subprocess.CalledProcessError as e:
        print(f"  {C.RED}ffmpeg conversion failed: {e.stderr.decode()[:200]}{C.RESET}")
        return None


def load_audio(filepath):
    """Load audio, converting from other formats if needed."""
    ext = os.path.splitext(filepath)[1].lower()
    wav_path = filepath
    temp_file = None

    if ext not in ('.wav', '.wave'):
        print(f"  {C.YELLOW}Converting {ext} to WAV via ffmpeg...{C.RESET}")
        wav_path = convert_to_wav(filepath)
        if not wav_path:
            return None, None
        temp_file = wav_path

    try:
        sample_rate, data = wavfile.read(wav_path)
        if len(data.shape) > 1:
            data = data.mean(axis=1).astype(data.dtype)
        return sample_rate, data
    except Exception as e:
        print(f"  {C.RED}Error reading audio: {e}{C.RESET}")
        return None, None
    finally:
        if temp_file and temp_file != filepath:
            try:
                os.unlink(temp_file)
            except:
                pass


# ─── Spectrogram ─────────────────────────────────────────────────────────────

def generate_spectrogram(data, sample_rate, out_file, cmap='magma', high_res=False):
    """Generate and save a visual spectrogram."""
    print(f"\n{C.CYAN}{C.BOLD}─── Spectrogram Generator ─────────────────────────────────────{C.RESET}")
    print(f"  {C.DIM}Sample rate: {sample_rate} Hz | Duration: {len(data)/sample_rate:.2f}s{C.RESET}")

    nperseg = 2048 if high_res else 1024
    noverlap = nperseg - nperseg // 4

    f, t, Sxx = signal.spectrogram(data.astype(float), fs=sample_rate,
                                    window='hamming', nperseg=nperseg, noverlap=noverlap)

    fig, ax = plt.subplots(figsize=(18, 7))
    ax.pcolormesh(t, f, 10 * np.log10(Sxx + 1e-10), shading='gouraud', cmap=cmap)
    ax.set_ylabel('Frequency [Hz]')
    ax.set_xlabel('Time [sec]')
    ax.set_title(f'Spectrogram (nperseg={nperseg})')
    plt.colorbar(ax.collections[0], ax=ax, label='dB')
    plt.tight_layout()
    plt.savefig(out_file, dpi=200)
    plt.close()

    print(f"  {C.GREEN}▶ Spectrogram saved to:{C.RESET} {out_file}")
    print(f"  {C.YELLOW}Open this image to look for hidden text/shapes in the frequency domain.{C.RESET}")

    # Also generate a zoomed high-frequency version
    if high_res:
        hi_out = out_file.replace('.png', '_highfreq.png')
        fig, ax = plt.subplots(figsize=(18, 7))
        mask = f > sample_rate / 4
        if mask.any():
            ax.pcolormesh(t, f[mask], 10 * np.log10(Sxx[mask] + 1e-10), shading='gouraud', cmap=cmap)
            ax.set_ylabel('Frequency [Hz]')
            ax.set_xlabel('Time [sec]')
            ax.set_title('High-Frequency Detail')
            plt.tight_layout()
            plt.savefig(hi_out, dpi=200)
            plt.close()
            print(f"  {C.GREEN}▶ High-freq detail:{C.RESET} {hi_out}")


# ─── LSB Extraction ──────────────────────────────────────────────────────────

def extract_lsb(filepath, bit_idx=0, out_file=None):
    """Extract specific bit indices from raw audio samples."""
    print(f"\n{C.CYAN}{C.BOLD}─── WAV LSB Extractor ─────────────────────────────────────────{C.RESET}")

    import wave
    try:
        with wave.open(filepath, 'rb') as w:
            n_channels = w.getnchannels()
            sampwidth = w.getsampwidth()
            n_frames = w.getnframes()
            raw_data = w.readframes(n_frames)
        print(f"  {C.DIM}Channels: {n_channels} | Sample Width: {sampwidth} bytes | Frames: {n_frames}{C.RESET}")
    except Exception as e:
        print(f"  {C.RED}Error: {e}{C.RESET}")
        return

    samples = np.frombuffer(raw_data, dtype=np.uint8)
    print(f"  {C.YELLOW}Extracting bit {bit_idx} from {len(samples)} bytes...{C.RESET}")

    bits = (samples >> bit_idx) & 1
    extracted = np.packbits(bits)
    text = extracted.tobytes()

    # Check for flags
    import re
    text_str = text.decode('utf-8', errors='ignore')
    flags = re.findall(r'(?:flag|ctf|picoctf|htb)\{[^}]+\}', text_str, re.IGNORECASE)
    if flags:
        for f in flags:
            print(f"  {C.RED}{C.BOLD}⚑ FLAG: {f}{C.RESET}")

    # Show printable text
    printable = "".join(chr(c) if (32 <= c <= 126 or c in (9, 10, 13)) else '.' for c in text[:300])
    print(f"  {C.DIM}Excerpt:{C.RESET}\n  {printable[:200]}")

    # Check for file magics
    for magic, name in [
        (b'\x89PNG', 'PNG'), (b'\xff\xd8\xff', 'JPEG'), (b'PK\x03\x04', 'ZIP'),
        (b'%PDF-', 'PDF'), (b'\x7fELF', 'ELF'), (b'Rar!', 'RAR'),
    ]:
        idx = text[:1000].find(magic)
        if idx != -1:
            print(f"  {C.RED}{C.BOLD}Embedded file detected: {name} at offset {idx}{C.RESET}")

    if out_file:
        with open(out_file, 'wb') as f:
            f.write(text)
        print(f"\n  {C.GREEN}▶ Extracted to:{C.RESET} {out_file}")


# ─── DTMF Decoder ────────────────────────────────────────────────────────────

def decode_dtmf(data, sample_rate):
    """Detect DTMF tones in audio and decode to keypad digits."""
    print(f"\n{C.CYAN}{C.BOLD}─── DTMF Tone Decoder ─────────────────────────────────────────{C.RESET}")

    chunk_size = int(sample_rate * 0.05)  # 50ms chunks
    stride = int(sample_rate * 0.02)      # 20ms stride
    threshold = 0.1

    digits = []
    prev_digit = None

    data_float = data.astype(float) / max(abs(data.max()), abs(data.min()), 1)

    for start in range(0, len(data_float) - chunk_size, stride):
        chunk = data_float[start:start + chunk_size]
        
        # Apply Goertzel-like approach: compute magnitude at DTMF frequencies
        N = len(chunk)
        freqs_to_check = DTMF_LOW + DTMF_HIGH
        magnitudes = {}

        for freq in freqs_to_check:
            k = round(freq * N / sample_rate)
            if k >= N:
                continue
            # DFT at specific frequency
            omega = 2 * np.pi * k / N
            coeff = 2 * np.cos(omega)
            s0, s1, s2 = 0.0, 0.0, 0.0
            for sample in chunk:
                s0 = sample + coeff * s1 - s2
                s2 = s1
                s1 = s0
            mag = np.sqrt(s1*s1 + s2*s2 - coeff*s1*s2) / N
            magnitudes[freq] = mag

        # Find dominant low and high frequencies
        best_low = max(DTMF_LOW, key=lambda f: magnitudes.get(f, 0))
        best_high = max(DTMF_HIGH, key=lambda f: magnitudes.get(f, 0))

        if magnitudes.get(best_low, 0) > threshold and magnitudes.get(best_high, 0) > threshold:
            digit = DTMF_FREQS.get((best_low, best_high), '?')
            if digit != prev_digit:
                digits.append(digit)
                prev_digit = digit
        else:
            prev_digit = None

    if not digits:
        print(f"  {C.DIM}No DTMF tones detected.{C.RESET}")
        return

    result = ''.join(digits)
    print(f"  {C.GREEN}▶ Decoded DTMF: {C.BOLD}{result}{C.RESET}")
    print(f"  {C.DIM}Total digits: {len(digits)}{C.RESET}")

    # Try to interpret as ASCII (phone number or text)
    if all(d.isdigit() for d in digits):
        # Pairs of digits = ASCII?
        if len(digits) >= 4 and len(digits) % 2 == 0:
            try:
                ascii_text = ''.join(chr(int(digits[i:i+2])) for i in range(0, len(digits), 2)
                                     if 32 <= int(digits[i:i+2]) <= 126)
                if ascii_text:
                    print(f"  {C.YELLOW}As ASCII pairs: {ascii_text}{C.RESET}")
            except:
                pass


# ─── Morse Audio Decoder ─────────────────────────────────────────────────────

def decode_morse_audio(data, sample_rate):
    """Detect morse code beeps in audio."""
    print(f"\n{C.CYAN}{C.BOLD}─── Morse Code Audio Decoder ──────────────────────────────────{C.RESET}")

    MORSE_TO_CHAR = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
        '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
        '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
        '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
        '--..': 'Z', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
        '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9',
        '-----': '0',
    }

    data_float = np.abs(data.astype(float))
    avg = np.mean(data_float)
    threshold = avg * 2

    # Find "on" and "off" regions
    is_on = data_float > threshold
    chunk_ms = 10
    chunk_size = int(sample_rate * chunk_ms / 1000)

    regions = []
    for i in range(0, len(is_on), chunk_size):
        chunk = is_on[i:i+chunk_size]
        regions.append(np.mean(chunk) > 0.5)

    # Extract on/off durations
    durations = []
    current = regions[0] if regions else False
    count = 0
    for r in regions:
        if r == current:
            count += 1
        else:
            durations.append((current, count * chunk_ms))
            current = r
            count = 1
    if count > 0:
        durations.append((current, count * chunk_ms))

    on_durations = [d for is_on, d in durations if is_on]
    if not on_durations:
        print(f"  {C.DIM}No clear tone patterns detected.{C.RESET}")
        return

    # Classify dot vs dash
    avg_on = np.median(on_durations)
    dot_threshold = avg_on * 1.5

    morse_string = ''
    for is_on_val, dur in durations:
        if is_on_val:
            if dur < dot_threshold:
                morse_string += '.'
            else:
                morse_string += '-'
        else:
            if dur > avg_on * 5:
                morse_string += ' / '
            elif dur > avg_on * 2:
                morse_string += ' '

    print(f"  {C.DIM}Raw: {morse_string[:150]}{C.RESET}")

    # Decode
    words = morse_string.split('/')
    decoded = ''
    for word in words:
        letters = word.strip().split()
        for letter in letters:
            decoded += MORSE_TO_CHAR.get(letter.strip(), '?')
        decoded += ' '

    decoded = decoded.strip()
    if decoded and decoded != '?':
        print(f"  {C.GREEN}▶ Decoded: {C.BOLD}{decoded}{C.RESET}")

        import re
        flags = re.findall(r'(?:flag|ctf|picoctf|htb)\{[^}]+\}', decoded, re.IGNORECASE)
        for f in flags:
            print(f"  {C.RED}{C.BOLD}⚑ FLAG: {f}{C.RESET}")
    else:
        print(f"  {C.DIM}Could not decode morse. Signal may be too noisy.{C.RESET}")


# ─── Reverse Audio Check ─────────────────────────────────────────────────────

def check_reverse(data, sample_rate, out_file):
    """Save a reversed copy of the audio."""
    print(f"\n{C.CYAN}{C.BOLD}─── Reverse Audio ─────────────────────────────────────────────{C.RESET}")

    reversed_data = data[::-1]
    wavfile.write(out_file, sample_rate, reversed_data)
    print(f"  {C.GREEN}▶ Reversed audio saved to:{C.RESET} {out_file}")
    print(f"  {C.DIM}Play this file to check for backward messages.{C.RESET}")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='CTF Audio Forensics Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s audio.wav -s                  # Spectrogram
  %(prog)s audio.wav -s --cmap gray      # Grayscale spectrogram
  %(prog)s audio.wav -s --hires          # High resolution spectrogram
  %(prog)s audio.wav -l                  # LSB extraction
  %(prog)s audio.wav -l --bit 1          # Extract bit 1
  %(prog)s audio.wav --dtmf              # DTMF tone decoding
  %(prog)s audio.wav --morse             # Morse code detection
  %(prog)s audio.wav --reverse           # Save reversed audio
  %(prog)s audio.mp3 -s                  # Non-WAV (converts via ffmpeg)
  %(prog)s audio.wav                     # Run all analyses
""")

    parser.add_argument('file', help='Target audio file (WAV, MP3, FLAC, OGG)')

    parser.add_argument('-s', '--spectrogram', action='store_true', help='Generate spectrogram')
    parser.add_argument('-l', '--lsb', action='store_true', help='Extract LSB steganography')
    parser.add_argument('--dtmf', action='store_true', help='Detect DTMF tones')
    parser.add_argument('--morse', action='store_true', help='Detect morse code beeps')
    parser.add_argument('--reverse', action='store_true', help='Save reversed audio')

    parser.add_argument('--bit', type=int, default=0, help='Bit index for LSB (0=LSB, 7=MSB)')
    parser.add_argument('--cmap', default='magma', help='Colormap (magma, gray, viridis, inferno)')
    parser.add_argument('--hires', action='store_true', help='High-resolution spectrogram')
    parser.add_argument('-o', '--out', help='Output file')

    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"{C.RED}Error: File '{args.file}' not found.{C.RESET}")
        sys.exit(1)

    print(f"\n  {C.BOLD}Analyzing Audio: {args.file}{C.RESET}")

    run_all = not any([args.spectrogram, args.lsb, args.dtmf, args.morse, args.reverse])

    # Load audio (with format conversion)
    sample_rate, data = load_audio(args.file)
    if data is None:
        sys.exit(1)

    print(f"  {C.DIM}Sample Rate: {sample_rate} Hz | Duration: {len(data)/sample_rate:.2f}s | Samples: {len(data):,}{C.RESET}")

    if args.spectrogram or run_all:
        out = args.out if args.out else 'spectrogram.png'
        generate_spectrogram(data, sample_rate, out, args.cmap, args.hires)

    if args.lsb or run_all:
        ext = os.path.splitext(args.file)[1].lower()
        wav_path = args.file
        if ext not in ('.wav', '.wave'):
            wav_path = convert_to_wav(args.file)
            if not wav_path:
                print(f"  {C.RED}LSB requires WAV format.{C.RESET}")
            else:
                out = args.out if args.out else 'extracted_audio.bin'
                extract_lsb(wav_path, args.bit, out)
                os.unlink(wav_path)
        else:
            out = args.out if args.out else 'extracted_audio.bin'
            extract_lsb(wav_path, args.bit, out)

    if args.dtmf or run_all:
        decode_dtmf(data, sample_rate)

    if args.morse or run_all:
        decode_morse_audio(data, sample_rate)

    if args.reverse:
        out = args.out if args.out else 'reversed_audio.wav'
        check_reverse(data, sample_rate, out)

    print()


if __name__ == '__main__':
    main()
