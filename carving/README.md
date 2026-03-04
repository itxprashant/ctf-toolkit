# 🔬 CTF Binary Analysis / Carving Toolkit

Binwalk-style tools for firmware analysis, file carving, and entropy visualization. Pure Python, no external dependencies.

## Scripts

| Script | Description |
|--------|-------------|
| `file_carver.py` | Scan & extract embedded files — pure Python binwalk alternative (35+ signatures) |
| `entropy_visualizer.py` | Block entropy heatmap, region detection, optional PNG graph |
| `firmware_analyzer.py` | Firmware headers, filesystem ID, bootloaders, secrets scanning |

## Quick Reference

### File Carver (Binwalk Alternative)
```bash
python3 file_carver.py firmware.bin                          # Scan only
python3 file_carver.py firmware.bin --extract                # Scan + extract
python3 file_carver.py blob.dat -e --output-dir carved/      # Extract to dir
python3 file_carver.py data.bin --min-size 1024              # Skip small matches
python3 file_carver.py data.bin --json                       # JSON output
```

Detected formats: PNG, JPEG, GIF, BMP, ZIP, GZIP, BZIP2, XZ, 7z, RAR, PDF, ELF, PE, SquashFS, U-Boot, UBI, JFFS2, CramFS, DTB, SQLite, PEM certs, and more.

### Entropy Visualizer
```bash
python3 entropy_visualizer.py firmware.bin                   # ASCII heatmap
python3 entropy_visualizer.py blob.bin --block-size 1024     # Larger blocks
python3 entropy_visualizer.py data --png entropy.png         # PNG graph
python3 entropy_visualizer.py data --regions                 # Show enc/comp regions
python3 entropy_visualizer.py data --compact                 # Heatmap only
```

### Firmware Analyzer
```bash
python3 firmware_analyzer.py router.bin                      # Detect structures
python3 firmware_analyzer.py iot_dump.bin --strings           # Find URLs, IPs, keys
python3 firmware_analyzer.py blob.bin --all                   # Everything
python3 firmware_analyzer.py blob.bin --json                  # JSON output
```

## Typical CTF Workflow

```bash
# 1. Quick scan for embedded files
python3 file_carver.py challenge.bin

# 2. Entropy analysis — spot encrypted/compressed regions
python3 entropy_visualizer.py challenge.bin --regions

# 3. Extract embedded files
python3 file_carver.py challenge.bin --extract --output-dir out/

# 4. Firmware deep dive — headers, secrets
python3 firmware_analyzer.py challenge.bin --all
```
