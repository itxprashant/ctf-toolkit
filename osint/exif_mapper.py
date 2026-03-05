#!/usr/bin/env python3
"""
exif_mapper.py - CTF Geographic Metadata Visualizer

Scans a directory for images, extracts GPS coordinates
using exiftool (or PIL fallback), and generates an interactive
Leaflet HTML map to visualize the locations.
"""

import argparse
import sys
import os
import subprocess
import json

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
except ImportError:
    print("\033[91mError: Pillow not installed.\033[0m")
    print("Fallback metadata extraction requires it: pip install Pillow")
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


def get_exiftool_gps(filepath):
    """Use exiftool to extract precise GPS data (preferred method)."""
    try:
        res = subprocess.run(
            ['exiftool', '-json', '-GPSLatitude', '-GPSLongitude', filepath],
            capture_output=True, text=True, check=True
        )
        data = json.loads(res.stdout)[0]
        
        lat = data.get('GPSLatitude')
        lon = data.get('GPSLongitude')
        
        if lat is None or lon is None:
            return None
            
        # Exiftool usually outputs decimal format directly if requested, 
        # but standard is "deg min sec". Let's parse string coordinates
        # like "51 deg 30' 9.40\" N" to floats if needed.
        
        def parse_dms(s):
            if isinstance(s, (int, float)): return s
            parts = s.split(' ')
            if len(parts) >= 4:
                try:
                    d = float(parts[0])
                    m = float(parts[2].replace("'", ""))
                    sec = float(parts[3].replace('"', ''))
                    dec = d + (m / 60.0) + (sec / 3600.0)
                    if len(parts) > 4 and parts[4] in ['S', 'W']:
                        dec = -dec
                    return dec
                except:
                    pass
            # Try parsing a float embedded in string
            from re import sub
            try: return float(sub(r'[^\d.-]', '', s))
            except: return None
            
        lat_dec = parse_dms(lat)
        lon_dec = parse_dms(lon)
        
        # S and W coordinates are negative
        # Exiftool gives Ref separately sometimes, but -c "%f" avoids this.
        # Rerunning with decimal flag:
        res = subprocess.run(
            ['exiftool', '-c', '%f', '-json', '-GPSLatitude', '-GPSLongitude', filepath],
            capture_output=True, text=True, check=True
        )
        data = json.loads(res.stdout)[0]
        
        try:
            lat_str = data.get('GPSLatitude', '')
            lon_str = data.get('GPSLongitude', '')
            
            lat_f = float(lat_str.split()[0])
            if 'S' in lat_str: lat_f = -lat_f
            
            lon_f = float(lon_str.split()[0])
            if 'W' in lon_str: lon_f = -lon_f
            
            return (lat_f, lon_f)
        except:
            return None
            
    except Exception:
        return None

def get_pil_gps(filepath):
    """Basic PIL fallback for GPS extraction."""
    def get_exif_data(image):
        exif_data = {}
        info = image._getexif()
        if info:
            for tag, value in info.items():
                decoded = TAGS.get(tag, tag)
                if decoded == "GPSInfo":
                    gps_data = {}
                    for t in value:
                        sub_decoded = GPSTAGS.get(t, t)
                        gps_data[sub_decoded] = value[t]
                    exif_data[decoded] = gps_data
                else:
                    exif_data[decoded] = value
        return exif_data

    def get_if_exist(data, key):
        if key in data: return data[key]
        return None

    def convert_to_degrees(value):
        d0, d1, d2 = value[0], value[1], value[2]
        return d0 + (d1 / 60.0) + (d2 / 3600.0)

    try:
        with Image.open(filepath) as img:
            exif_data = get_exif_data(img)
            
            if "GPSInfo" not in exif_data:
                return None
                
            gps_info = exif_data["GPSInfo"]
            
            gps_latitude = get_if_exist(gps_info, "GPSLatitude")
            gps_latitude_ref = get_if_exist(gps_info, 'GPSLatitudeRef')
            gps_longitude = get_if_exist(gps_info, 'GPSLongitude')
            gps_longitude_ref = get_if_exist(gps_info, 'GPSLongitudeRef')
            
            if gps_latitude and gps_latitude_ref and gps_longitude and gps_longitude_ref:
                lat = convert_to_degrees(gps_latitude)
                if gps_latitude_ref != "N": lat = -lat
                
                lon = convert_to_degrees(gps_longitude)
                if gps_longitude_ref != "E": lon = -lon
                
                return (lat, lon)
    except:
        pass
    
    return None


def generate_html_map(points_data, out_file):
    """Generate a Leaflet.js interactive map given a list of dicts with coords/info."""
    
    # Calculate center point for initial view
    if not points_data:
        center_lat, center_lon = 0, 0
    else:
        lats = [p['lat'] for p in points_data]
        lons = [p['lon'] for p in points_data]
        center_lat = sum(lats) / len(lats)
        center_lon = sum(lons) / len(lons)
        
    # Build JS markers array
    markers_js = ""
    for idx, p in enumerate(points_data):
        popup_html = f"<b>{os.path.basename(p['file'])}</b><br>{p['lat']:.6f}, {p['lon']:.6f}"
        markers_js += f"    L.marker([{p['lat']}, {p['lon']}]).addTo(map).bindPopup('{popup_html}');\n"

    template = f"""<!DOCTYPE html>
<html>
<head>
    <title>CTF EXIF GPS Mapper</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <style>
        body {{ margin: 0; padding: 0; font-family: sans-serif; }}
        #overview {{ position: absolute; top: 10px; right: 10px; z-index: 1000; 
                    background: white; padding: 15px; border-radius: 8px;
                    box-shadow: 0 0 15px rgba(0,0,0,0.2); width: 250px; }}
        h3 {{ margin-top: 0; color: #333; }}
        #map {{ position: absolute; top: 0; bottom: 0; width: 100%; }}
        .file-list {{ max-height: 400px; overflow-y: auto; font-size: 13px; }}
        .file-item {{ padding: 5px 0; border-bottom: 1px solid #eee; }}
    </style>
</head>
<body>

    <div id="map"></div>
    <div id="overview">
        <h3>📍 EXIF Map</h3>
        <p>Found <b>{len(points_data)}</b> locations.</p>
        <div class="file-list">
            {''.join([f"<div class='file-item'>{os.path.basename(p['file'])}</div>" for p in points_data])}
        </div>
    </div>

    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <script>
        var map = L.map('map').setView([{center_lat}, {center_lon}], 3);

        L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
            maxZoom: 19,
            attribution: '© OpenStreetMap'
        }}).addTo(map);

    {markers_js}
    
    </script>
</body>
</html>
"""

    with open(out_file, 'w') as f:
        f.write(template)


def main():
    parser = argparse.ArgumentParser(
        description='CTF Geographic Metadata Visualizer (EXIF Mapper)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s ./images_dir
  %(prog)s target.jpg -o my_map.html
""")

    parser.add_argument('target', help='Directory containing images, or a single image file')
    parser.add_argument('-o', '--output', default='exif_map.html', help='Output HTML file (default: exif_map.html)')
    
    args = parser.parse_args()
    
    # Check if target is valid
    if not os.path.exists(args.target):
        print(f"{C.RED}Error: Target path '{args.target}' not found.{C.RESET}")
        sys.exit(1)
        
    print(f"\n{C.CYAN}{C.BOLD}{'─' * 60}\n  EXIF Geographic Mapper\n{'─' * 60}{C.RESET}")
    print(f"  {C.BOLD}Target:{C.RESET}    {args.target}")
    
    # Get files to process
    files_to_check = []
    if os.path.isdir(args.target):
        for root, _, files in os.walk(args.target):
            for file in files:
                # Basic filter for image types
                ext = os.path.splitext(file)[1].lower()
                if ext in ['.jpg', '.jpeg', '.tiff', '.tif', '.png']:
                    files_to_check.append(os.path.join(root, file))
        print(f"  {C.DIM}Found {len(files_to_check)} visual media files to scan...{C.RESET}\n")
    else:
        files_to_check = [args.target]
        print(f"  {C.DIM}Scanning single file...{C.RESET}\n")

    points = []
    
    # Process files
    for filepath in files_to_check:
        fname = os.path.basename(filepath)
        print(f"  {C.DIM}Analyzing: {fname}...{C.RESET}", end='\r')
        
        # Try exiftool first
        coords = get_exiftool_gps(filepath)
        method = "exiftool"
        
        # Fallback to PIL
        if not coords:
            coords = get_pil_gps(filepath)
            method = "PIL"
            
        if coords:
            lat, lon = coords
            print(f"  {C.GREEN}▶ {fname:<25}{C.RESET} : {lat:.5f}, {lon:.5f} ({method})")
            points.append({
                'file': filepath,
                'lat': lat,
                'lon': lon
            })
            
    print(" "*50, end='\r') # clear loading line
    
    if not points:
        print(f"\n  {C.RED}No GPS coordinates found in any scanned files.{C.RESET}")
        print(f"  {C.DIM}Note: Many social networks strip EXIF data on upload.{C.RESET}\n")
        return
        
    print(f"\n{C.CYAN}{'─' * 60}{C.RESET}")
    print(f"  {C.GREEN}Successfully extracted {len(points)} GPS locations.{C.RESET}")
    
    # Generate Map
    try:
        generate_html_map(points, args.output)
        print(f"  {C.BOLD}Interactive Map Generated:{C.RESET} {args.output}")
        print(f"  {C.YELLOW}Open {args.output} in your web browser to view locations.{C.RESET}\n")
    except Exception as e:
        print(f"  {C.RED}Failed to generate HTML map: {e}{C.RESET}\n")


if __name__ == '__main__':
    main()
