#!/usr/bin/env python3
import os
import subprocess
import re
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init()

BANNER = (Fore.CYAN + r"""
███████╗███╗   ██╗██╗ ██████╗ ███╗   ███╗ █████╗
██╔════╝████╗  ██║██║██╔════╝ ████╗ ████║██╔══██╗
█████╗  ██╔██╗ ██║██║██║  ███╗██╔████╔██║███████║
██╔══╝  ██║╚██╗██║██║██║   ██║██║╚██╔╝██║██╔══██║
███████╗██║ ╚████║██║╚██████╔╝██║ ╚═╝ ██║██║  ██║
╚══════╝╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝
              Created by: EN1GMA
""" + Style.RESET_ALL)

FILE_TYPES = {
    # Image formats
    'jpg': {'header': b'\xff\xd8\xff', 'footer': b'\xff\xd9', 'validate': lambda x: x.startswith(b'\xff\xd8') and x.endswith(b'\xff\xd9')},
    'png': {'header': b'\x89PNG\r\n\x1a\n', 'footer': b'IEND\xaeB`\x82', 'validate': lambda x: x.startswith(b'\x89PNG') and b'IEND' in x},
    'gif': {'header': b'GIF', 'footer': b'\x00\x3b', 'validate': lambda x: x.startswith((b'GIF87a', b'GIF89a')) and x.endswith(b'\x00\x3b')},
    'bmp': {'header': b'BM', 'footer': None, 'validate': lambda x: x.startswith(b'BM') and len(x) > 30},
    'webp': {'header': b'RIFF', 'footer': None, 'validate': lambda x: x.startswith(b'RIFF') and b'WEBP' in x[:20]},
    
    # Document formats
    'pdf': {'header': b'%PDF', 'footer': b'%%EOF', 'validate': lambda x: x.startswith(b'%PDF') and b'%%EOF' in x[-20:]},
    'docx': {'header': b'PK\x03\x04', 'footer': None, 'validate': lambda x: x.startswith(b'PK\x03\x04') and b'word/' in x[:1000]},
    'xlsx': {'header': b'PK\x03\x04', 'footer': None, 'validate': lambda x: x.startswith(b'PK\x03\x04') and b'xl/' in x[:1000]},
    
    # Archive formats
    'zip': {'header': b'PK\x03\x04', 'footer': None, 'validate': lambda x: x.startswith(b'PK\x03\x04')},
    'gz': {'header': b'\x1f\x8b', 'footer': None, 'validate': lambda x: x.startswith(b'\x1f\x8b')},
    
    # Audio/Video
    'mp3': {'header': b'\xff\xfb', 'footer': None, 'validate': lambda x: x.startswith(b'\xff\xfb')},
    'mp4': {'header': b'\x00\x00\x00\x18ftyp', 'footer': None, 'validate': lambda x: x.startswith(b'\x00\x00\x00') and b'moov' in x[:1000]}
}

def extract_files(pcap_path, output_dir="extracted_files", selected_types=None):
    print(BANNER)
    os.makedirs(output_dir, exist_ok=True)
    
    if selected_types is None:
        selected_types = FILE_TYPES.keys()
    
    # Step 1: Extract raw TCP payloads
    print("[*] Extracting payloads...")
    try:
        cmd = f"tshark -r {pcap_path} -Y 'tcp.payload' -T fields -e tcp.payload"
        payloads = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().split('\n')
        raw_data = b"".join(bytes.fromhex(p) for p in payloads if p.strip())
    except Exception as e:
        print(f"[-] Error: {e}")
        return

    # Step 2: Search for selected file types
    print("[*] Scanning for files...")
    found = 0
    
    for ext in selected_types:
        spec = FILE_TYPES.get(ext)
        if not spec:
            continue
            
        header = spec['header']
        footer = spec['footer']
        
        # Find all occurrences of this file type
        for match in re.finditer(re.escape(header), raw_data):
            start = match.start()
            
            # Determine end position
            if footer:
                end = raw_data.find(footer, start)
                if end == -1: continue
                end += len(footer)
            else:
                # For files without footer, use next header or end of data
                next_header = raw_data.find(header, start + 1)
                end = next_header if next_header != -1 else len(raw_data)
            
            file_data = raw_data[start:end]
            
            # Validate the file
            if not spec['validate'](file_data):
                continue
                
            # Save the file
            timestamp = datetime.now().strftime("%H%M%S")
            filename = f"{output_dir}/{ext}_{timestamp}_{found}.{ext}"
            with open(filename, 'wb') as f:
                f.write(file_data)
            print(f"[+] Found {ext.upper()}: {filename}")
            found += 1
    
    print(f"\n[+] Done! Extracted {found} files to '{output_dir}/'")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Extract files from PCAP")
    parser.add_argument("pcap_file", help="Path to PCAP file")
    parser.add_argument("-o", "--output", help="Output directory", default="extracted_files")
    
    # Add flags for all file types
    parser.add_argument("--all", help="Extract all file types", action="store_true")
    for file_type in FILE_TYPES.keys():
        parser.add_argument(f"--{file_type}", help=f"Extract {file_type.upper()} files", action="store_true")
    
    args = parser.parse_args()
    
    # Determine which file types to extract
    if args.all:
        selected_types = FILE_TYPES.keys()
    else:
        selected_types = [ft for ft in FILE_TYPES.keys() if getattr(args, ft)]
    
    if not selected_types:
        print("[!] No file types selected. Use --all or specify individual file types.")
        exit(1)
    
    extract_files(args.pcap_file, args.output, selected_types)
