# EN1GMA-PCAP-Forensic-Extractor
A PCAP file extractor tool to recover embedded images and data files from network capture files (.pcap/.pcapng). The tool provides both a command-line interface (CLI) and a GUI built with PyQt5, and is designed to run on Windows (also works on Linux/macOS).

<br>


# Features
- <a> **Multi-format support:** <br>
  Extracts common file types i.e. `JPEG`, `PNG`, `BMP`, `PDF`, `Office documents`, `ZIP/GZIP`, `MP3`, `MP4`, etc.) from PCAPs. </a>
- <a> **CLI mode:** <br>
  Script-based usage with options to select file types (e.g., `--jpg`, `--png`, or `--all`). </a> 

- <a> **GUI mode:** <br>
  User-friendly `Qt` interface with progress bar and status messages.
PCAP/PCAPNG: Supports both pcap and pcapng formats.</a>

- <a> **Self-contained executable:** <br>
  Can build a single Windows `.EXE` using `PyInstaller` (no Python install needed on target).</a>

-  <a> **Lightweight:** <br>
  No heavy dependencies beyond `PyQt5`; uses native `tshark` for packet parsing. </a>

<br>


# Requirements
- <a> **Python:** Version 3.6 or higher.</a>
- <a> **PyQt5:** GUI framework (install via pip install PyQt5). </a>
- <a> **Wireshark/TShark:** <br>
  The tshark CLI tool (usually included with Wireshark) must be installed and in your system PATH. </a>
- <a> **PyInstaller:** (Optional) <br>
  Only needed if you want to build a standalone executable. </a>
  
# Installation
1. <a> **Clone** the repository or download the source code. </a>
2. <a> Install **dependencies**: `pip install PyQt5` </a>
3. <a> Install **Wireshark**: Download and install Wireshark for your OS. Ensure that the tshark executable is accessible (add it to your PATH on Windows).</a>
4. <a>**PyInstaller:** (Optional)  If you plan to create an executable, install PyInstaller: `pip install pyinstaller` </a>


# Usage
### CLI (Command-Line)
- <a> Run the CLI script directly with Python. For example, to extract all supported file types from a PCAP: </a>

  ```bash
    python PCAP_Extractor.py path/to/capture.pcap --all -o output_dir

<br>

- <a> This scans capture.pcap, extracts every supported file type, and saves results under output_dir/ (created if needed). The script prints progress messages and a summary. You can also specify individual types instead of --all. For example, to extract only images: </a>

    ```bash
      python PCAP_Extractor.py capture.pcap --jpg --png --gif -o images_out

<br>

- <a> If no types are selected (and --all is not used), the tool will prompt you to choose something. <a>


### GUI (PyQt5)
- <a> Launch the GUI version to use a graphical interface: </a>
  ```bash
     python PCAP_Extractor_GUI.py

- <a> In the GUI window, click `Browse` to select the input PCAP file and the output directory. Check the boxes for the `file types` you want to extract (or click Select All). Then click `Start Extraction`. The progress bar will update and a status message will appear when done.

- The GUI window is themed in dark mode. It uses the provided `icon.png` as the application icon. (On Windows, the title bar and taskbar icon will show this icon.)

  
### Building a Windows Executable
- <a> To create a standalone Windows executable with `PyInstaller`, run the following commands in your project directory: </a>
  ```bash
    pip install pyinstaller
    pyinstaller --onefile --windowed --icon=icon.png PCAP_Extractor_GUI.py

- <a> The `--onefile` option bundles everything into a single `EXE`.
- The `--windowed` flag (or `--noconsole`) prevents a console window from appearing (useful for GUI apps).
- `--icon=icon.png` tells PyInstaller to use the provided `icon.png` as the application’s icon.
  
- After running PyInstaller, you’ll find `PCAP_Extractor_GUI.exe` in the `dist/` folder. You can similarly build a CLI executable (without --windowed) by running: </a>
  ```bash
    pyinstaller --onefile PCAP_Extractor.py
<i> Note: On Windows, run these commands in the Command Prompt or PowerShell. Make sure `icon.png` is in the current directory so PyInstaller can include it.</i>


# Considerations
- <a> **Encrypted/Unsupported Traffic:** Encrypted streams (HTTPS, TLS) or proprietary protocols will not yield extractable data. Only clear-text TCP payloads are scanned.</a> 
- <a> **TShark dependency:** This tool relies on the external `tshark` utility. The PCAP is fed to `tshark` (via subprocess) to extract raw TCP payloads. If tshark is not installed or not in PATH, extraction will fail.</a> 
- <a> **File Types:** Only the file signatures listed in the code are detected. Files using the same headers but different formats may be falsely identified.</a> 
- <a> **Performance:** Very large PCAP files may consume significant memory and time, as all TCP payloads are concatenated in memory before scanning. Use adequate system resources.</a> 
- <a> **Filename Collisions:** Extracted files are named with a timestamp to reduce collisions, but if run rapidly, files may overwrite. You can change the naming scheme in the code if needed.</a> 
- <a> **Windows Paths:** On Windows, avoid extremely long file paths. Use short directory names or run from a root directory if path-length errors occur.</a> 

# Credits
- <a> **Developer:** Developed by Uzzam Arif.</a>
- <a> **Libraries:** Built with `PyQt5` and Python’s standard library.</a>
- <a> **Tools:** Extraction logic leverages Wireshark Tshark for packet parsing.</a>
- <a> **Icon:** The GUI icon is provided (`icon.png`) – sourced from the public domain.</a>
- <a> **Inspiration:** This tool was inspired by various network forensics scripts and exercises in packet analysis. </a>

# License
<i> This project is released under the `MIT` License. See the LICENSE file for details. </i>
