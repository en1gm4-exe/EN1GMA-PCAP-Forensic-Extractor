#!/usr/bin/env python3
import os
import sys
import subprocess
import re
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QLabel, QLineEdit, QPushButton, QProgressBar,
                            QFileDialog, QMessageBox, QGroupBox, QGridLayout, QSizePolicy)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QIcon, QPalette, QColor

# File type definitions
FILE_TYPES = {
    'jpg': {'header': b'\xff\xd8\xff', 'footer': b'\xff\xd9'},
    'png': {'header': b'\x89PNG\r\n\x1a\n', 'footer': b'IEND\xaeB`\x82'},
    'gif': {'header': b'GIF', 'footer': b'\x00\x3b'},
    'bmp': {'header': b'BM', 'footer': None},
    'webp': {'header': b'RIFF', 'footer': None},
    'pdf': {'header': b'%PDF', 'footer': b'%%EOF'},
    'docx': {'header': b'PK\x03\x04', 'footer': None},
    'xlsx': {'header': b'PK\x03\x04', 'footer': None},
    'zip': {'header': b'PK\x03\x04', 'footer': None},
    'gz': {'header': b'\x1f\x8b', 'footer': None},
    'mp3': {'header': b'\xff\xfb', 'footer': None},
    'mp4': {'header': b'\x00\x00\x00\x18ftyp', 'footer': None}
}

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

class ExtractionThread(QThread):
    update_progress = pyqtSignal(int, str)
    finished = pyqtSignal(bool, str)

    def __init__(self, pcap_path, output_dir, selected_types):
        super().__init__()
        self.pcap_path = pcap_path
        self.output_dir = output_dir
        self.selected_types = selected_types

    def run(self):
        try:
            self.update_progress.emit(10, "Extracting network payloads...")
            
            cmd = f"tshark -r {self.pcap_path} -Y 'tcp.payload' -T fields -e tcp.payload"
            payloads = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().split('\n')
            raw_data = b"".join(bytes.fromhex(p) for p in payloads if p.strip())
            
            self.update_progress.emit(30, "Analyzing payload content...")
            
            found = 0
            total_files = sum(1 for _ in re.finditer(b'|'.join(
                re.escape(FILE_TYPES[ft]['header']) for ft in self.selected_types
            ), raw_data))
            
            if total_files == 0:
                self.finished.emit(False, "No matching files found in payload")
                return
            
            progress_step = 60 / total_files
            current_progress = 30
            
            for ext in self.selected_types:
                spec = FILE_TYPES.get(ext)
                if not spec:
                    continue
                
                header = spec['header']
                footer = spec['footer']
                
                for match in re.finditer(re.escape(header), raw_data):
                    start = match.start()
                    
                    if footer:
                        end = raw_data.find(footer, start)
                        if end == -1: continue
                        end += len(footer)
                    else:
                        next_header = raw_data.find(header, start + 1)
                        end = next_header if next_header != -1 else len(raw_data)
                    
                    file_data = raw_data[start:end]
                    
                    if not file_data.startswith(header):
                        continue
                    
                    os.makedirs(self.output_dir, exist_ok=True)
                    filename = f"{self.output_dir}/{ext}_{datetime.now().strftime('%H%M%S')}_{found}.{ext}"
                    
                    with open(filename, 'wb') as f:
                        f.write(file_data)
                    
                    found += 1
                    current_progress += progress_step
                    self.update_progress.emit(
                        min(95, int(current_progress)),
                        f"Extracted {found} files (latest: {ext.upper()})"
                    )
            
            self.finished.emit(
                True,
                f"✔ Success! Extracted {found} files to:\n{os.path.abspath(self.output_dir)}"
            )
            
        except Exception as e:
            self.finished.emit(False, f"✖ Extraction failed: {str(e)}")

class ForensicExtractor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.current_dir = os.getcwd()
        self.setup_ui()
        self.setup_theme()
        self.selected_buttons = {}
        
    def setup_theme(self):
        palette = self.palette()
        palette.setColor(QPalette.Window, QColor(30, 30, 30))
        palette.setColor(QPalette.WindowText, Qt.white)
        palette.setColor(QPalette.Base, QColor(40, 40, 40))
        palette.setColor(QPalette.AlternateBase, QColor(50, 50, 50))
        palette.setColor(QPalette.ToolTipBase, Qt.white)
        palette.setColor(QPalette.ToolTipText, Qt.white)
        palette.setColor(QPalette.Text, Qt.white)
        palette.setColor(QPalette.Button, QColor(60, 60, 60))
        palette.setColor(QPalette.ButtonText, Qt.white)
        palette.setColor(QPalette.Highlight, QColor(200, 0, 0))
        palette.setColor(QPalette.HighlightedText, Qt.white)
        self.setPalette(palette)
        
    def setup_ui(self):
        self.setWindowTitle("EN1GMA Forensic Extractor")
        self.setMinimumSize(1200, 600)  
        
        # Set window icon
        icon_paths = [
            resource_path('icon.png'),
            os.path.join(os.path.dirname(__file__), 'icon.png')
        ]
        
        for icon_path in icon_paths:
            if os.path.exists(icon_path):
                try:
                    self.setWindowIcon(QIcon(icon_path))
                    break
                except:
                    continue
        
        # Main widget with size policy
        main_widget = QWidget()
        main_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setCentralWidget(main_widget)
        
        # Main layout
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(10)
        main_widget.setLayout(main_layout)
        
        # Header - Centered
        header_layout = QVBoxLayout()
        header_layout.setAlignment(Qt.AlignCenter)
        
        title_label = QLabel("EN1GMA")
        title_label.setFont(QFont("Helvetica", 24, QFont.Bold))
        title_label.setStyleSheet("color: #d40000; margin-bottom: 0;")
        title_label.setAlignment(Qt.AlignCenter)
        
        subtitle_label = QLabel("PCAP EXTRACTION SUITE")
        subtitle_label.setFont(QFont("Helvetica", 14))
        subtitle_label.setStyleSheet("color: white; margin-top: 0;")
        subtitle_label.setAlignment(Qt.AlignCenter)
        
        title_container = QWidget()
        title_container_layout = QHBoxLayout()
        title_container_layout.setContentsMargins(25, 0, 0, 0)
        title_container_layout.addWidget(title_label)
        title_container.setLayout(title_container_layout)
        
        header_layout.addWidget(title_container)
        header_layout.addWidget(subtitle_label)
        main_layout.addLayout(header_layout)
        
        # File selection
        file_group = QGroupBox("PCAP File Selection")
        file_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        file_layout = QHBoxLayout()
        
        self.file_entry = QLineEdit()
        self.file_entry.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.file_entry.setPlaceholderText("Select PCAP file...")
        file_layout.addWidget(self.file_entry)
        
        browse_btn = QPushButton("Browse")
        browse_btn.setFixedWidth(100)
        browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #d40000;
                color: white;
                border: none;
                padding: 5px 10px;
            }
            QPushButton:hover {
                background-color: #ff0000;
            }
        """)
        browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(browse_btn)
        
        file_group.setLayout(file_layout)
        main_layout.addWidget(file_group)
        
        # Content area - now resizable
        content_layout = QHBoxLayout()
        content_layout.setSpacing(15)
        
        # Left panel - File types
        type_group = QGroupBox("File Types to Extract")
        type_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        type_layout = QVBoxLayout()
        
        categories = {
            "Images": ['jpg', 'png', 'gif', 'bmp', 'webp'],
            "Documents": ['pdf', 'docx', 'xlsx'],
            "Archives": ['zip', 'gz'],
            "Media": ['mp3', 'mp4']
        }
        
        self.type_buttons = {}
        for category, types in categories.items():
            cat_label = QLabel(category)
            cat_label.setFont(QFont("Helvetica", 10, QFont.Bold))
            cat_label.setStyleSheet("color: white;")
            type_layout.addWidget(cat_label)
            
            btn_grid = QGridLayout()
            btn_grid.setHorizontalSpacing(5)
            btn_grid.setVerticalSpacing(5)
            
            for i, ftype in enumerate(types):
                btn = QPushButton(ftype.upper())
                btn.setCheckable(True)
                btn.setMinimumWidth(80)
                btn.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.Fixed)
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: #333333;
                        color: white;
                        border: 1px solid #555555;
                        padding: 5px 10px;
                    }
                    QPushButton:checked {
                        background-color: #d40000;
                        border: 1px solid #d40000;
                    }
                    QPushButton:hover {
                        border: 1px solid #777777;
                    }
                """)
                self.type_buttons[ftype] = btn
                btn_grid.addWidget(btn, i // 3, i % 3)
            
            type_layout.addLayout(btn_grid)
            type_layout.addSpacing(10)
        
        # Selection controls
        control_layout = QHBoxLayout()
        
        select_all_btn = QPushButton("Select All")
        select_all_btn.setStyleSheet("""
            QPushButton {
                background-color: #d40000;
                color: white;
                border: none;
                padding: 5px 10px;
            }
            QPushButton:hover {
                background-color: #ff0000;
            }
        """)
        select_all_btn.clicked.connect(self.select_all_types)
        control_layout.addWidget(select_all_btn)
        
        deselect_all_btn = QPushButton("Deselect All")
        deselect_all_btn.setStyleSheet("""
            QPushButton {
                background-color: #333333;
                color: white;
                border: none;
                padding: 5px 10px;
            }
            QPushButton:hover {
                background-color: #444444;
            }
        """)
        deselect_all_btn.clicked.connect(self.deselect_all_types)
        control_layout.addWidget(deselect_all_btn)
        
        type_layout.addLayout(control_layout)
        type_group.setLayout(type_layout)
        content_layout.addWidget(type_group, stretch=2)
        
        # Right panel - Output and progress
        right_panel = QVBoxLayout()
        right_panel.setSpacing(15)
        
        # Output group
        output_group = QGroupBox("Output Configuration")
        output_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        output_layout = QVBoxLayout()
        
        self.output_entry = QLineEdit(os.path.join(self.current_dir, "extracted_files"))
        output_layout.addWidget(self.output_entry)
        
        output_browse_btn = QPushButton("Browse Output Directory")
        output_browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #d40000;
                color: white;
                border: none;
                padding: 5px 10px;
            }
            QPushButton:hover {
                background-color: #ff0000;
            }
        """)
        output_browse_btn.clicked.connect(self.browse_output)
        output_layout.addWidget(output_browse_btn)
        
        output_group.setLayout(output_layout)
        right_panel.addWidget(output_group)
        
        # Progress group
        progress_group = QGroupBox("Extraction Progress")
        progress_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        progress_layout = QVBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready to begin extraction")
        self.status_label.setStyleSheet("color: white;")
        progress_layout.addWidget(self.status_label)
        
        progress_group.setLayout(progress_layout)
        right_panel.addWidget(progress_group)
        
        content_layout.addLayout(right_panel, stretch=1)
        main_layout.addLayout(content_layout, stretch=1)
        
        # Action buttons
        action_layout = QHBoxLayout()
        action_layout.addStretch()
        
        self.extract_btn = QPushButton("Extract Files")
        self.extract_btn.setFixedWidth(150)
        self.extract_btn.setStyleSheet("""
            QPushButton {
                background-color: #d40000;
                color: white;
                border: none;
                padding: 8px 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #ff0000;
            }
            QPushButton:disabled {
                background-color: #444444;
            }
        """)
        self.extract_btn.clicked.connect(self.start_extraction)
        action_layout.addWidget(self.extract_btn)
        
        exit_btn = QPushButton("Exit")
        exit_btn.setFixedWidth(100)
        exit_btn.setStyleSheet("""
            QPushButton {
                background-color: #333333;
                color: white;
                border: none;
                padding: 8px 15px;
            }
            QPushButton:hover {
                background-color: #444444;
            }
        """)
        exit_btn.clicked.connect(self.close)
        action_layout.addWidget(exit_btn)
        
        main_layout.addLayout(action_layout)
    
    def browse_file(self):
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.ExistingFile)
        file_dialog.setNameFilter("PCAP files (*.pcap *.pcapng);;All files (*.*)")
        file_dialog.setDirectory(self.current_dir)
        
        if file_dialog.exec_():
            selected = file_dialog.selectedFiles()
            if selected:
                self.file_entry.setText(selected[0])
                self.current_dir = os.path.dirname(selected[0])
    
    def browse_output(self):
        dir_dialog = QFileDialog()
        dir_dialog.setFileMode(QFileDialog.Directory)
        dir_dialog.setDirectory(self.current_dir)
        
        if dir_dialog.exec_():
            selected = dir_dialog.selectedFiles()
            if selected:
                self.output_entry.setText(selected[0])
                self.current_dir = selected[0]
    
    def select_all_types(self):
        for btn in self.type_buttons.values():
            btn.setChecked(True)
    
    def deselect_all_types(self):
        for btn in self.type_buttons.values():
            btn.setChecked(False)
    
    def start_extraction(self):
        pcap_file = self.file_entry.text()
        output_dir = self.output_entry.text()
        selected_types = [ftype for ftype, btn in self.type_buttons.items() if btn.isChecked()]
        
        if not pcap_file:
            QMessageBox.critical(self, "Error", "Please select a PCAP file")
            return
        
        if not selected_types:
            QMessageBox.critical(self, "Error", "Please select at least one file type")
            return
        
        self.extract_btn.setEnabled(False)
        self.status_label.setText("Initializing extraction...")
        self.progress_bar.setValue(0)
        
        self.thread = ExtractionThread(pcap_file, output_dir, selected_types)
        self.thread.update_progress.connect(self.update_progress)
        self.thread.finished.connect(self.extraction_finished)
        self.thread.start()
    
    def update_progress(self, value, message):
        self.progress_bar.setValue(value)
        self.status_label.setText(message)
    
    def extraction_finished(self, success, message):
        self.extract_btn.setEnabled(True)
        self.status_label.setText(message)
        if success:
            self.progress_bar.setValue(100)
        else:
            self.progress_bar.setValue(0)

if __name__ == "__main__":
    app = QApplication([])
    window = ForensicExtractor()
    window.show()
    app.exec_()
