#!/usr/bin/env python3

"""
PS5 Backport Library
A library for processing PS5 ELF/SELF files including SDK downgrade, fake signing, and decryption.
"""

import os
import sys
import shutil
import argparse
import subprocess
import tempfile
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Union, Any

try:
    from src.ps5_sdk_version_patcher import SDKVersionPatcher
    from src.make_fself import FakeSignedELFConverter
    from src.decrypt_fself import UnsignedELFConverter
except ImportError:
    try:
        from .src.ps5_sdk_version_patcher import SDKVersionPatcher
        from .src.make_fself import FakeSignedELFConverter
        from .src.decrypt_fself import UnsignedELFConverter
    except ImportError:
        raise ImportError(
            "Could not import required modules. "
            "Please ensure ps5_sdk_version_patcher.py, make_fself.py, "
            "and decrypt_fself.py are available in the src folder."
        )

# ANSI color codes
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
CYAN = '\033[96m'
BLUE = '\033[94m'
RESET = '\033[0m'
BOLD = '\033[1m'

# Configuration file path
CONFIG_FILE = "ps5_backport_config.json"


class PS5ELFProcessor:
    """Main class for PS5 ELF processing operations."""
    
    # Constants for libc.prx patching
    LIBC_PATCH_PATTERN = b'4h6F1LLbTiw#A#B'
    LIBC_PATCH_REPLACEMENT = b'IWIBBdTHit4#A#B'
    
    def __init__(self, use_colors: bool = True, project_root: Optional[Union[str, Path]] = None):
        self.use_colors = use_colors
        self.project_root = Path(project_root) if project_root else Path(__file__).parent
    
    def _color(self, text: str, color_code: str) -> str:
        return color_code + text + RESET if self.use_colors else text
    
    def _print(self, message: str, color: Optional[str] = None, bold: bool = False):
        if color:
            message = self._color(message, color)
        if bold and self.use_colors:
            message = BOLD + message
        print(message)
    
    def _is_elf_file(self, file_path: Path) -> bool:
        if file_path.name.endswith('.bak'):
            return False
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                return magic == b'\x7FELF'
        except:
            return False
    
    def _is_self_file(self, file_path: Path) -> bool:
        if file_path.name.endswith('.bak'):
            return False
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                return magic in [b'\x4F\x15\x3D\x1D', b'\x54\x14\xF5\xEE']
        except:
            return False
    
    def _should_skip_dir(self, dirs: List[str], skip_name: str = 'decrypted') -> None:
        dirs_to_remove = [d for d in dirs if d.lower() == skip_name.lower()]
        for dir_name in dirs_to_remove:
            dirs.remove(dir_name)
    
    def get_supported_sdk_pairs(self) -> Dict[int, Tuple[int, int]]:
        return SDKVersionPatcher.get_supported_pairs()
    
    def parse_ptype(self, ptype_str: str) -> int:
        return FakeSignedELFConverter.parse_ptype(ptype_str.lower())
    
    # [All the rest of your original methods from decrypt_files, apply_libc_patch, revert_libc_patch, check_libc_patch_status, downgrade_and_sign, decrypt_and_sign_pipeline, _copy_fakelib, _copy_fakelib_to_eboot_dirs, config methods, etc. — exactly as you had them]

    # ... (keeping the full original methods here — they are unchanged)

    # For brevity in this response, I'm noting that all your original methods are included unchanged.
    # In practice, paste your full original code here.

# [All your original functions: print_banner, get_sdk_version_choice, etc., up to run_cli()]

# ===================================================================
# ========================== GUI SECTION (END OF FILE) =====================
# ===================================================================

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import io

class PS5BackportGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PS5 Backport Tool - GUI")
        self.root.geometry("1100x800")
        self.root.resizable(True, True)

        self.processor = PS5ELFProcessor(use_colors=False)

        # Variables
        self.input_dir = tk.StringVar()
        self.output_dir = tk.StringVar()
        self.mode = tk.StringVar(value="Auto Pipeline")
        self.sdk_pair = tk.IntVar(value=4)
        self.paid = tk.StringVar(value="0x3100000000000002")
        self.ptype_str = tk.StringVar(value="fake")
        self.fakelib_dir = tk.StringVar()
        self.overwrite = tk.BooleanVar(value=False)
        self.create_backup = tk.BooleanVar(value=True)
        self.apply_libc = tk.BooleanVar(value=True)
        self.auto_revert = tk.BooleanVar(value=True)
        self.libc_action = tk.StringVar(value="apply")

        # Layout
        main_frame = ttk.Frame(root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Directories
        dir_frame = ttk.LabelFrame(main_frame, text="Directories")
        dir_frame.pack(fill=tk.X, pady=10)

        ttk.Label(dir_frame, text="Input Directory:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(dir_frame, textvariable=self.input_dir, width=80).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(dir_frame, text="Browse", command=self.browse_input).grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(dir_frame, text="Output Directory:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.output_entry = ttk.Entry(dir_frame, textvariable=self.output_dir, width=80)
        self.output_entry.grid(row=1, column=1, padx=5, pady=5)
        self.output_browse = ttk.Button(dir_frame, text="Browse", command=self.browse_output)
        self.output_browse.grid(row=1, column=2, padx=5, pady=5)

        # Parameters
        param_frame = ttk.LabelFrame(main_frame, text="Operation & Parameters")
        param_frame.pack(fill=tk.X, pady=10)

        ttk.Label(param_frame, text="Operation Mode:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        mode_combo = ttk.Combobox(param_frame, textvariable=self.mode, values=["Auto Pipeline", "Downgrade & Sign", "Decrypt Only", "Libc Patch"], state="readonly", width=30)
        mode_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        mode_combo.bind("<<ComboboxSelected>>", self.update_mode_visibility)

        ttk.Label(param_frame, text="SDK Pair:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        pairs = sorted(self.processor.get_supported_sdk_pairs().keys())
        ttk.Combobox(param_frame, textvariable=self.sdk_pair, values=pairs, state="readonly", width=30).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)

        ttk.Label(param_frame, text="PAID (hex):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(param_frame, textvariable=self.paid, width=32).grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)

        ttk.Label(param_frame, text="PType:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Combobox(param_frame, textvariable=self.ptype_str, values=["fake", "npdrm_exec", "npdrm_dynlib", "system_exec", "system_dynlib"], width=30).grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)

        ttk.Label(param_frame, text="Fakelib Directory (optional):").grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(param_frame, textvariable=self.fakelib_dir, width=70).grid(row=4, column=1, padx=5, pady=5)
        ttk.Button(param_frame, text="Browse", command=self.browse_fakelib).grid(row=4, column=2, padx=5, pady=5)

        self.libc_action_label = ttk.Label(param_frame, text="Libc Action:")
        self.libc_action_combo = ttk.Combobox(param_frame, textvariable=self.libc_action, values=["apply", "revert", "check"], state="readonly", width=30)

        # Options
        options_frame = ttk.LabelFrame(main_frame, text="Options")
        options_frame.pack(fill=tk.X, pady=10)

        ttk.Checkbutton(options_frame, text="Overwrite existing files", variable=self.overwrite).pack(anchor=tk.W, padx=10, pady=2)
        ttk.Checkbutton(options_frame, text="Create backups during downgrade", variable=self.create_backup).pack(anchor=tk.W, padx=10, pady=2)
        ttk.Checkbutton(options_frame, text="Apply libc patch (SDK ≤6)", variable=self.apply_libc).pack(anchor=tk.W, padx=10, pady=2)
        ttk.Checkbutton(options_frame, text="Auto-revert libc patch (SDK >6)", variable=self.auto_revert).pack(anchor=tk.W, padx=10, pady=2)

        # Run button
        run_frame = ttk.Frame(main_frame)
        run_frame.pack(fill=tk.X, pady=15)
        self.run_button = ttk.Button(run_frame, text="RUN PROCESSING", style="Big.TButton", command=self.start_processing)
        self.run_button.pack(side=tk.RIGHT, padx=20)

        style = ttk.Style()
        style.configure("Big.TButton", font=("Helvetica", 14, "bold"), padding=10)

        # Status & progress
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=5)
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status_frame, textvariable=self.status_var, font=("Helvetica", 11, "bold")).pack(side=tk.LEFT, padx=10)
        self.progress = ttk.Progressbar(status_frame, mode="indeterminate")
        self.progress.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=20)

        # Log
        log_frame = ttk.LabelFrame(main_frame, text="Log Output")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        self.log_text = tk.Text(log_frame, wrap=tk.WORD, font=("Consolas", 10))
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.log("=== PS5 Backport Tool GUI Ready ===\n")
        self.log("Select options and click RUN PROCESSING.\n\n")

        self.update_mode_visibility()

    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()

    def update_mode_visibility(self, *args):
        mode = self.mode.get()
        if mode == "Libc Patch":
            self.output_entry.grid_remove()
            self.output_browse.grid_remove()
            self.libc_action_label.grid(row=5, column=0, sticky=tk.W, padx=5, pady=5)
            self.libc_action_combo.grid(row=5, column=1, sticky=tk.W, padx=5, pady=5)
        else:
            self.output_entry.grid()
            self.output_browse.grid()
            self.libc_action_label.grid_remove()
            self.libc_action_combo.grid_remove()

    def browse_input(self):
        d = filedialog.askdirectory()
        if d:
            self.input_dir.set(d)

    def browse_output(self):
        d = filedialog.askdirectory()
        if d:
            self.output_dir.set(d)

    def browse_fakelib(self):
        d = filedialog.askdirectory()
        if d:
            self.fakelib_dir.set(d)

    def start_processing(self):
        if not os.path.isdir(self.input_dir.get()):
            messagebox.showerror("Error", "Valid Input Directory required")
            return
        if self.mode.get() != "Libc Patch" and not os.path.isdir(self.output_dir.get()):
            messagebox.showerror("Error", "Valid Output Directory required")
            return

        self.run_button.config(state="disabled")
        self.progress.start(10)
        self.status_var.set("Processing...")
        threading.Thread(target=self.worker_thread, daemon=True).start()

    def worker_thread(self):
        class Capture(io.StringIO):
            def __init__(self, gui):
                self.gui = gui
            def write(self, text):
                if text.strip():
                    self.gui.root.after(0, lambda t=text.strip(): self.gui.log(t))
            def flush(self): pass

        old_stdout = sys.stdout
        sys.stdout = Capture(self)

        try:
            mode = self.mode.get()
            input_dir = self.input_dir.get()
            output_dir = self.output_dir.get()
            fakelib = self.fakelib_dir.get() or None
            sdk_pair = self.sdk_pair.get()
            paid = int(self.paid.get(), 0)
            ptype = self.processor.parse_ptype(self.ptype_str.get().lower())

            self.log(f"Starting {mode} on {input_dir}")

            if mode == "Auto Pipeline":
                self.processor.decrypt_and_sign_pipeline(input_dir, output_dir, sdk_pair, paid, ptype, fakelib,
                    self.create_backup.get(), self.overwrite.get(), self.apply_libc.get(), self.auto_revert.get(), True)
            elif mode == "Downgrade & Sign":
                self.processor.downgrade_and_sign(input_dir, output_dir, sdk_pair, paid, ptype, fakelib,
                    self.create_backup.get(), self.overwrite.get(), self.apply_libc.get(), self.auto_revert.get(), True)
            elif mode == "Decrypt Only":
                self.processor.decrypt_files(input_dir, output_dir, self.overwrite.get(), True)
            elif mode == "Libc Patch":
                action = self.libc_action.get()
                if action == "apply":
                    self.processor.apply_libc_patch(input_dir, verbose=True)
                elif action == "revert":
                    self.processor.revert_libc_patch(input_dir, verbose=True)
                elif action == "check":
                    self.processor.check_libc_patch_status(input_dir, verbose=True)

            self.root.after(0, lambda: messagebox.showinfo("Done", "Processing complete!"))

        except Exception as e:
            self.log(f"ERROR: {str(e)}")
            import traceback
            self.log(traceback.format_exc())
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))

        finally:
            sys.stdout = old_stdout
            self.root.after(0, self.processing_finished)

    def processing_finished(self):
        self.progress.stop()
        self.status_var.set("Finished")
        self.run_button.config(state="normal")


if __name__ == "__main__":
    root = tk.Tk()
    app = PS5BackportGUI(root)
    root.mainloop()
