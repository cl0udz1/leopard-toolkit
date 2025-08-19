# Main application entry point for the Leopard toolkit.

import sys
import os

# Add the project's root directory to the Python path to ensure robust imports
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(ROOT_DIR)

import customtkinter as ctk
import threading
import queue
from tkinter import messagebox, filedialog

# Import the core logic from the existing modules
from modules import scanner, analyzer
from utils import logger, config

class LeopardGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Main window setup
        self.title("Leopard Toolkit (Advanced Edition)")
        self.geometry("1000x800")
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")
        
        # Controls the running scan thread
        self.scan_thread = None
        self.stop_scan_event = threading.Event()

        # Load config and set up logging
        self.cfg = config.load_config()
        self.log = logger.setup_logger(self.cfg['GENERAL']['log_file'])

        # Configure the main layout grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.title_label = ctk.CTkLabel(self, text="Leopard", font=ctk.CTkFont(size=24, weight="bold"))
        self.title_label.grid(row=0, column=0, padx=20, pady=(10, 10))

        self.tab_view = ctk.CTkTabview(self, width=250)
        self.tab_view.grid(row=1, column=0, padx=20, pady=(0, 10), sticky="nsew")
        self.tab_view.add("Scanner")
        self.tab_view.add("Analyzer")

        self.output_textbox = ctk.CTkTextbox(self, wrap="word")
        self.output_textbox.grid(row=2, column=0, padx=20, pady=5, sticky="nsew")
        self.output_textbox.configure(state="disabled")

        # Frame for the bottom buttons
        bottom_frame = ctk.CTkFrame(self)
        bottom_frame.grid(row=3, column=0, padx=20, pady=10, sticky="ew")
        self.export_button = ctk.CTkButton(bottom_frame, text="Export Results", command=self.export_results)
        self.export_button.pack(side="left", padx=10)
        self.clear_button = ctk.CTkButton(bottom_frame, text="Clear Output", command=self.clear_output)
        self.clear_button.pack(side="left", padx=10)

        # Build the UI tabs
        self.create_scanner_tab()
        self.create_analyzer_tab()
        
        # Redirect print statements to the output textbox
        self.output_queue = queue.Queue()
        sys.stdout = self.TextRedirector(self.output_queue)
        self.after(100, self.process_queue)

    def process_queue(self):
        # Checks the output queue and writes any new messages to the textbox.
        try:
            while True:
                msg = self.output_queue.get_nowait()
                self.output_textbox.configure(state="normal")
                self.output_textbox.insert("end", msg)
                self.output_textbox.see("end")
                self.output_textbox.configure(state="disabled")
        except queue.Empty:
            pass
        self.after(100, self.process_queue)

    def run_in_thread(self, target_func, *args):
        # Starts a function in a new thread to keep the GUI responsive.
        self.output_textbox.configure(state="normal")
        self.output_textbox.delete("1.0", "end")
        self.output_textbox.configure(state="disabled")
        
        # This is for non-stoppable tasks
        thread = threading.Thread(target=target_func, args=(self.log, *args))
        thread.daemon = True
        thread.start()

    def create_scanner_tab(self):
        tab = self.tab_view.tab("Scanner")
        tab.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(tab, text="Target(s):").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.scanner_targets_entry = ctk.CTkEntry(tab, placeholder_text="e.g., 192.168.1.1 example.com")
        self.scanner_targets_entry.grid(row=0, column=1, padx=10, pady=5, sticky="ew")
        
        ctk.CTkLabel(tab, text="Port Range:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.scanner_ports_entry = ctk.CTkEntry(tab, placeholder_text="e.g., 1-1024")
        self.scanner_ports_entry.insert(0, "1-1024")
        self.scanner_ports_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")

        ctk.CTkLabel(tab, text="Scan Type:").grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.scan_type_var = ctk.StringVar(value="Fast Scan")
        scan_types = ["Fast Scan", "Stealth (SYN) Scan", "UDP Scan"]
        self.scan_type_menu = ctk.CTkOptionMenu(tab, variable=self.scan_type_var, values=scan_types)
        self.scan_type_menu.grid(row=2, column=1, padx=10, pady=5, sticky="w")

        button_frame = ctk.CTkFrame(tab)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        self.start_scan_button = ctk.CTkButton(button_frame, text="Start Scan", command=self.start_scan)
        self.start_scan_button.pack(side="left", padx=10)
        self.stop_scan_button = ctk.CTkButton(button_frame, text="Stop Scan", command=self.stop_scan, state="disabled")
        self.stop_scan_button.pack(side="left", padx=10)

    def create_analyzer_tab(self):
        tab = self.tab_view.tab("Analyzer")
        tab.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(tab, text="Web Crawler Target:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.crawler_target_entry = ctk.CTkEntry(tab, placeholder_text="e.g., http://example.com")
        self.crawler_target_entry.grid(row=0, column=1, padx=10, pady=5, sticky="ew")
        
        ctk.CTkLabel(tab, text="Crawl Depth:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.crawl_depth_entry = ctk.CTkEntry(tab)
        self.crawl_depth_entry.insert(0, "2")
        self.crawl_depth_entry.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        ctk.CTkButton(tab, text="Run Crawler", command=self.start_crawl).grid(row=2, column=0, columnspan=2, padx=10, pady=10)
        
        ctk.CTkLabel(tab, text="Windows Tools:").grid(row=3, column=0, padx=10, pady=(20, 5), sticky="w")
        ctk.CTkButton(tab, text="Scan Wi-Fi Networks", command=self.start_wifi_scan).grid(row=4, column=0, columnspan=2, padx=10, pady=10)

    def start_scan(self):
        targets = self.scanner_targets_entry.get().split()
        ports = self.scanner_ports_entry.get()
        scan_type_map = {
            "Fast Scan": "fast",
            "Stealth (SYN) Scan": "stealth",
            "UDP Scan": "udp"
        }
        scan_type = scan_type_map[self.scan_type_var.get()]

        if not targets or not targets[0]:
            messagebox.showerror("Input Error", "Please provide at least one target.")
            return

        self.stop_scan_event.clear()
        self.start_scan_button.configure(state="disabled")
        self.stop_scan_button.configure(state="normal")
        self.output_textbox.configure(state="normal")
        self.output_textbox.delete("1.0", "end")
        self.output_textbox.configure(state="disabled")

        def scan_task_wrapper():
            for target in targets:
                if self.stop_scan_event.is_set():
                    print("\n[!] Scan stopped by user.")
                    break
                print(f"\n--- Processing Target: {target} ---\n")
                scanner.run_scan(self.log, target, ports, scan_type, self.stop_scan_event)
            
            self.after(100, self.on_scan_complete)

        self.scan_thread = threading.Thread(target=scan_task_wrapper)
        self.scan_thread.daemon = True
        self.scan_thread.start()

    def stop_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self.stop_scan_event.set()
            self.stop_scan_button.configure(state="disabled", text="Stopping...")

    def on_scan_complete(self):
        # Called on the main thread when a scan finishes or is stopped.
        self.start_scan_button.configure(state="normal")
        self.stop_scan_button.configure(state="disabled", text="Stop Scan")
        if not self.stop_scan_event.is_set():
            print("\n[+] All scans complete.")

    def start_crawl(self):
        target = self.crawler_target_entry.get()
        try:
            depth = int(self.crawl_depth_entry.get())
        except ValueError:
            messagebox.showerror("Input Error", "Crawl depth must be a number.")
            return
        if not target:
            messagebox.showerror("Input Error", "Please provide a target URL for the crawler.")
            return
        self.run_in_thread(analyzer.crawl_website, target, depth)
        
    def start_wifi_scan(self):
        self.run_in_thread(analyzer.scan_wifi)

    def export_results(self):
        content = self.output_textbox.get("1.0", "end-1c")
        if not content:
            messagebox.showinfo("Export", "Nothing to export.")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Results As"
        )
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            messagebox.showinfo("Export Successful", f"Results saved to {file_path}")

    def clear_output(self):
        self.output_textbox.configure(state="normal")
        self.output_textbox.delete("1.0", "end")
        self.output_textbox.configure(state="disabled")

    class TextRedirector:
        def __init__(self, queue):
            self.queue = queue
        def write(self, text):
            self.queue.put(text)
        def flush(self):
            pass

if __name__ == "__main__":
    if sys.platform != "win32":
        print("This application is designed to run on Windows.")
        sys.exit(1)
    app = LeopardGUI()
    app.mainloop()
