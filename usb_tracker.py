import subprocess
import os
import re
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox

class USBTrackerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("USBTracker")
        self.root.geometry("1000x700")

        # Main frame
        self.main_frame = tk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Menu buttons
        self.menu_frame = tk.Frame(self.main_frame)
        self.menu_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

        self.connected_devices_button = tk.Button(self.menu_frame, text="Connected USB Devices", command=self.show_connected_devices, width=20)
        self.connected_devices_button.pack(pady=5)

        self.detailed_info_button = tk.Button(self.menu_frame, text="Detailed USB Info", command=self.show_detailed_info, width=20)
        self.detailed_info_button.pack(pady=5)

        self.usb_events_button = tk.Button(self.menu_frame, text="USB Connection Logs", command=self.show_usb_events, width=20)
        self.usb_events_button.pack(pady=5)

        self.refresh_button = tk.Button(self.menu_frame, text="Refresh", command=self.refresh, width=20)
        self.refresh_button.pack(pady=5)

        self.analyze_logs_button = tk.Button(self.menu_frame, text="Analyze Logs", command=self.analyze_logs, width=20)
        self.analyze_logs_button.pack(pady=5)

        self.save_logs_button = tk.Button(self.menu_frame, text="Save Logs", command=self.save_logs, width=20)
        self.save_logs_button.pack(pady=5)

        self.exit_button = tk.Button(self.menu_frame, text="Exit", command=self.root.quit, width=20)
        self.exit_button.pack(pady=5)

        # Display area for results
        self.result_text = scrolledtext.ScrolledText(self.main_frame, width=80, height=30, wrap=tk.WORD)
        self.result_text.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

    def show_connected_devices(self):
        """Show all connected USB storage devices."""
        self.result_text.delete(1.0, tk.END)
        try:
            # Run lsusb and filter for storage devices
            devices = subprocess.check_output("lsusb", shell=True, text=True).splitlines()
            for device in devices:
                # Exclude root hubs and virtual devices
                if "root hub" in device or "VirtualBox" in device:
                    continue

                # Check if the device is a storage device
                if "Mass Storage" in device or "Flash Drive" in device:
                    self.result_text.insert(tk.END, f"{device}\n")

        except Exception as e:
            self.result_text.insert(tk.END, f"Error retrieving USB devices: {e}\n")

    def show_detailed_info(self):
        """Show detailed information about connected USB storage devices."""
        self.result_text.delete(1.0, tk.END)
        try:
            # Get list of connected USB storage devices using lsblk
            usb_devices = subprocess.check_output("lsblk -o NAME,MOUNTPOINT,VENDOR,MODEL,TRAN,SIZE,SERIAL", shell=True, text=True).splitlines()

            # Filter for USB devices
            for device in usb_devices[1:]:  # Skip the header line
                if "usb" in device.lower():
                    # Split the device details into columns
                    details = device.split()
                    name = details[0]
                    mount_point = details[1] if len(details) > 1 else "Not mounted"
                    vendor = details[2] if len(details) > 2 else "Unknown"
                    model = details[3] if len(details) > 3 else "Unknown"
                    size = details[5] if len(details) > 5 else "Unknown"
                    serial = details[6] if len(details) > 6 else "Unknown"

                    # Print detailed information
                    self.result_text.insert(tk.END, f"🔹 **Device Name:** {name}\n")
                    self.result_text.insert(tk.END, f"📍 **Mount Point:** {mount_point}\n")
                    self.result_text.insert(tk.END, f"🏭 **Vendor:** {vendor}\n")
                    self.result_text.insert(tk.END, f"💻 **Model:** {model}\n")
                    self.result_text.insert(tk.END, f"💾 **Size:** {size}\n")
                    self.result_text.insert(tk.END, f"🔢 **Serial Number:** {serial}\n")
                    self.result_text.insert(tk.END, "=" * 50 + "\n")

        except Exception as e:
            self.result_text.insert(tk.END, f"Error retrieving detailed USB info: {e}\n")

    def show_usb_events(self):
        """Show recent USB connection/disconnection events."""
        self.result_text.delete(1.0, tk.END)
        try:
            # Extract USB-related logs from journalctl
            logs = subprocess.check_output("journalctl -k | grep -i 'usb 1-1: New USB device\\|usb 1-1: USB disconnect'", shell=True, text=True)
            logs = logs.strip().split("\n")

            if logs:
                for log in logs:
                    match = re.search(r'(\w+ \d+ \d+:\d+:\d+).*usb\s+\d+-\d+:\s+(.*)', log)
                    if match:
                        timestamp, event = match.groups()
                        if "New USB device found" in event:
                            log_entry = f"✅ **[Connected]** {timestamp} - {event}\n"
                        elif "USB disconnect" in event:
                            log_entry = f"❌ **[Disconnected]** {timestamp} - {event}\n"
                        else:
                            log_entry = f"🔹 {timestamp} - {event}\n"

                        # Print to console
                        self.result_text.insert(tk.END, log_entry)

            else:
                self.result_text.insert(tk.END, "⚠ No recent USB connection events detected.\n")

        except Exception as e:
            self.result_text.insert(tk.END, f"Error retrieving USB event logs: {e}\n")

    def refresh(self):
        """Refresh the list of connected USB devices and events."""
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, "🔄 Refreshing USB device and event list...\n")
        self.show_connected_devices()
        self.show_detailed_info()
        self.show_usb_events()

    def save_logs(self):
        """Save the displayed logs to a file."""
        logs = self.result_text.get(1.0, tk.END)
        if not logs.strip():
            messagebox.showwarning("No Logs", "No logs to save.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".log", filetypes=[("Log Files", "*.log"), ("All Files", "*.*")])
        if file_path:
            try:
                with open(file_path, "w") as file:
                    file.write(logs)
                messagebox.showinfo("Success", f"Logs saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save logs: {e}")

    def analyze_logs(self):
        """Open the log analyzer GUI."""
        log_analyzer_window = tk.Toplevel(self.root)
        log_analyzer_window.title("Log File Analyzer")
        log_analyzer_window.geometry("800x600")

        # File selection button
        file_label = tk.Label(log_analyzer_window, text="No file selected.", fg="blue")
        file_label.pack(pady=10)
        file_button = tk.Button(log_analyzer_window, text="Select Log File", command=lambda: self.select_file(log_analyzer_window, file_label))
        file_button.pack(pady=5)

        # Analyze Button
        analyze_button = tk.Button(log_analyzer_window, text="Analyze Logs", command=lambda: self.analyze_logs_gui(log_analyzer_window), state=tk.DISABLED)
        analyze_button.pack(pady=5)

        # Keyword filter entry and button
        keyword_label = tk.Label(log_analyzer_window, text="Filter by Keyword:")
        keyword_label.pack(pady=5)
        keyword_entry = tk.Entry(log_analyzer_window)
        keyword_entry.pack(pady=5)
        filter_button = tk.Button(log_analyzer_window, text="Filter Logs", command=lambda: self.filter_logs_gui(log_analyzer_window, keyword_entry), state=tk.DISABLED)
        filter_button.pack(pady=5)

        # Display area for results
        result_text = scrolledtext.ScrolledText(log_analyzer_window, width=100, height=25, wrap=tk.WORD)
        result_text.pack(pady=10)

        # Store widgets for later use
        log_analyzer_window.file_label = file_label
        log_analyzer_window.analyze_button = analyze_button
        log_analyzer_window.filter_button = filter_button
        log_analyzer_window.result_text = result_text
        log_analyzer_window.log_file = None

    def select_file(self, window, file_label):
        """Select a log file."""
        window.log_file = filedialog.askopenfilename(title="Select Log File", filetypes=[("Log Files", "*.log"), ("All Files", "*.*")])
        if window.log_file:
            file_label.config(text=f"Selected: {window.log_file}")
            window.analyze_button.config(state=tk.NORMAL)
            window.filter_button.config(state=tk.NORMAL)
        else:
            file_label.config(text="No file selected.")
            window.analyze_button.config(state=tk.DISABLED)
            window.filter_button.config(state=tk.DISABLED)

    def analyze_logs_gui(self, window):
        """Analyze the selected log file."""
        if not window.log_file:
            return
        
        try:
            with open(window.log_file, 'r') as file:
                logs = file.readlines()

            total_logs = len(logs)
            connected_logs = sum(1 for log in logs if "✅" in log)
            disconnected_logs = sum(1 for log in logs if "❌" in log)

            window.result_text.delete(1.0, tk.END)
            window.result_text.insert(tk.END, f"=== Log File Summary ===\n")
            window.result_text.insert(tk.END, f"Total Log Entries: {total_logs}\n")
            window.result_text.insert(tk.END, f"Connected Events: {connected_logs}\n")
            window.result_text.insert(tk.END, f"Disconnected Events: {disconnected_logs}\n")

        except Exception as e:
            window.result_text.delete(1.0, tk.END)
            window.result_text.insert(tk.END, f"Error reading file: {e}\n")

    def filter_logs_gui(self, window, keyword_entry):
        """Filter logs by a keyword."""
        if not window.log_file:
            return
        
        keyword = keyword_entry.get().strip()
        if not keyword:
            window.result_text.insert(tk.END, "Please enter a keyword to filter logs.\n")
            return
        
        try:
            with open(window.log_file, 'r') as file:
                logs = file.readlines()

            filtered_logs = [log for log in logs if keyword.upper() in log.upper()]

            window.result_text.delete(1.0, tk.END)
            window.result_text.insert(tk.END, f"=== Logs Containing '{keyword}' ===\n")
            if filtered_logs:
                for log in filtered_logs:
                    window.result_text.insert(tk.END, log)
            else:
                window.result_text.insert(tk.END, "No logs found with the given keyword.\n")

        except Exception as e:
            window.result_text.delete(1.0, tk.END)
            window.result_text.insert(tk.END, f"Error reading file: {e}\n")
