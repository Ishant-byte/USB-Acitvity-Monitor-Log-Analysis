import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox

class LogAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Analyze the log of usb")
        self.root.geometry("800x600")

        # File selection button
        self.file_label = tk.Label(root, text="No file selected.", fg="blue")
        self.file_label.pack(pady=10)
        self.file_button = tk.Button(root, text="Select Log File", command=self.select_file)
        self.file_button.pack(pady=5)

        # Analyze Button
        self.analyze_button = tk.Button(root, text="Analyze Logs", command=self.analyze_logs, state=tk.DISABLED)
        self.analyze_button.pack(pady=5)

        # Keyword filter entry and button
        self.keyword_label = tk.Label(root, text="Filter by Keyword:")
        self.keyword_label.pack(pady=5)
        self.keyword_entry = tk.Entry(root)
        self.keyword_entry.pack(pady=5)
        self.filter_button = tk.Button(root, text="Filter Logs", command=self.filter_logs, state=tk.DISABLED)
        self.filter_button.pack(pady=5)

        # Display area for results
        self.result_text = scrolledtext.ScrolledText(root, width=100, height=25, wrap=tk.WORD)
        self.result_text.pack(pady=10)

        # Log file path
        self.log_file = None

    def select_file(self):
        """Select a log file."""
        self.log_file = filedialog.askopenfilename(title="Select Log File", filetypes=[("Log Files", "*.log"), ("All Files", "*.*")])
        if self.log_file:
            self.file_label.config(text=f"Selected: {self.log_file}")
            self.analyze_button.config(state=tk.NORMAL)
            self.filter_button.config(state=tk.NORMAL)
        else:
            self.file_label.config(text="No file selected.")
            self.analyze_button.config(state=tk.DISABLED)
            self.filter_button.config(state=tk.DISABLED)

    def analyze_logs(self):
        """Analyze the selected log file."""
        if not self.log_file:
            return
        
        try:
            with open(self.log_file, 'r') as file:
                logs = file.readlines()

            total_logs = len(logs)
            connected_logs = sum(1 for log in logs if "✅" in log)
            disconnected_logs = sum(1 for log in logs if "❌" in log)

            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"=== Log File Summary ===\n")
            self.result_text.insert(tk.END, f"Total Log Entries: {total_logs}\n")
            self.result_text.insert(tk.END, f"Connected Events: {connected_logs}\n")
            self.result_text.insert(tk.END, f"Disconnected Events: {disconnected_logs}\n")

        except Exception as e:
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Error reading file: {e}\n")

    def filter_logs(self):
        """Filter logs by a keyword."""
        if not self.log_file:
            return
        
        keyword = self.keyword_entry.get().strip()
        if not keyword:
            self.result_text.insert(tk.END, "Please enter a keyword to filter logs.\n")
            return
        
        try:
            with open(self.log_file, 'r') as file:
                logs = file.readlines()

            filtered_logs = [log for log in logs if keyword.upper() in log.upper()]

            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"=== Logs Containing '{keyword}' ===\n")
            if filtered_logs:
                for log in filtered_logs:
                    self.result_text.insert(tk.END, log)
            else:
                self.result_text.insert(tk.END, "No logs found with the given keyword.\n")

        except Exception as e:
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Error reading file: {e}\n")
