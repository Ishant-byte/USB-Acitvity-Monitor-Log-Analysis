# USB Activity Monitor and Log Analysis System


The **USB Activity Monitor and Log Analysis System** is a Python-based tool designed to monitor USB device activities, analyze historical logs, and provide a user-friendly interface for both technical and non-technical users. It is particularly useful for system administrators, security professionals, and anyone interested in tracking USB device usage.

---

## Features

- **Real-Time USB Monitoring**: Tracks USB connections and disconnections in real time.
- **Device Information Display**: Provides detailed information about connected USB devices (e.g., vendor, model, size, serial number).
- **Log Analysis**: Filters and analyzes historical logs based on user-defined criteria (e.g., keywords, event types).
- **Secure User Authentication**: Ensures only authorized users can access the system using bcrypt for password hashing.
- **Log Saving**: Allows users to save filtered logs to a file for further analysis.
- **User-Friendly GUI**: Built using Tkinter for easy interaction.

---

## Tools and Technologies Used

- **Programming Language**: Python
- **Libraries**:
  - `tkinter`: For building the graphical user interface (GUI).
  - `mysql.connector`: For database connectivity.
  - `bcrypt`: For secure password hashing.
  - `subprocess`: For executing system commands.
  - `re`: For parsing and filtering log data.
- **Database**: MySQL
- **System Commands**: `lsusb`, `journalctl`, `lsblk`
- **Development Environment**: Linux (Ubuntu), Visual Studio Code, Git, GitHub

---

## Installation and Setup

### Prerequisites
- Python 3.x
- MySQL Server
- Linux-based operating system (for system command support)

