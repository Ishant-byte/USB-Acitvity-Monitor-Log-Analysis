import tkinter as tk
import mysql.connector
import bcrypt
from tkinter import messagebox
from usb_tracker import USBTrackerApp

# Database Configuration
DB_HOST = "localhost"
DB_USER = "root"
DB_PASSWORD = ""  # Change if needed
DB_NAME = "usbtracker"

# Connect to Database
def connect_to_db():
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        return conn
    except mysql.connector.Error as e:
        messagebox.showerror("Database Error", f"Failed to connect to database: {e}")
        return None

# Hash Passwords Securely
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Verify Entered Password
def check_password(stored_password, entered_password):
    return bcrypt.checkpw(entered_password.encode('utf-8'), stored_password.encode('utf-8'))

# Login Window
class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Login")

        # Login Frame
        self.login_frame = tk.Frame(root)
        self.login_frame.pack(pady=20)

        tk.Label(self.login_frame, text="Username:").grid(row=0, column=0, padx=10, pady=10)
        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.grid(row=0, column=1, padx=10, pady=10)

        tk.Label(self.login_frame, text="Password:").grid(row=1, column=0, padx=10, pady=10)
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.password_entry.grid(row=1, column=1, padx=10, pady=10)

        # Show Password Button
        self.show_password_btn = tk.Button(self.login_frame, text="Show", command=self.toggle_password)
        self.show_password_btn.grid(row=1, column=2, padx=5, pady=10)

        # Login & Register Buttons
        self.login_button = tk.Button(self.login_frame, text="Login", command=self.authenticate_user)
        self.login_button.grid(row=2, column=0, columnspan=3, pady=10)

        self.register_button = tk.Button(self.login_frame, text="Register", command=self.register_user)
        self.register_button.grid(row=3, column=0, columnspan=3, pady=5)

    # Toggle Password Visibility
    def toggle_password(self):
        if self.password_entry.cget("show") == "*":
            self.password_entry.config(show="")
            self.show_password_btn.config(text="Hide")
        else:
            self.password_entry.config(show="*")
            self.show_password_btn.config(text="Show")

    # Authenticate User
    def authenticate_user(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Login Failed", "All fields are required.")
            return

        conn = connect_to_db()
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
                user = cursor.fetchone()

                if user and check_password(user[0], password):
                    messagebox.showinfo("Login Successful", f"Welcome, {username}!")
                    self.launch_main_tool(username)  # Pass username to display in the tool

                else:
                    messagebox.showerror("Login Failed", "Invalid username or password.")

            except mysql.connector.Error as e:
                messagebox.showerror("Database Error", f"Failed to authenticate user: {e}")
            finally:
                cursor.close()
                conn.close()

    # Register User
    def register_user(self):
        reg_window = tk.Toplevel(self.root)
        reg_window.title("Register")

        tk.Label(reg_window, text="Username:").grid(row=0, column=0, padx=10, pady=10)
        reg_username_entry = tk.Entry(reg_window)
        reg_username_entry.grid(row=0, column=1, padx=10, pady=10)

        tk.Label(reg_window, text="Password:").grid(row=1, column=0, padx=10, pady=10)
        reg_password_entry = tk.Entry(reg_window, show="*")
        reg_password_entry.grid(row=1, column=1, padx=10, pady=10)

        tk.Label(reg_window, text="Confirm Password:").grid(row=2, column=0, padx=10, pady=10)
        confirm_password_entry = tk.Entry(reg_window, show="*")
        confirm_password_entry.grid(row=2, column=1, padx=10, pady=10)

        def process_registration():
            username = reg_username_entry.get().strip()
            password = reg_password_entry.get()
            confirm_password = confirm_password_entry.get()

            if not username or not password or not confirm_password:
                messagebox.showerror("Registration Failed", "All fields are required.")
                return

            if password != confirm_password:
                messagebox.showerror("Registration Failed", "Passwords do not match.")
                return

            conn = connect_to_db()
            if conn:
                try:
                    cursor = conn.cursor()
                    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
                    if cursor.fetchone():
                        messagebox.showerror("Registration Failed", "Username already exists.")
                    else:
                        hashed_pw = hash_password(password).decode('utf-8')
                        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_pw))
                        conn.commit()
                        messagebox.showinfo("Registration Successful", "User registered successfully.")
                        reg_window.destroy()

                except mysql.connector.Error as e:
                    messagebox.showerror("Database Error", f"Failed to register user: {e}")
                finally:
                    cursor.close()
                    conn.close()

        tk.Button(reg_window, text="Register", command=process_registration).grid(row=3, column=0, columnspan=2, pady=10)

    # Launch Main Tool (USBTrackerApp) with Logout Button
    def launch_main_tool(self, username):
        """Displays the main tool after successful login."""
        self.root.title("USB Tracker")
        self.username = username  # Store username

        # Remove login UI
        for widget in self.root.winfo_children():
            widget.destroy()

        # Initialize the main tool
        tracker_frame = tk.Frame(self.root)
        tracker_frame.pack(pady=20)

        # Display welcome message with username 
        tk.Label(tracker_frame, text=f"Welcome, {self.username}!").pack(pady=20)

        # Launch the USBTrackerApp
        self.app = USBTrackerApp(self.root)

        # Logout Button
        logout_button = tk.Button(tracker_frame, text="Logout", command=self.logout)
        logout_button.pack(pady=10)

    # Logout Function
    def logout(self):
        """Logs the user out and returns to login screen."""
        messagebox.showinfo("Logged Out", "You have been logged out.")
        
        # Redirect to login again
        for widget in self.root.winfo_children():
            widget.destroy()

        self.__init__(self.root)  # Restart the login UI


if __name__ == "__main__":
    root = tk.Tk()
    app = LoginApp(root)  
    root.mainloop()
