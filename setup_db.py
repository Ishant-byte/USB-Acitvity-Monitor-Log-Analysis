import mysql.connector

# Database connection details
DB_HOST = "localhost"
DB_USER = "root"  
DB_PASSWORD = ""
DB_NAME = "usbtracker"

def connect_to_db():
    """Connect to MySQL database."""
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD
        )
        return conn
    except mysql.connector.Error as e:
        print(f"⚠ Database Connection Error: {e}")
        return None

def create_database_and_tables():
    """Create database and tables if they don't exist."""
    conn = connect_to_db()
    if conn:
        try:
            cursor = conn.cursor()

            # Create the database if not exists
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
            cursor.execute(f"USE {DB_NAME}")

            # Create the users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) NOT NULL UNIQUE,
                    password VARCHAR(255) NOT NULL
                )
            """)

            # Create the logs table (for future use)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT,
                    log_entry TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)

            conn.commit()
            print("✅ Database and tables created successfully.")

        except mysql.connector.Error as e:
            print(f"⚠ Database Setup Error: {e}")
        finally:
            cursor.close()
            conn.close()

if __name__ == "__main__":
    create_database_and_tables()