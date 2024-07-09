import sqlite3

# SQLite database file path
db_file = 'restfulapi.db'

# SQL statements to create tables
create_users_table = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE
);
"""

create_tokens_table = """
CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL,
    expiry_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
"""

# Function to create tables
def create_tables():
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Create users table
        cursor.execute(create_users_table)

        # Create tokens table
        cursor.execute(create_tokens_table)

        conn.commit()
        print("Tables created successfully!")

    except sqlite3.Error as e:
        print(f"Error creating tables: {e}")

    finally:
        if conn:
            conn.close()

# Run the function to create tables
if __name__ == '__main__':
    create_tables()
