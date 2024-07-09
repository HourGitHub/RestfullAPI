import sqlite3
from werkzeug.security import generate_password_hash

# SQLite database file path
db_file = 'restfulapi.db'

# User data to insert
username = 'test'
password = 'test'
email = 'test@domain.com'

# Generate hashed password
hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

# SQL statement to insert a user
insert_user_sql = """
INSERT INTO users (username, password, email)
VALUES (?, ?, ?);
"""

# Function to insert user
def insert_user(username, hashed_password, email):
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        cursor.execute(insert_user_sql, (username, hashed_password, email))
        conn.commit()
        print("User inserted successfully!")

    except sqlite3.Error as e:
        print(f"Error inserting user: {e}")

    finally:
        if conn:
            conn.close()

# Run the function to insert user
if __name__ == '__main__':
    insert_user(username, hashed_password, email)
