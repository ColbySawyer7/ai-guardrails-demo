#!/usr/bin/env python3
# This script creates a SQLite database and populates it with fake user data.
# It uses the Faker library to generate fake data.
# The database is created in the current working directory.
# The database file is named "users.db".
# The script logs information and errors to the console.

import sqlite3
import os
from faker import Faker
from typing import List, Dict
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Faker
fake = Faker()

def create_database(db_path: str = "users.db") -> sqlite3.Connection:
    """Create and initialize the SQLite database with a users table."""
    try:
        # Remove existing database if it exists
        if os.path.exists(db_path):
            os.remove(db_path)
            logger.info(f"Removed existing database at {db_path}")

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Create users table with PII fields
        cursor.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                phone_number TEXT,
                date_of_birth DATE,
                address TEXT,
                ssn TEXT UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create indexes for commonly queried fields
        cursor.execute("CREATE INDEX idx_email ON users(email)")
        cursor.execute("CREATE INDEX idx_ssn ON users(ssn)")
        
        conn.commit()
        logger.info("Database and tables created successfully")
        return conn
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        raise

def generate_fake_users(count: int = 100) -> List[Dict]:
    """Generate a list of fake user records."""
    users = []
    for _ in range(count):
        user = {
            'first_name': fake.first_name(),
            'last_name': fake.last_name(),
            'email': fake.unique.email(),
            'phone_number': fake.phone_number(),
            'date_of_birth': fake.date_of_birth(minimum_age=18, maximum_age=90).strftime('%Y-%m-%d'),
            'address': fake.address(),
            'ssn': fake.unique.ssn()
        }
        users.append(user)
    return users

def insert_users(conn: sqlite3.Connection, users: List[Dict]) -> None:
    """Insert users into the database using parameterized queries."""
    try:
        cursor = conn.cursor()
        for user in users:
            cursor.execute("""
                INSERT INTO users (
                    first_name, last_name, email, phone_number,
                    date_of_birth, address, ssn
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                user['first_name'],
                user['last_name'],
                user['email'],
                user['phone_number'],
                user['date_of_birth'],
                user['address'],
                user['ssn']
            ))
        conn.commit()
        logger.info(f"Successfully inserted {len(users)} users")
    except sqlite3.Error as e:
        logger.error(f"Error inserting users: {e}")
        conn.rollback()
        raise

def main():
    """Main function to create and populate the database."""
    try:
        # Create database connection
        conn = create_database()
        
        # Generate and insert fake users
        users = generate_fake_users(count=100)
        insert_users(conn, users)
        
        # Verify data insertion
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        logger.info(f"Total users in database: {count}")
        
        # Close the connection
        conn.close()
        logger.info("Database operations completed successfully")
        
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        raise

if __name__ == "__main__":
    main()
