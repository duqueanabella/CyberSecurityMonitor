import sqlite3
from datetime import datetime


def get_connection():
    return sqlite3.connect("database/security_events.db")

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            process_name TEXT,
            severity TEXT NOT NULL,
            description TEXT
        )
    """)
    conn.commit()
    conn.close()


def log_event(event_type, process_name, severity, description):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO events (timestamp, event_type, process_name, severity, description)
        VALUES (?, ?, ?, ?, ?)
    """, (datetime.now().isoformat(), event_type, process_name, severity, description))
    conn.commit()
    conn.close()
    