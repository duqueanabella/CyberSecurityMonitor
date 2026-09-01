import sys
import os
import sqlite3

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "database"))
import database

TEST_DB_PATH = "database/test_security_events.db"


def setup_function():
    database.get_connection = lambda: sqlite3.connect(TEST_DB_PATH)
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)
    database.init_db()


def teardown_function():
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)


def test_init_db_creates_events_table():
    conn = sqlite3.connect(TEST_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events'")
    result = cursor.fetchone()
    conn.close()
    assert result is not None


def test_log_event_inserts_a_row():
    database.log_event("PROCESS_SCAN", "malware.exe", "HIGH", "Test detection")

    conn = sqlite3.connect(TEST_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT event_type, process_name, severity, description FROM events")
    row = cursor.fetchone()
    conn.close()

    assert row == ("PROCESS_SCAN", "malware.exe", "HIGH", "Test detection")


def test_log_event_allows_none_process_name():
    database.log_event("PROCESS_SCAN", None, "INFO", "Scan completed, nothing found")

    conn = sqlite3.connect(TEST_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT process_name FROM events")
    row = cursor.fetchone()
    conn.close()

    assert row[0] is None
