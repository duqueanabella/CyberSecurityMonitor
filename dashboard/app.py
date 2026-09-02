import sys
import os
import sqlite3
from flask import Flask, jsonify, send_from_directory


sys.path.append(os.path.join(os.path.dirname(__file__), "..", "database"))

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "database", "security_events.db")


@app.route("/api/events")
def get_events():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM events ORDER BY id DESC Limit 50")
    rows = cursor.fetchall()
    conn.close()

    events = [dict(row) for row in rows]
    return jsonify(events)

from flask import send_from_directory

@app.route("/")
def dashboard_home():
    return send_from_directory(os.path.dirname(__file__), "index.html")


@app.route("/style.css")
def dashboard_css():
    return send_from_directory(os.path.dirname(__file__), "style.css")

@app.route("/script.js")
def dashboard_js():
    return send_from_directory(os.path.dirname(__file__), "script.js")

@app.route("/api/timeline")
def get_timeline():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT strftime('%Y-%m-%d %H:00', timestamp) AS hour,
               COUNT(*) AS total,
               SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) AS alerts
        FROM events
        GROUP BY hour
        ORDER BY hour
    """)
    rows = cursor.fetchall()
    conn.close()

    timeline = [{"hour": row[0], "total": row[1], "alerts": row[2]} for row in rows]
    return jsonify(timeline)


if __name__ == "__main__":
    app.run(debug=True, port=5000)

