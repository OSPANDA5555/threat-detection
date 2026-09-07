import os
import json
import time
import sqlite3
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

LOG_DIR = os.getenv("LOG_DIR", "/var/log/soc")
DB_PATH = os.path.join(LOG_DIR, "soc_logs.db")
JSONL_PATH = os.path.join(LOG_DIR, "audit_events.jsonl")

os.makedirs(LOG_DIR, exist_ok=True)

# Initialize SQLite database index for fast log queries
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_logs (
            id TEXT PRIMARY KEY,
            timestamp TEXT,
            event_type TEXT,
            host TEXT,
            user TEXT,
            source_ip TEXT,
            status TEXT,
            payload TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

app = FastAPI(
    title="Dedicated Security Log Storage Service",
    description="Centralized Log Collector & Storage Container for SOC Audit Logs and Telemetry Events",
    version="1.0.0"
)

class LogEntry(BaseModel):
    id: str = Field(default_factory=lambda: f"log-{int(time.time()*1000)}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: str
    host: Optional[str] = None
    user: Optional[str] = None
    source_ip: Optional[str] = None
    status: str = "INFO"
    details: Dict[str, Any] = Field(default_factory=dict)

@app.get("/health")
def health_check():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM security_logs")
    count = cursor.fetchone()[0]
    conn.close()

    storage_bytes = os.path.getsize(JSONL_PATH) if os.path.exists(JSONL_PATH) else 0

    return {
        "status": "HEALTHY",
        "service": "threat_hunting_log_storage",
        "total_logs_stored": count,
        "jsonl_storage_bytes": storage_bytes,
        "log_directory": LOG_DIR
    }

@app.post("/api/v1/logs", status_code=201)
def ingest_log(entry: LogEntry):
    # 1. Append to immutable JSONL audit file
    log_data = entry.model_dump()
    with open(JSONL_PATH, "a") as f:
        f.write(json.dumps(log_data) + "\n")

    # 2. Insert into SQLite search index
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO security_logs (id, timestamp, event_type, host, user, source_ip, status, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            entry.id,
            entry.timestamp,
            entry.event_type,
            entry.host or "",
            entry.user or "",
            entry.source_ip or "",
            entry.status,
            json.dumps(entry.details)
        )
    )
    conn.commit()
    conn.close()

    return {"status": "SUCCESS", "log_id": entry.id}

@app.get("/api/v1/logs")
def query_logs(
    event_type: Optional[str] = None,
    host: Optional[str] = None,
    user: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(default=50, le=500)
):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    query = "SELECT id, timestamp, event_type, host, user, source_ip, status, payload FROM security_logs WHERE 1=1"
    params = []

    if event_type:
        query += " AND event_type = ?"
        params.append(event_type)
    if host:
        query += " AND host = ?"
        params.append(host)
    if user:
        query += " AND user = ?"
        params.append(user)
    if status:
        query += " AND status = ?"
        params.append(status)

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    logs = []
    for r in rows:
        logs.append({
            "id": r[0],
            "timestamp": r[1],
            "event_type": r[2],
            "host": r[3],
            "user": r[4],
            "source_ip": r[5],
            "status": r[6],
            "details": json.loads(r[7]) if r[7] else {}
        })

    return {"count": len(logs), "logs": logs}
