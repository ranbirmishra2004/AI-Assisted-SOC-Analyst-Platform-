import json
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone

from werkzeug.security import check_password_hash, generate_password_hash

DB = os.getenv("SOC_DB_PATH", "data/soc.db")
STATUSES = ("New", "Triaging", "Contained", "Resolved", "Closed")
os.makedirs("data", exist_ok=True)

def con():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA busy_timeout=5000")
    return c

def init():
    c = con()
    c.execute("""CREATE TABLE IF NOT EXISTS incidents(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT, severity TEXT, attack_type TEXT,
        source_ip TEXT, affected_user TEXT, summary TEXT,
        events_json TEXT, ai_json TEXT, iocs_json TEXT NOT NULL DEFAULT '{}',
        status TEXT NOT NULL DEFAULT 'New',
        assigned_to TEXT NOT NULL DEFAULT '',
        notes_json TEXT NOT NULL DEFAULT '[]',
        risk_score INTEGER NOT NULL DEFAULT -1,
        alert_tags_json TEXT NOT NULL DEFAULT '[]',
        detection_evidence_json TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL COLLATE NOCASE UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin', 'analyst', 'viewer')),
        is_active INTEGER NOT NULL DEFAULT 1,
        failed_login_attempts INTEGER NOT NULL DEFAULT 0,
        locked_until TEXT,
        last_login_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
    c.execute("""CREATE TABLE IF NOT EXISTS audit_events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        action TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id TEXT NOT NULL DEFAULT '',
        details_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at DESC)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events(actor_user_id, created_at DESC)"
    )
    columns = {r["name"] for r in c.execute("PRAGMA table_info(incidents)")}
    migrations = {
        "status": "TEXT NOT NULL DEFAULT 'New'",
        "iocs_json": "TEXT NOT NULL DEFAULT '{}'",
        "assigned_to": "TEXT NOT NULL DEFAULT ''",
        "notes_json": "TEXT NOT NULL DEFAULT '[]'",
        "risk_score": "INTEGER NOT NULL DEFAULT -1",
        "alert_tags_json": "TEXT NOT NULL DEFAULT '[]'",
        "detection_evidence_json": "TEXT NOT NULL DEFAULT '[]'",
        "created_at": "TEXT NOT NULL DEFAULT ''",
        "updated_at": "TEXT NOT NULL DEFAULT ''",
    }
    for name, definition in migrations.items():
        if name not in columns:
            c.execute(f"ALTER TABLE incidents ADD COLUMN {name} {definition}")
    c.execute(
        "UPDATE incidents SET created_at=CURRENT_TIMESTAMP WHERE created_at=''"
    )
    c.execute(
        "UPDATE incidents SET updated_at=CURRENT_TIMESTAMP WHERE updated_at=''"
    )
    c.execute(
        """UPDATE incidents SET risk_score=-1
        WHERE risk_score=0 AND alert_tags_json='[]' AND detection_evidence_json='[]'"""
    )
    c.commit()
    c.close()

def insert(item, actor_user_id=None):
    c = con()
    try:
        cur = c.execute(
            """INSERT INTO incidents
            (filename,severity,attack_type,source_ip,affected_user,summary,
             events_json,ai_json,iocs_json,risk_score,alert_tags_json,detection_evidence_json)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (item["filename"], item["severity"], item["attack_type"],
             item["source_ip"], item["affected_user"], item["summary"],
             json.dumps(item["events"]), json.dumps({}), json.dumps(item.get("iocs", {})),
             item.get("risk_score", 0),
             json.dumps(item.get("alert_tags", [])),
             json.dumps(item.get("detection_evidence", [])))
        )
        item["id"] = cur.lastrowid
        c.execute(
            """INSERT INTO audit_events
            (actor_user_id,action,entity_type,entity_id,details_json)
            VALUES(?,?,?,?,?)""",
            (
                actor_user_id,
                "incident.created",
                "incident",
                str(item["id"]),
                json.dumps({"filename": item["filename"]}),
            ),
        )
        c.commit()
        return item
    finally:
        c.close()

def create_user(username, password, role="analyst"):
    username = username.strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,64}", username):
        raise ValueError(
            "Username must be 3-64 characters using letters, numbers, dot, underscore, or hyphen."
        )
    if len(password) < 12:
        raise ValueError("Password must contain at least 12 characters.")
    if role not in {"admin", "analyst", "viewer"}:
        raise ValueError("Role must be admin, analyst, or viewer.")
    c = con()
    try:
        cur = c.execute(
            "INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
            (username, generate_password_hash(password), role),
        )
        c.commit()
        return cur.lastrowid
    finally:
        c.close()

def get_user(user_id):
    c = con()
    try:
        user = c.execute(
            "SELECT id,username,role,is_active FROM users WHERE id=?",
            (user_id,),
        ).fetchone()
        return dict(user) if user else None
    finally:
        c.close()

def authenticate_user(username, password):
    c = con()
    try:
        user = c.execute(
            "SELECT * FROM users WHERE username=? COLLATE NOCASE",
            (username.strip(),),
        ).fetchone()
        if not user or not user["is_active"]:
            return None

        now = datetime.now(timezone.utc)
        locked_until = user["locked_until"]
        if locked_until and datetime.fromisoformat(locked_until) > now:
            return None
        if not check_password_hash(user["password_hash"], password):
            failures = user["failed_login_attempts"] + 1
            lock_until = (
                (now + timedelta(minutes=15)).isoformat(timespec="seconds")
                if failures >= 5
                else None
            )
            c.execute(
                """UPDATE users SET failed_login_attempts=?, locked_until=?
                WHERE id=?""",
                (0 if lock_until else failures, lock_until, user["id"]),
            )
            c.commit()
            return None

        c.execute(
            """UPDATE users SET failed_login_attempts=0, locked_until=NULL,
            last_login_at=? WHERE id=?""",
            (now.isoformat(timespec="seconds"), user["id"]),
        )
        c.commit()
        return {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
        }
    finally:
        c.close()

def record_audit_event(actor_user_id, action, entity_type, entity_id="", details=None):
    c = con()
    try:
        c.execute(
            """INSERT INTO audit_events
            (actor_user_id,action,entity_type,entity_id,details_json)
            VALUES(?,?,?,?,?)""",
            (
                actor_user_id,
                action,
                entity_type,
                str(entity_id),
                json.dumps(details or {}),
            ),
        )
        c.commit()
    finally:
        c.close()

def list_audit_events(limit=100):
    c = con()
    try:
        rows = c.execute(
            """SELECT audit_events.id, audit_events.actor_user_id,
            users.username AS actor, audit_events.action, audit_events.entity_type,
            audit_events.entity_id, audit_events.details_json, audit_events.created_at
            FROM audit_events LEFT JOIN users ON users.id=audit_events.actor_user_id
            ORDER BY audit_events.id DESC LIMIT ?""",
            (max(1, min(int(limit), 500)),),
        ).fetchall()
        events = []
        for row in rows:
            event = dict(row)
            event["details"] = json.loads(event.pop("details_json") or "{}")
            events.append(event)
        return events
    finally:
        c.close()

def update_ai(i, ai):
    c = con()
    c.execute(
        "UPDATE incidents SET ai_json=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
        (json.dumps(ai), i)
    )
    c.commit()
    c.close()

def update_workflow(i, status, assigned_to, note, actor_user_id=None):
    c = con()
    r = c.execute("SELECT notes_json FROM incidents WHERE id=?", (i,)).fetchone()
    if not r:
        c.close()
        return False
    notes = json.loads(r["notes_json"] or "[]")
    if note:
        notes.append({
            "text": note,
            "created_at": datetime.now().astimezone().isoformat(timespec="seconds")
        })
    c.execute(
        """UPDATE incidents
        SET status=?, assigned_to=?, notes_json=?, updated_at=CURRENT_TIMESTAMP
        WHERE id=?""",
        (status, assigned_to, json.dumps(notes), i)
    )
    c.execute(
        """INSERT INTO audit_events
        (actor_user_id,action,entity_type,entity_id,details_json)
        VALUES(?,?,?,?,?)""",
        (
            actor_user_id,
            "incident.workflow_updated",
            "incident",
            str(i),
            json.dumps({"status": status, "assigned_to": assigned_to}),
        ),
    )
    c.commit()
    c.close()
    return True

def row(r):
    if not r:
        return None
    x = dict(r)
    x["events"] = json.loads(x.pop("events_json") or "[]")
    x.pop("ai_json", None)
    x["iocs"] = json.loads(x.pop("iocs_json", "{}") or "{}")
    x["notes"] = json.loads(x.pop("notes_json") or "[]")
    x["alert_tags"] = json.loads(x.pop("alert_tags_json") or "[]")
    x["detection_evidence"] = json.loads(
        x.pop("detection_evidence_json", "[]") or "[]"
    )
    return x

def get(i):
    c = con()
    r = c.execute("SELECT * FROM incidents WHERE id=?", (i,)).fetchone()
    c.close()
    return row(r)

def all(search="", severity="", status="", days=None, risk_min=0, sort="newest"):
    c = con()
    clauses = []
    values = []
    if search:
        clauses.append("(filename LIKE ? OR attack_type LIKE ? OR source_ip LIKE ? OR affected_user LIKE ?)")
        values.extend([f"%{search}%"] * 4)
    if severity:
        clauses.append("severity=?")
        values.append(severity)
    if status:
        clauses.append("status=?")
        values.append(status)
    if days:
        clauses.append("created_at >= datetime('now', ?)")
        values.append(f"-{days} days")
    if risk_min is not None:
        clauses.append("risk_score >= ?")
        values.append(int(risk_min))
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    order_by = "risk_score DESC, id DESC" if sort == "risk" else "id DESC"
    if sort == "severity":
        order_by = "CASE severity WHEN 'Critical' THEN 5 WHEN 'High' THEN 4 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 2 WHEN 'Info' THEN 1 ELSE 0 END DESC, id DESC"
    r = c.execute(
        "SELECT id,filename,severity,attack_type,source_ip,affected_user,summary,"
        "status,assigned_to,risk_score,alert_tags_json,detection_evidence_json,"
        "created_at,updated_at "
        f"FROM incidents{where} ORDER BY {order_by}",
        values
    ).fetchall()
    c.close()
    incidents = []
    for item in r:
        incident = dict(item)
        incident["alert_tags"] = json.loads(incident.pop("alert_tags_json") or "[]")
        incident["detection_evidence"] = json.loads(
            incident.pop("detection_evidence_json") or "[]"
        )
        incidents.append(incident)
    return incidents

def update_workflow_bulk(ids, status, assigned_to, note, actor_user_id=None):
    c = con()
    placeholders = ",".join("?" for _ in ids)
    try:
        rows = c.execute(
            f"SELECT id,notes_json FROM incidents WHERE id IN ({placeholders})",
            ids,
        ).fetchall()
        if len(rows) != len(ids):
            c.rollback()
            return False

        updated_at = datetime.now().astimezone().isoformat(timespec="seconds")
        updates = []
        for item in rows:
            notes = json.loads(item["notes_json"] or "[]")
            if note:
                notes.append({"text": note, "created_at": updated_at})
            updates.append((status, assigned_to, json.dumps(notes), item["id"]))
        c.executemany(
            """UPDATE incidents
            SET status=?, assigned_to=?, notes_json=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=?""",
            updates,
        )
        c.executemany(
            """INSERT INTO audit_events
            (actor_user_id,action,entity_type,entity_id,details_json)
            VALUES(?,?,?,?,?)""",
            [
                (
                    actor_user_id,
                    "incident.workflow_updated",
                    "incident",
                    str(item["id"]),
                    json.dumps({"status": status, "assigned_to": assigned_to}),
                )
                for item in rows
            ],
        )
        c.commit()
        return True
    finally:
        c.close()

init()
