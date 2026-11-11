import csv
import hmac
import io
import json
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import click
from flask import (
    Flask,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

from analyzer import analyze_text, get_incident
from assessment import answer_question, build_assessment
import database
from database import (
    STATUSES,
    all as list_incidents,
    authenticate_user,
    create_user,
    get_user,
    list_audit_events,
    update_workflow,
    update_workflow_bulk,
)
from report import build_report

app = Flask(__name__)
environment = os.getenv("SOC_ENV", "development").lower()
secret_key = os.getenv("SOC_SECRET_KEY")
if environment == "production" and (
    not secret_key or secret_key.startswith("change-me-")
):
    raise RuntimeError("Set SOC_SECRET_KEY to a unique random value of at least 32 characters.")
app.secret_key = secret_key or secrets.token_hex(32)
if len(app.secret_key) < 32:
    raise RuntimeError("SOC_SECRET_KEY must contain at least 32 characters.")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SOC_COOKIE_SECURE", "").lower() in {"1", "true", "yes"},
)
app.config["MAX_CONTENT_LENGTH"] = 3 * 1024 * 1024

SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
PERIODS = {"7": 7, "30": 30, "90": 90, "all": None}

@app.before_request
def enforce_identity_and_csrf():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)

    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        submitted_token = request.headers.get("X-CSRF-Token")
        if not submitted_token and request.form:
            submitted_token = request.form.get("csrf_token")
        if not submitted_token or not hmac.compare_digest(
            session["csrf_token"], submitted_token
        ):
            if request.path.startswith("/api/") or request.is_json:
                return jsonify(error="CSRF validation failed."), 400
            return "CSRF validation failed.", 400

    if request.endpoint in {"login", "static", "health"}:
        return None

    user_id = session.get("user_id")
    current_user = get_user(user_id) if type(user_id) is int else None
    if not current_user or not current_user["is_active"]:
        session.pop("user_id", None)
        if request.path.startswith("/api/") or request.is_json:
            return jsonify(error="Authentication required."), 401
        return redirect(url_for("login", next=request.path))

    g.current_user = current_user
    if request.endpoint == "audit_events" and current_user["role"] != "admin":
        return jsonify(error="Administrator role required."), 403
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        if current_user["role"] == "viewer" and request.endpoint != "logout":
            return jsonify(error="Analyst or administrator role required."), 403
    return None

@app.context_processor
def expose_security_context():
    return {
        "csrf_token": session.get("csrf_token", ""),
        "current_user": getattr(g, "current_user", None),
    }

def _safe_next_url(candidate):
    if not candidate:
        return "/"
    parsed = urlsplit(candidate)
    if (
        candidate.startswith("/")
        and not candidate.startswith("//")
        and "\\" not in candidate
        and not parsed.netloc
    ):
        return candidate
    return "/"

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", next_url=_safe_next_url(request.args.get("next", "")))

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    user = authenticate_user(username, password) if username and password else None
    if not user:
        database.record_audit_event(
            None,
            "auth.login_failed",
            "user",
            details={"username": username[:64]},
        )
        return render_template(
            "login.html",
            next_url=_safe_next_url(request.form.get("next", "")),
            error="Invalid username or password, or the account is temporarily locked.",
        ), 401

    session.clear()
    session["user_id"] = user["id"]
    session["csrf_token"] = secrets.token_urlsafe(32)
    database.record_audit_event(user["id"], "auth.login_succeeded", "user", user["id"])
    return redirect(_safe_next_url(request.form.get("next", "")))

@app.route("/logout", methods=["POST"])
def logout():
    user_id = g.current_user["id"]
    database.record_audit_event(user_id, "auth.logout", "user", user_id)
    session.clear()
    return redirect(url_for("login"))

@app.route("/admin/audit-events")
def audit_events():
    return jsonify(events=list_audit_events())

@app.cli.command("create-user")
@click.option("--username", prompt=True)
@click.option("--role", type=click.Choice(["admin", "analyst", "viewer"]), default="analyst")
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
def create_user_command(username, role, password):
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,64}", username):
        raise click.ClickException(
            "Username must be 3-64 characters using letters, numbers, dot, underscore, or hyphen."
        )
    try:
        user_id = create_user(username, password, role)
    except ValueError as error:
        raise click.ClickException(str(error)) from error
    except sqlite3.IntegrityError as error:
        raise click.ClickException("That username already exists.") from error
    database.record_audit_event(
        None,
        "user.created",
        "user",
        user_id,
        {"username": username, "role": role},
    )
    click.echo(f"Created {role} account {username}.")

def _incident_filters():
    search = request.args.get("q", "").strip()[:100]
    severity = request.args.get("severity", "").strip()
    status = request.args.get("status", "").strip()
    period = request.args.get("period", "30").strip()
    risk_min_raw = request.args.get("risk_min", "0").strip()
    sort = request.args.get("sort", "newest").strip().lower()
    if severity not in {"", *SEVERITIES}:
        severity = ""
    if status not in {"", *STATUSES}:
        status = ""
    if period not in PERIODS:
        period = "30"
    try:
        risk_min = max(0, min(100, int(risk_min_raw)))
    except ValueError:
        risk_min = 0
    if sort not in {"newest", "risk", "severity"}:
        sort = "newest"
    return {
        "search": search,
        "severity": severity,
        "status": status,
        "period": period,
        "days": PERIODS[period],
        "risk_min": risk_min,
        "sort": sort,
    }

@app.route("/")
def index():
    filters = _incident_filters()
    incidents = list_incidents(
        search=filters["search"],
        severity=filters["severity"],
        status=filters["status"],
        days=filters["days"],
        risk_min=filters["risk_min"],
        sort=filters["sort"],
    )
    counts = {
        "total": len(incidents),
        "open": sum(x["status"] not in {"Resolved", "Closed"} for x in incidents),
        "critical": sum(x["severity"] == "Critical" for x in incidents),
        "high": sum(x["severity"] == "High" for x in incidents),
    }
    top_user = {}
    top_ip = {}
    top_attack = {}
    if incidents:
        user_counts = {}
        for incident in incidents:
            user = (incident.get("affected_user") or "Unknown").strip()
            if user and user != "Unknown":
                user_counts[user] = user_counts.get(user, 0) + 1
        if user_counts:
            top_user = {"label": max(user_counts, key=user_counts.get), "value": user_counts[max(user_counts, key=user_counts.get)]}

        ip_counts = {}
        for incident in incidents:
            ip = (incident.get("source_ip") or "Unknown").strip()
            if ip and ip != "Unknown":
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        if ip_counts:
            top_ip = {"label": max(ip_counts, key=ip_counts.get), "value": ip_counts[max(ip_counts, key=ip_counts.get)]}

        attack_counts = {}
        for incident in incidents:
            attack = (incident.get("attack_type") or "Unclassified").strip()
            if attack:
                attack_counts[attack] = attack_counts.get(attack, 0) + 1
        if attack_counts:
            top_attack = {"label": max(attack_counts, key=attack_counts.get), "value": attack_counts[max(attack_counts, key=attack_counts.get)]}

    highest_risk = max((incident.get("risk_score", -1) for incident in incidents), default=-1)
    if incidents and highest_risk >= 0:
        highest_risk_case = next(incident for incident in incidents if incident.get("risk_score") == highest_risk)
    else:
        highest_risk_case = None

    insight_cards = [
        {"title": "Highest risk case", "value": highest_risk_case["attack_type"] if highest_risk_case else "No cases", "meta": f"{highest_risk}/100" if highest_risk_case else "0/100"},
        {"title": "Most targeted user", "value": top_user.get("label", "No user activity"), "meta": f"{top_user.get('value', 0)} occurrences" if top_user else "0 occurrences"},
        {"title": "Most active source IP", "value": top_ip.get("label", "No source IP"), "meta": f"{top_ip.get('value', 0)} cases" if top_ip else "0 cases"},
        {"title": "Top attack pattern", "value": top_attack.get("label", "No pattern"), "meta": f"{top_attack.get('value', 0)} cases" if top_attack else "0 cases"},
    ]
    trend_days = min(filters["days"] or 14, 14)
    today = datetime.now(timezone.utc).date()
    trend_dates = [today - timedelta(days=offset) for offset in range(trend_days - 1, -1, -1)]
    trend_counts = {day.isoformat(): 0 for day in trend_dates}
    for incident in incidents:
        created_at = incident["created_at"]
        if created_at:
            created_day = datetime.fromisoformat(created_at.replace("Z", "+00:00")).date()
            if created_day.isoformat() in trend_counts:
                trend_counts[created_day.isoformat()] += 1
    trend = [
        {"date": day.strftime("%b %d"), "count": trend_counts[day.isoformat()]}
        for day in trend_dates
    ]
    max_trend = max((item["count"] for item in trend), default=0) or 1
    for item in trend:
        item["width"] = round(item["count"] * 100 / max_trend)
    severity_counts = [
        {
            "name": level,
            "count": sum(x["severity"] == level for x in incidents),
        }
        for level in SEVERITIES
    ]
    max_severity = max((item["count"] for item in severity_counts), default=0) or 1
    for item in severity_counts:
        item["width"] = round(item["count"] * 100 / max_severity)
    return render_template(
        "index.html",
        incidents=incidents,
        counts=counts,
        trend=trend,
        severity_counts=severity_counts,
        insight_cards=insight_cards,
        search=filters["search"],
        selected_severity=filters["severity"],
        selected_status=filters["status"],
        selected_period=filters["period"],
        selected_risk_min=filters["risk_min"],
        selected_sort=filters["sort"],
        periods=PERIODS,
        statuses=STATUSES,
    )

@app.route("/export/incidents.<format>")
def export_incidents(format):
    if format not in {"csv", "json"}:
        return jsonify(error="Choose CSV or JSON export."), 404
    filters = _incident_filters()
    incidents = list_incidents(
        search=filters["search"],
        severity=filters["severity"],
        status=filters["status"],
        days=filters["days"],
        risk_min=filters["risk_min"],
        sort=filters["sort"],
    )
    fields = (
        "id", "filename", "severity", "risk_score", "attack_type", "source_ip",
        "affected_user", "status", "assigned_to", "summary", "created_at", "updated_at",
    )
    if format == "json":
        payload = json.dumps(incidents, indent=2).encode("utf-8")
        database.record_audit_event(
            g.current_user["id"],
            "incident.exported",
            "incident_queue",
            details={"format": "json", "count": len(incidents)},
        )
        return send_file(
            io.BytesIO(payload),
            mimetype="application/json",
            as_attachment=True,
            download_name="incidents.json",
        )

    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(fields)
    for incident in incidents:
        values = []
        for field in fields:
            value = incident.get(field, "")
            if isinstance(value, str) and value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
                value = "'" + value
            values.append(value)
        writer.writerow(values)
    database.record_audit_event(
        g.current_user["id"],
        "incident.exported",
        "incident_queue",
        details={"format": "csv", "count": len(incidents)},
    )
    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8-sig")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="incidents.csv",
    )

@app.route("/api/health")
def health():
    return jsonify(status="ok", analysis="deterministic-rules")

@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("logfile")
    if not f or not f.filename:
        return jsonify(error="Select a log file."), 400
    content = f.read(app.config["MAX_CONTENT_LENGTH"] + 1)
    if len(content) > app.config["MAX_CONTENT_LENGTH"]:
        return jsonify(error="Log file is too large (maximum 3 MB)."), 413
    text = content.decode("utf-8", errors="replace")
    if not text.strip():
        return jsonify(error="The selected log file is empty."), 400
    filename = secure_filename(f.filename) or "uploaded-log.txt"
    incident = analyze_text(text, filename, actor_user_id=g.current_user["id"])
    incident["assessment"] = build_assessment(incident)
    return jsonify(incident)

@app.errorhandler(413)
def request_entity_too_large(_error):
    return jsonify(error="Request is too large (maximum log file size is 3 MB)."), 413

@app.route("/incident/<int:i>")
def incident(i):
    x = get_incident(i)
    if not x:
        return "Incident not found", 404
    return render_template("incident.html", incident=x)

@app.route("/api/chat", methods=["POST"])
def chat():
    d = request.get_json(silent=True) or {}
    if not isinstance(d, dict):
        return jsonify(error="Request body must be a JSON object."), 400
    try:
        incident_id = int(d.get("incident_id", 0))
    except (TypeError, ValueError):
        return jsonify(error="A valid incident ID is required."), 400
    x = get_incident(incident_id)
    q = d.get("question", "")
    if not isinstance(q, str):
        return jsonify(error="Question must be text."), 400
    q = q.strip()
    if not x or not q:
        return jsonify(error="Incident and question are required."), 400
    if len(q) > 2000:
        return jsonify(error="Question is too long (maximum 2,000 characters)."), 400
    return jsonify(answer_question(x, q))

@app.route("/api/incidents/<int:i>/workflow", methods=["POST"])
def update_incident_workflow(i):
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify(error="Request body must be a JSON object."), 400
    status = data.get("status", "")
    assigned_to = data.get("assigned_to", "")
    note = data.get("note", "")
    if status not in STATUSES:
        return jsonify(error="Select a valid incident status."), 400
    if not isinstance(assigned_to, str) or len(assigned_to) > 100:
        return jsonify(error="Assignee must be text up to 100 characters."), 400
    if not isinstance(note, str) or len(note) > 2000:
        return jsonify(error="Note must be text up to 2,000 characters."), 400
    if not update_workflow(
        i, status, assigned_to.strip(), note.strip(), actor_user_id=g.current_user["id"]
    ):
        return jsonify(error="Incident not found."), 404
    return jsonify(status="updated")

@app.route("/api/incidents/bulk-workflow", methods=["POST"])
def update_bulk_incident_workflow():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Request body must be a JSON object."), 400
    ids = data.get("incident_ids")
    if (
        not isinstance(ids, list)
        or not 1 <= len(ids) <= 100
        or any(type(i) is not int or i <= 0 for i in ids)
        or len(set(ids)) != len(ids)
    ):
        return jsonify(error="Select between 1 and 100 unique incident IDs."), 400
    status = data.get("status", "")
    assigned_to = data.get("assigned_to", "")
    note = data.get("note", "")
    if status not in STATUSES:
        return jsonify(error="Select a valid incident status."), 400
    if not isinstance(assigned_to, str) or len(assigned_to) > 100:
        return jsonify(error="Assignee must be text up to 100 characters."), 400
    if not isinstance(note, str) or len(note) > 2000:
        return jsonify(error="Note must be text up to 2,000 characters."), 400
    if not update_workflow_bulk(
        ids,
        status,
        assigned_to.strip(),
        note.strip(),
        actor_user_id=g.current_user["id"],
    ):
        return jsonify(error="One or more incidents were not found; no cases were updated."), 404
    return jsonify(status="updated", updated=len(ids))

@app.route("/report/<int:i>")
def report(i):
    x = get_incident(i)
    if not x:
        return "Incident not found", 404
    path = build_report(x)
    database.record_audit_event(
        g.current_user["id"],
        "incident.report_downloaded",
        "incident",
        i,
    )
    return send_file(path, as_attachment=True, download_name=f"incident_{i}_report.txt")

if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)
