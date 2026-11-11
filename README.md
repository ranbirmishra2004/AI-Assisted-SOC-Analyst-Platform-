# SOC Analyst Platform

A local-first security operations workbench for log triage and incident case tracking. Analysis uses deterministic detection rules; the application does not call Ollama or any hosted AI service.

## Platform capabilities

1. Local ingestion for UTF-8 text and newline-delimited JSON security logs up to 3 MB.
2. Indicator extraction for IP addresses, usernames, file hashes, and URLs.
3. Transparent detections for authentication failures, suspicious commands, and time-windowed password spraying.
4. Risk scoring with a deterministic 0–100 severity model.
5. Structured incident records that preserve evidence, metadata, and timeline details.
6. Case queue search and filtering across date, severity, status, and keyword criteria.
7. Inline status management and bulk workflow updates for multiple selected cases.
8. Assignee tracking and investigation notes to support analyst accountability.
9. CSV/JSON export plus a downloadable report for external sharing and review.
10. Local-first deployment designed for secure data handling without external AI dependencies.
11. Role-based accounts for administrators, analysts, and read-only viewers.
12. CSRF-protected sessions, temporary login lockout, and an actor-linked audit trail.

## What it does

- Accepts UTF-8 text and newline-delimited JSON security logs up to 3 MB.
- Normalizes common JSON event fields, nested user/source fields, event IDs, and ISO timestamps.
- Correlates password-spray signals across source IPs and distinct accounts within a 10-minute window; timestamp-less sources are explicitly marked in evidence.
- Extracts validated IP addresses, usernames, and file hashes.
- Detects repeated authentication failures, suspicious PowerShell, potential ransomware, and known malware-tool strings.
- Assigns a transparent 0-100 rule risk score, severity, evidence, and alert tags.
- Provides a deterministic, rule-based incident assessment and evidence-grounded case Q&A without a model server.
- Exposes a lightweight health endpoint for local and container checks.
- Tracks incident status, assignee, investigation notes, and evidence history in SQLite.
- Filters the incident queue by date range, severity, status, and case details.
- Shows date-range-aware daily incident trends and severity charts.
- Updates one case status inline or applies workflow changes to up to 100 selected cases.
- Exports the filtered incident queue as CSV or JSON.
- Exports a text report with detection evidence, response suggestions, and analyst notes.
- Binds the development server to `127.0.0.1`; uploaded logs remain local.
- Requires provisioned accounts; there is no public registration or default password.
- Supports administrator, analyst, and viewer roles; viewers can inspect but cannot change cases.
- Records login outcomes, case creation/workflow changes, exports, and report downloads.
- Limits an account to five consecutive failed password attempts before a 15-minute lockout.
- Stores password hashes rather than plaintext passwords and uses CSRF-protected form/API writes.

> Detection rules are starter rules, not a production SIEM. Verify findings with original telemetry and your organization's incident-response procedures.

## Windows setup

Open PowerShell in the project folder:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000). No model download, API key, or separate AI service is required.
Create the first local account with `flask --app app create-user --role admin --username <name>`.
The command prompts for a password of at least 12 characters.

## Development checks

The project targets Python 3.10 and newer. Install the editable project with its development tools as shown above, then run:

```powershell
python -m pytest --cov --cov-report=term-missing
ruff check .
```

The GitHub Actions workflow runs the test and lint checks on Linux and Windows, using the minimum and newest supported Python versions.

## Container deployment

Docker Compose runs the production WSGI server as a non-root user, stores the database and reports in persistent volumes, and binds the web interface to localhost. Generate a unique session key and set it in `.env` before starting:

```powershell
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
# Replace SOC_SECRET_KEY in .env with the generated value.
docker compose up --build -d
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000).
Provision an administrator with `docker compose exec web flask --app app create-user --role admin --username <name>`.
Set `SOC_COOKIE_SECURE=1` when serving the application over HTTPS; keep it `0` for the bundled localhost-only HTTP setup.

## Workflow

1. Upload a small text log or newline-delimited JSON log from the dashboard.
2. Review the deterministic detection signals, assessment, and risk score.
3. Assign the case, update its status, and add investigation notes.
4. Update individual or selected case workflows, and export the filtered queue as CSV/JSON.
5. Ask evidence-based questions about the case or download the case report.
6. Sign in with an administrator, analyst, or viewer account; administrators can inspect the audit event feed at `/admin/audit-events`.

## Current scope and next enterprise phases

This is a hardened single-instance SOC workbench, not yet an enterprise SIEM/SOAR. It still uses a local SQLite database and manual file uploads; it has no live event collectors, multi-instance queue, configurable rule lifecycle, threat-intelligence connectors, or response integrations. A production expansion should add these in stages: (1) authenticated access and auditability (implemented), (2) scalable event ingestion and durable processing, (3) versioned/testable detections and correlation, (4) opt-in threat-intelligence enrichment, and (5) human-approved response playbooks with integration-specific access controls. Validate connector vendors, retention requirements, and approval boundaries before enabling external or response integrations.

## Run tests

```powershell
python -m unittest discover -s tests -v
```

Tests use temporary SQLite databases and do not require external services.
