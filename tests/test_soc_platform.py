import csv
from io import BytesIO, StringIO
import json
import os
import sqlite3
import tempfile
import unittest

import app as web_app
import analyzer
import assessment
import database


class SOCPlatformTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database.DB = os.path.join(self.temp_dir.name, "test.db")
        database.init()
        web_app.app.config.update(TESTING=True)
        self.client = web_app.app.test_client()
        self.user_id = database.create_user(
            "test-analyst", "test-password-long", "analyst"
        )
        self.csrf_token = "test-csrf-token"
        with self.client.session_transaction() as browser_session:
            browser_session["user_id"] = self.user_id
            browser_session["csrf_token"] = self.csrf_token
        self.client.environ_base["HTTP_X_CSRF_TOKEN"] = self.csrf_token

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_brute_force_followed_by_success_is_critical(self):
        failures = [
            f"2025-01-01 10:00:0{i} sshd: Failed password for admin from 192.0.2.10 port 22"
            for i in range(5)
        ]
        failures.append(
            "2025-01-01 10:01:00 sshd: Accepted password for admin from 192.0.2.10 port 22"
        )

        incident = analyzer.analyze_text("\n".join(failures), "auth.log")

        self.assertEqual(incident["severity"], "Critical")
        self.assertEqual(incident["risk_score"], 85)
        self.assertEqual(incident["source_ip"], "192.0.2.10")
        self.assertEqual(incident["affected_user"], "admin")
        self.assertIn("Success After Authentication Failures", incident["alert_tags"])
        self.assertEqual(
            database.get(incident["id"])["iocs"]["ips"], ["192.0.2.10"]
        )

    def test_suspicious_powershell_generates_detection_signal(self):
        incident = analyzer.analyze_text(
            "powershell.exe -EncodedCommand dGVzdA==", "process.log"
        )

        self.assertEqual(incident["attack_type"], "Suspicious PowerShell Activity")
        self.assertEqual(incident["severity"], "Medium")
        self.assertEqual(incident["risk_score"], 35)

    def test_invalid_ip_is_not_recorded_as_indicator(self):
        incident = analyzer.analyze_text(
            "2025-01-01 10:00:00 sshd: Failed password for admin from 999.999.999.999",
            "auth.log",
        )

        self.assertEqual(incident["source_ip"], "Unknown")
        self.assertEqual(incident["iocs"]["ips"], [])

    def test_http_urls_are_extracted_as_indicators(self):
        incident = analyzer.analyze_text(
            "process started curl https://example.test/payload.exe, then exited",
            "process.log",
        )

        self.assertEqual(
            incident["iocs"]["urls"], ["https://example.test/payload.exe"]
        )

    def test_json_security_events_are_normalized(self):
        record = {
            "@timestamp": "2026-05-01T10:00:00Z",
            "event": {"code": 4625, "original": "Authentication failure"},
            "source": {"ip": "2001:db8::8"},
            "user": {"name": "analyst-test"},
        }

        event = analyzer.parse(json.dumps(record))[0]

        self.assertEqual(event["event_type"], "authentication_failure")
        self.assertEqual(event["ip"], "2001:db8::8")
        self.assertEqual(event["user"], "analyst-test")
        self.assertEqual(event["timestamp"], "2026-05-01T10:00:00+00:00")

    def test_password_spray_requires_accounts_within_time_window(self):
        close_events = [
            json.dumps(
                {
                    "timestamp": f"2026-05-01T10:00:{second:02d}Z",
                    "event": {"code": 4625},
                    "source": {"ip": "192.0.2.40"},
                    "user": {"name": f"user-{second % 3}"},
                }
            )
            for second in range(5)
        ]
        spread_events = [
            json.dumps(
                {
                    "timestamp": f"2026-05-01T{hour:02d}:00:00Z",
                    "event": {"code": 4625},
                    "source": {"ip": "192.0.2.41"},
                    "user": {"name": f"user-{hour % 3}"},
                }
            )
            for hour in (1, 2, 3, 4, 5)
        ]

        correlated = analyzer.analyze_text("\n".join(close_events), "auth.jsonl")
        separated = analyzer.analyze_text("\n".join(spread_events), "auth.jsonl")

        self.assertEqual(
            correlated["attack_type"], "Password Spraying / Account Enumeration"
        )
        self.assertEqual(
            assessment.build_assessment(correlated)["mitre_attack"],
            "T1110.003 - Password Spraying",
        )
        self.assertTrue(
            any("within 10 minutes" in item for item in correlated["detection_evidence"])
        )
        self.assertNotEqual(
            separated["attack_type"], "Password Spraying / Account Enumeration"
        )

    def test_workflow_updates_status_assignment_and_notes(self):
        incident = analyzer.analyze_text(
            "2025-01-01 10:00:00 sshd: Failed password for admin from 192.0.2.1",
            "auth.log",
        )
        response = self.client.post(
            f"/api/incidents/{incident['id']}/workflow",
            json={
                "status": "Triaging",
                "assigned_to": "SOC Team",
                "note": "Correlating identity logs",
            },
        )

        self.assertEqual(response.status_code, 200)
        updated = database.get(incident["id"])
        self.assertEqual(updated["status"], "Triaging")
        self.assertEqual(updated["assigned_to"], "SOC Team")
        self.assertEqual(updated["notes"][0]["text"], "Correlating identity logs")

    def test_workflow_rejects_invalid_status(self):
        response = self.client.post(
            "/api/incidents/1/workflow",
            json={"status": "Delete Everything", "assigned_to": "", "note": ""},
        )

        self.assertEqual(response.status_code, 400)

    def test_rule_assessment_uses_detection_facts(self):
        incident = {
            "attack_type": "Suspicious Authentication Activity",
            "severity": "Medium",
            "source_ip": "192.0.2.7",
            "affected_user": "admin",
            "summary": "Three failures",
            "events": [],
            "iocs": {"ips": ["192.0.2.7"]},
            "risk_score": 20,
            "detection_evidence": ["3 authentication failure event(s)"],
        }

        result = assessment.build_assessment(incident)

        self.assertEqual(result["severity"], "Medium")
        self.assertEqual(result["attack_type"], "Suspicious Authentication Activity")
        self.assertEqual(result["source_ip"], "192.0.2.7")
        self.assertEqual(result["analysis_source"], "Detection Rules")

    def test_case_question_answers_from_rule_based_evidence(self):
        incident = {
            "id": 1,
            "filename": "auth.log",
            "attack_type": "Suspicious Authentication Activity",
            "severity": "Medium",
            "source_ip": "192.0.2.7",
            "affected_user": "admin",
            "summary": "Three failures",
            "events": [{"raw": "failed login", "event_type": "authentication_failure"}],
            "iocs": {"ips": ["192.0.2.7"]},
            "risk_score": 20,
            "detection_evidence": ["3 authentication failure event(s)"],
        }

        result = assessment.answer_question(incident, "What is the source IP?")

        self.assertEqual(result["source"], "Detection Rules")
        self.assertIn("192.0.2.7", result["answer"])

    def test_upload_returns_rule_assessment_and_sanitized_filename(self):
        log = b"2025-01-01 10:00:00 sshd: Failed password for admin from 192.0.2.7"
        response = self.client.post(
            "/upload",
            data={"logfile": (BytesIO(log), "../../auth.log")},
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 200)
        incident = database.get(response.json["id"])
        self.assertEqual(incident["filename"], "auth.log")
        self.assertEqual(incident["iocs"]["ips"], ["192.0.2.7"])
        self.assertEqual(response.json["assessment"]["analysis_source"], "Detection Rules")

    def test_upload_rejects_empty_file(self):
        response = self.client.post(
            "/upload",
            data={"logfile": (BytesIO(b""), "empty.log")},
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)

    def test_login_requires_csrf_and_authenticates_provisioned_user(self):
        client = web_app.app.test_client()
        login_page = client.get("/login")
        self.assertEqual(login_page.status_code, 200)

        with client.session_transaction() as browser_session:
            csrf_token = browser_session["csrf_token"]
        response = client.post(
            "/login",
            data={
                "username": "test-analyst",
                "password": "test-password-long",
                "csrf_token": csrf_token,
                "next": "/",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/")
        self.assertEqual(client.get("/").status_code, 200)

    def test_authentication_and_role_permissions_are_enforced(self):
        anonymous = web_app.app.test_client()
        self.assertEqual(anonymous.get("/").status_code, 302)
        self.assertEqual(anonymous.get("/api/incidents/1").status_code, 401)

        viewer_id = database.create_user(
            "test-viewer", "viewer-password-long", "viewer"
        )
        viewer = web_app.app.test_client()
        with viewer.session_transaction() as browser_session:
            browser_session["user_id"] = viewer_id
            browser_session["csrf_token"] = "viewer-csrf-token"
        denied = viewer.post(
            "/api/incidents/1/workflow",
            json={"status": "Closed", "assigned_to": "", "note": ""},
            headers={"X-CSRF-Token": "viewer-csrf-token"},
        )

        self.assertEqual(denied.status_code, 403)

    def test_write_requests_require_a_valid_csrf_token(self):
        response = self.client.post(
            "/api/incidents/1/workflow",
            json={"status": "Closed", "assigned_to": "", "note": ""},
            headers={"X-CSRF-Token": "invalid-token"},
        )

        self.assertEqual(response.status_code, 400)

    def test_case_actions_are_actor_linked_in_admin_audit_feed(self):
        incident = analyzer.analyze_text(
            "ordinary system activity", "audit-test.log", actor_user_id=self.user_id
        )
        admin_id = database.create_user(
            "test-admin", "admin-password-long", "admin"
        )
        admin_client = web_app.app.test_client()
        with admin_client.session_transaction() as browser_session:
            browser_session["user_id"] = admin_id
            browser_session["csrf_token"] = "admin-csrf-token"

        self.assertEqual(self.client.get("/admin/audit-events").status_code, 403)
        response = admin_client.get("/admin/audit-events")
        self.assertEqual(response.status_code, 200)
        created = next(
            event
            for event in response.json["events"]
            if event["entity_id"] == str(incident["id"])
        )
        self.assertEqual(created["actor"], "test-analyst")
        self.assertEqual(created["action"], "incident.created")

    def test_login_lockout_after_five_failed_attempts(self):
        database.create_user("locked-user", "locked-password-long", "analyst")
        for _attempt in range(5):
            self.assertIsNone(
                database.authenticate_user("locked-user", "incorrect-password")
            )

        self.assertIsNone(
            database.authenticate_user("locked-user", "locked-password-long")
        )

    def test_existing_database_schema_is_migrated(self):
        legacy_path = os.path.join(self.temp_dir.name, "legacy.db")
        connection = sqlite3.connect(legacy_path)
        connection.execute(
            """CREATE TABLE incidents(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT, severity TEXT, attack_type TEXT,
                source_ip TEXT, affected_user TEXT, summary TEXT,
                events_json TEXT, ai_json TEXT)"""
        )
        connection.execute(
            """INSERT INTO incidents
            (filename,severity,attack_type,source_ip,affected_user,summary,events_json,ai_json)
            VALUES('old.log','Low','Old Event','Unknown','Unknown','old','[]','{}')"""
        )
        connection.commit()
        connection.close()

        database.DB = legacy_path
        database.init()
        incident = database.get(1)

        self.assertEqual(incident["status"], "New")
        self.assertEqual(incident["risk_score"], -1)
        self.assertEqual(incident["notes"], [])
        self.assertTrue(incident["created_at"])

    def test_dashboard_health_and_filters_render(self):
        health = self.client.get("/api/health")
        dashboard = self.client.get("/?severity=Critical&status=New")

        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json["status"], "ok")
        self.assertEqual(health.json["analysis"], "deterministic-rules")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn(b"Incident queue", dashboard.data)

    def test_dashboard_date_and_severity_filters_and_charts(self):
        high_risk = analyzer.analyze_text(
            "\n".join(
                f"2025-01-01 10:00:0{i} sshd: Failed password for admin from 192.0.2.10"
                for i in range(5)
            ),
            "critical.log",
        )
        analyzer.analyze_text("ordinary system activity", "info.log")
        connection = database.con()
        connection.execute(
            "UPDATE incidents SET created_at='2000-01-01 00:00:00' WHERE id=?",
            (high_risk["id"],),
        )
        connection.commit()
        connection.close()

        recent = self.client.get("/?period=7")
        all_high = self.client.get("/?period=all&severity=High")

        self.assertEqual(recent.status_code, 200)
        self.assertNotIn(b"critical.log", recent.data)
        self.assertIn(b"info.log", recent.data)
        self.assertIn(b"critical.log", all_high.data)
        self.assertIn(b"Severity breakdown", all_high.data)

    def test_exports_respect_filters_and_csv_formula_protection(self):
        analyzer.analyze_text("ordinary system activity", "=formula.log")
        analyzer.analyze_text("ordinary system activity", "other.log")

        csv_response = self.client.get("/export/incidents.csv?period=all&q=formula")
        rows = list(csv.reader(StringIO(csv_response.get_data(as_text=True).lstrip("\ufeff"))))
        json_response = self.client.get("/export/incidents.json?period=all&q=formula")

        self.assertEqual(csv_response.status_code, 200)
        self.assertEqual(rows[1][1], "'=formula.log")
        self.assertEqual(json_response.status_code, 200)
        self.assertEqual(len(json_response.json), 1)
        self.assertEqual(json_response.json[0]["filename"], "=formula.log")

    def test_bulk_workflow_updates_selected_cases_and_notes(self):
        first = analyzer.analyze_text("ordinary activity", "first.log")
        second = analyzer.analyze_text("ordinary activity", "second.log")

        response = self.client.post(
            "/api/incidents/bulk-workflow",
            json={
                "incident_ids": [first["id"], second["id"]],
                "status": "Contained",
                "assigned_to": "SOC Team",
                "note": "Grouped for review",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["updated"], 2)
        for incident_id in (first["id"], second["id"]):
            incident = database.get(incident_id)
            self.assertEqual(incident["status"], "Contained")
            self.assertEqual(incident["assigned_to"], "SOC Team")
            self.assertEqual(incident["notes"][0]["text"], "Grouped for review")

    def test_bulk_workflow_rejects_missing_case_without_partial_updates(self):
        incident = analyzer.analyze_text("ordinary activity", "first.log")

        response = self.client.post(
            "/api/incidents/bulk-workflow",
            json={
                "incident_ids": [incident["id"], 999],
                "status": "Closed",
                "assigned_to": "",
                "note": "",
            },
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(database.get(incident["id"])["status"], "New")

    def test_bulk_workflow_validates_selection(self):
        response = self.client.post(
            "/api/incidents/bulk-workflow",
            json={
                "incident_ids": [1, 1],
                "status": "Contained",
                "assigned_to": "",
                "note": "",
            },
        )

        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
