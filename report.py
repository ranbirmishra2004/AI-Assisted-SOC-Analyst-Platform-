import json
import os

def build_report(x):
    os.makedirs("reports", exist_ok=True)
    a = x.get("assessment", {})
    risk_score = f"{x['risk_score']}/100" if x.get("risk_score", -1) >= 0 else "Not scored"
    content = f"""    SOC INCIDENT REPORT
========================
Incident ID: {x['id']}
File: {x['filename']}
Severity: {x['severity']}
Rule Risk Score: {risk_score}
Case Status: {x.get('status', 'New')}
Assigned To: {x.get('assigned_to') or 'Unassigned'}
Attack Type: {x['attack_type']}
Source IP: {x['source_ip']}
Affected User: {x['affected_user']}
Alert Tags: {', '.join(x.get('alert_tags', []))}

RULE-BASED ASSESSMENT
{a.get('executive_summary', 'No assessment available.')}
Analysis Source: {a.get('analysis_source', 'Not analyzed')}
Analysis Notice: {a.get('analysis_notice') or 'None'}
Analyst Notes: {a.get('analyst_notes', '')}

MITRE ATT&CK
{a.get('mitre_attack', 'Requires analyst validation')}

DETECTION EVIDENCE
{chr(10).join('- ' + item for item in x.get('detection_evidence', []))}

IOCs
{json.dumps(x.get('iocs', {}), indent=2)}

WHY SUSPICIOUS
{chr(10).join('- ' + s for s in a.get('why_suspicious', []))}

RECOMMENDED ACTIONS
{chr(10).join('- ' + s for s in a.get('recommended_actions', []))}

INVESTIGATION NOTES
{chr(10).join(f"- {note['created_at']}: {note['text']}" for note in x.get('notes', []))}

RAW EVENTS
{chr(10).join(e['raw'] for e in x['events'])}

Rule-based results are advisory. Verify evidence and follow incident-response procedures.
"""
    path = f"reports/incident_{x['id']}_report.txt"
    with open(path, "w", encoding="utf8") as f:
        f.write(content)
    return path
