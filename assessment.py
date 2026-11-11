import json


def build_assessment(incident):
    attack = incident["attack_type"]
    severity = incident["severity"]

    if "Brute" in attack:
        mitre = "T1110 - Brute Force"
    elif "Spray" in attack:
        mitre = "T1110.003 - Password Spraying"
    elif "Successful" in attack:
        mitre = "T1078 - Valid Accounts (investigate)"
    else:
        mitre = "Requires analyst validation"

    return {
        "executive_summary": (
            f"The incident is classified as {attack} with {severity} severity. "
            f"Source IP: {incident['source_ip']}; affected user: {incident['affected_user']}."
        ),
        "attack_type": attack,
        "severity": severity,
        "source_ip": incident["source_ip"],
        "affected_user": incident["affected_user"],
        "iocs": incident.get("iocs", {}),
        "mitre_attack": mitre,
        "why_suspicious": incident.get("detection_evidence", [])
        or ["No high-confidence detection rule matched; analyst review is recommended."],
        "timeline": [event["raw"] for event in incident.get("events", [])[:100]],
        "recommended_actions": [
            "Validate the alert against the original log source.",
            "Correlate related identity, endpoint and network events.",
            "Confirm scope and business impact before taking containment action.",
        ],
        "analyst_notes": "Rule-based assessment; validate findings before responding.",
        "analysis_source": "Detection Rules",
    }


def answer_question(incident, question):
    q = question.lower()
    if any(k in q for k in ("source ip", "ip address", "attacker ip", "which ip", "what ip")):
        answer = f"The source IP found in the uploaded evidence is {incident['source_ip']}."
    elif any(k in q for k in ("username", "affected user", "which user", "account")):
        answer = f"The affected account found in the evidence is {incident['affected_user']}."
    elif "ioc" in q or "indicator" in q:
        answer = "IOCs extracted from the evidence: " + json.dumps(incident.get("iocs", {}))
    elif "mitre" in q or "technique" in q:
        answer = build_assessment(incident)["mitre_attack"]
    elif "why" in q or "suspicious" in q:
        answer = " ".join(build_assessment(incident)["why_suspicious"])
    elif any(k in q for k in ("next", "should", "respond", "action")):
        answer = " ".join(build_assessment(incident)["recommended_actions"])
    else:
        answer = build_assessment(incident)["executive_summary"]

    return {
        "answer": answer,
        "source": "Detection Rules",
        "notice": "Answers are generated locally from deterministic rules; validate against original evidence.",
    }
