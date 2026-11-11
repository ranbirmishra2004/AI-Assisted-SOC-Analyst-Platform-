import ipaddress
import json
import re
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlsplit

from assessment import build_assessment
from database import insert, get

IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
HASH_RE = re.compile(r'\b[a-fA-F0-9]{32,64}\b')
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
USER_RE = re.compile(r'\b(?:for|user(?:name)?)\s*[=:]?\s*([A-Za-z0-9._@\\-]+)', re.I)
FAILED_RE = re.compile(
    r'failed|failure|invalid password|authentication failure|logon failure|4625',
    re.I
)
SUCCESS_RE = re.compile(
    r'accepted|successful|login success|logged in|logon success|4624',
    re.I
)
SUSPICIOUS_PATTERNS = (
    ("Suspicious PowerShell Activity",
     re.compile(r'-enc(?:odedcommand)?\b|frombase64string|downloadstring|invoke-expression', re.I)),
    ("Potential Ransomware Activity",
     re.compile(r'vssadmin.{0,80}delete shadows|wbadmin.{0,80}delete|encrypt(?:ed|ion)?\s+files?', re.I)),
    ("Potential Malware Activity",
     re.compile(r'\b(?:mimikatz|meterpreter|cobalt strike)\b', re.I)),
    ("Remote Administration / Lateral Movement",
     re.compile(r'\b(?:wmic|psexec|schtasks|at\.exe|rundll32|winrm|rdp)\b', re.I)),
)
SPRAY_WINDOW_SECONDS = 10 * 60
TIMESTAMP_KEYS = {"@timestamp", "timestamp", "time", "event_time", "datetime"}
IP_KEYS = {"src_ip", "source_ip", "client_ip", "remote_ip", "ip_address", "ip"}
USER_KEYS = {"user", "username", "user_name", "user.name", "account", "target_user"}

def _normalized_timestamp(value):
    if not isinstance(value, str) or not value.strip():
        return ""
    candidate = value.strip()
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")

def _structured_value(record, accepted_keys):
    pending = [(record, "")]
    while pending:
        current, prefix = pending.pop()
        for key, value in current.items():
            path = f"{prefix}.{key}" if prefix else key
            normalized_key = path.lower()
            suffix = normalized_key.rsplit(".", 1)[-1]
            if (
                (normalized_key in accepted_keys or suffix in accepted_keys)
                and isinstance(value, (str, int))
            ):
                return str(value)
            if isinstance(value, dict):
                pending.append((value, path))
    return ""

def _event_type(message):
    if FAILED_RE.search(message):
        return "authentication_failure"
    if SUCCESS_RE.search(message):
        return "authentication_success"
    if re.search(r'process|powershell|command line', message, re.I):
        return "process_activity"
    return "other"

def parse(text):
    events = []
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        record = {}
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                record = parsed
        except json.JSONDecodeError:
            pass

        message = _structured_value(record, {"message", "msg", "event.original"})
        if not message:
            message = raw
        event_code = _structured_value(record, {"event_id", "eventid", "event.code", "code"})
        action = _structured_value(record, {"action", "event.action", "event_type", "type"})
        classification_text = " ".join((message, event_code, action))

        ips = []
        for candidate in IP_RE.findall(raw):
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            ips.append(candidate)
        structured_ip = _structured_value(record, IP_KEYS)
        if structured_ip:
            try:
                ips.insert(0, str(ipaddress.ip_address(structured_ip)))
            except ValueError:
                pass

        username = _structured_value(record, USER_KEYS)
        um = USER_RE.search(message)
        if not username and um:
            username = um.group(1)

        msg = re.sub(r'^\S+\s+\S+\s+\S+\s*:\s*', '', message)
        timestamp = ""
        timestamp = _normalized_timestamp(
            _structured_value(record, TIMESTAMP_KEYS)
        )
        if not timestamp:
            prefix = re.match(
                r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)",
                raw,
            )
            if prefix:
                timestamp = _normalized_timestamp(prefix.group(1))

        events.append({
            "raw": raw,
            "msg": msg,
            "ip": ips[0] if ips else "",
            "user": username,
            "timestamp": timestamp,
            "event_type": _event_type(classification_text),
        })
    return events

def _password_spray_matches(failed_events):
    failed_by_ip = {}
    for event in failed_events:
        if event["ip"]:
            failed_by_ip.setdefault(event["ip"], []).append(event)

    matches = []
    for ip_events in failed_by_ip.values():
        timed_events = [event for event in ip_events if event["timestamp"]]
        candidates = timed_events if timed_events else ip_events
        candidates.sort(key=lambda event: event["timestamp"])
        start = 0
        for end, event in enumerate(candidates):
            if event["timestamp"]:
                event_time = datetime.fromisoformat(event["timestamp"])
                while start < end:
                    start_time = datetime.fromisoformat(candidates[start]["timestamp"])
                    if (event_time - start_time).total_seconds() <= SPRAY_WINDOW_SECONDS:
                        break
                    start += 1
            window = candidates[start : end + 1]
            users = {item["user"].casefold() for item in window if item["user"]}
            if len(window) >= 5 and len(users) >= 3:
                matches.extend(window)
                break
    return matches

def analyze_text(text, filename, actor_user_id=None):
    events = parse(text)
    failed = [e for e in events if e["event_type"] == "authentication_failure"]
    success = [e for e in events if e["event_type"] == "authentication_success"]
    suspicious_rules = [
        (name, pattern, [e for e in events if pattern.search(e["msg"])])
        for name, pattern in SUSPICIOUS_PATTERNS
    ]
    suspicious_rules = [rule for rule in suspicious_rules if rule[2]]

    spray_matches = _password_spray_matches(failed)
    if spray_matches:
        timed_matches = [event for event in spray_matches if event["timestamp"]]
        if timed_matches:
            first_seen = min(event["timestamp"] for event in timed_matches)
            last_seen = max(event["timestamp"] for event in timed_matches)
            evidence_text = (
                f"Password spraying correlated across {len({item['user'].casefold() for item in spray_matches if item['user']})} "
                f"accounts within {SPRAY_WINDOW_SECONDS // 60} minutes "
                f"({first_seen} to {last_seen})"
            )
        else:
            evidence_text = (
                f"Password spraying matched {len(spray_matches)} events across "
                f"{len({item['user'].casefold() for item in spray_matches if item['user']})} accounts "
                "(source logs did not contain usable timestamps)"
            )
        suspicious_rules.insert(
            0,
            ("Password Spraying / Account Enumeration",
             re.compile(r'password spraying|account enumeration|failed password', re.I),
             spray_matches),
        )

    ips = [e["ip"] for e in events if e["ip"]]
    users = [e["user"] for e in events if e["user"]]
    urls = set()
    for event in events:
        for match in URL_RE.findall(event["raw"]):
            candidate = match.rstrip(".,;:!?)]}")
            try:
                if urlsplit(candidate).hostname:
                    urls.add(candidate)
            except ValueError:
                continue

    ip = Counter(ips).most_common(1)[0][0] if ips else "Unknown"
    user = Counter(users).most_common(1)[0][0] if users else "Unknown"

    risk_score = min(
        100,
        (60 if len(failed) >= 5 else 20 if len(failed) >= 3 else 0)
        + (25 if failed and success else 0)
        + sum(60 if name == "Potential Ransomware Activity" else 35
              for name, _, _ in suspicious_rules)
        + (20 if any(name == "Password Spraying / Account Enumeration" for name, _, _ in suspicious_rules) else 0)
    )
    if risk_score >= 80:
        severity = "Critical"
    elif risk_score >= 55:
        severity = "High"
    elif risk_score >= 30:
        severity = "Medium"
    elif success:
        severity = "Low"
    else:
        severity = "Info"

    if suspicious_rules:
        attack = suspicious_rules[0][0]
    elif len(failed) >= 5:
        attack = "Brute Force / Credential Attack"
    elif len(failed) >= 3:
        attack = "Suspicious Authentication Activity"
    elif success:
        attack = "Successful Authentication Event"
    else:
        attack = "No Known Attack Pattern"

    tags = [name for name, _, _ in suspicious_rules]
    if len(failed) >= 3:
        tags.append("Repeated Authentication Failures")
    if failed and success:
        tags.append("Success After Authentication Failures")
    if any(name == "Password Spraying / Account Enumeration" for name in tags):
        tags.append("Credential stuffing pattern")
    if not tags and not success:
        tags.append("Needs Analyst Review")

    evidence = []
    for name, _, matches in suspicious_rules:
        if name == "Password Spraying / Account Enumeration":
            evidence.append(evidence_text)
        else:
            evidence.append(f"{name}: {len(matches)} matching event(s)")
    if failed:
        evidence.append(f"{len(failed)} authentication failure event(s)")
    if success:
        evidence.append(f"{len(success)} authentication success event(s)")

    item = {
        "filename": filename,
        "events": events,
        "severity": severity,
        "attack_type": attack,
        "source_ip": ip,
        "affected_user": user,
        "summary": f"{len(failed)} failed and {len(success)} successful authentication events were observed.",
        "iocs": {
            "ips": sorted(set(ips)),
            "hashes": sorted(set(h for e in events for h in HASH_RE.findall(e["raw"]))),
            "urls": sorted(urls),
        },
        "risk_score": risk_score,
        "alert_tags": tags,
        "detection_evidence": evidence,
    }
    return insert(item, actor_user_id=actor_user_id)

def get_incident(i):
    incident = get(i)
    if incident:
        incident["assessment"] = build_assessment(incident)
    return incident

def list_incidents():
    return all()
