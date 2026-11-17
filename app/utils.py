import csv
import ipaddress
import re
from datetime import datetime, timezone
from werkzeug.utils import secure_filename

from app.models import LogEntry


ALLOWED_LOG_EXTENSIONS = {"log", "txt", "csv"}
MAX_LOG_UPLOAD_BYTES = 5 * 1024 * 1024
IP_PATTERN = re.compile(
    r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|"
    r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])"
)
TIMESTAMP_PATTERNS = (
    "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f", "%d/%b/%Y:%H:%M:%S %z",
    "%b %d %H:%M:%S",
)


def allowed_log_filename(filename):
    safe_name = secure_filename(filename or "")
    return bool(safe_name and "." in safe_name and
                safe_name.rsplit(".", 1)[1].lower() in ALLOWED_LOG_EXTENSIONS)


def _parse_timestamp(line):
    # Prefer an ISO-like timestamp, then common web/syslog formats.
    candidates = re.findall(
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|"
        r"\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}|"
        r"[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
        line
    )
    for candidate in candidates:
        value = candidate.replace("Z", "+0000")
        for fmt in TIMESTAMP_PATTERNS:
            try:
                parsed = datetime.strptime(value, fmt)
                if parsed.tzinfo:
                    parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
                elif fmt == "%b %d %H:%M:%S":
                    parsed = parsed.replace(year=datetime.utcnow().year)
                return parsed
            except ValueError:
                continue
    return None


def _valid_ips(line):
    found = []
    for value in IP_PATTERN.findall(line):
        try:
            normalized = str(ipaddress.ip_address(value))
            if normalized not in found:
                found.append(normalized)
        except ValueError:
            continue
    return found


def _labelled_ip(line, labels):
    label_pattern = r"(?:%s)\s*[=:]\s*\[?([0-9a-fA-F:.]+)" % "|".join(labels)
    match = re.search(label_pattern, line, re.IGNORECASE)
    if match:
        try:
            return str(ipaddress.ip_address(match.group(1)))
        except ValueError:
            pass
    return None


def _event_type(line):
    match = re.search(r"\b(?:event|event_type|action|method)\s*[=:]\s*[\"']?([A-Za-z0-9_.-]+)", line, re.I)
    if match:
        return match.group(1).upper()[:100]
    upper = line.upper()
    for keyword in ("LOGIN", "LOGOUT", "FAILED", "DENIED", "BLOCK", "ALLOW",
                    "ERROR", "ALERT", "SCAN", "POST", "PUT", "DELETE", "GET"):
        if re.search(r"\b" + keyword + r"\b", upper):
            return keyword
    return "UNKNOWN"


def parse_log_text(text, incident_id):
    """Parse sample log text into LogEntry instances; return (saved, skipped)."""
    entries = []
    skipped = 0
    csv_columns = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Support ordinary comma-separated exports with a header row as well
        # as free-form text logs. Header values are used only for parsing.
        parse_line = line
        if "," in line:
            try:
                fields = next(csv.reader([line]))
            except (csv.Error, StopIteration):
                fields = []
            lowered = [field.strip().lower() for field in fields]
            if csv_columns is None and any(name in lowered for name in
                                           ("timestamp", "time", "datetime")):
                csv_columns = {name: index for index, name in enumerate(lowered)}
                continue
            if csv_columns:
                def column(*names):
                    index = next((csv_columns[name] for name in names
                                  if name in csv_columns), None)
                    return fields[index].strip() if index is not None and index < len(fields) else ""
                csv_timestamp = column("timestamp", "datetime", "time")
                csv_source = column("source_ip", "src_ip", "src", "source", "client_ip")
                csv_destination = column("destination_ip", "dst_ip", "dst", "destination", "server_ip")
                csv_event = column("event_type", "event", "action", "method")
                parse_line = (f"timestamp={csv_timestamp} src={csv_source} "
                              f"dst={csv_destination} event={csv_event}")

        timestamp = _parse_timestamp(parse_line)
        ips = _valid_ips(parse_line)
        if timestamp is None or not ips:
            skipped += 1
            continue

        source = _labelled_ip(parse_line, ("src", "source", "source_ip", "client_ip", "client"))
        destination = _labelled_ip(parse_line, ("dst", "dest", "destination", "destination_ip", "server_ip"))
        source = source or ips[0]
        if destination is None:
            destination = next((ip for ip in ips if ip != source), "Unknown")

        entries.append(LogEntry(
            timestamp=timestamp,
            source_ip=source,
            destination_ip=destination,
            event_type=_event_type(parse_line),
            raw_log=raw_line[:10000],
            incident_id=incident_id,
        ))
    return entries, skipped


def investigate_ip(entries, ip_address):
    """Build a local, simulated activity profile from incident log entries."""
    matching = [entry for entry in entries
                if entry.source_ip == ip_address or entry.destination_ip == ip_address]
    event_counts = {}
    for entry in matching:
        event_counts[entry.event_type] = event_counts.get(entry.event_type, 0) + 1

    try:
        parsed_ip = ipaddress.ip_address(ip_address)
        if parsed_ip.is_private or parsed_ip.is_loopback or parsed_ip.is_reserved:
            risk = "Low"
            location = "Private / reserved network (simulated)"
        else:
            # Deterministic training-only score; not a real threat-intelligence result.
            score = sum(parsed_ip.packed) % 100
            risk = "High" if score >= 75 else "Medium" if score >= 40 else "Low"
            location = "Simulated region lookup — not verified"
    except ValueError:
        return None

    timestamps = [entry.timestamp for entry in matching]
    return {
        "ip": ip_address,
        "request_count": len(matching),
        "event_counts": sorted(event_counts.items()),
        "first_seen": min(timestamps) if timestamps else None,
        "last_seen": max(timestamps) if timestamps else None,
        "risk": risk,
        "location": location,
    }
