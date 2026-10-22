#!/usr/bin/env python3
"""Curate a local nuclei-templates checkout down to the platform's read-only
GET detection profile and emit them as the JSON templates the Worker accepts.

This never downloads anything and never runs a scan. It only reads a local
directory (cloned by the CI workflow) and writes filtered JSON templates that
each satisfy the Worker's ValidateTemplate profile: a single GET to a
same-origin path with word/regex/status matchers, no payloads, no fuzzing, no
other protocols. Templates that cannot be represented this way are dropped.
"""
import argparse
import json
import re
import sys
from pathlib import Path

ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,99}$")
PATH_RE = re.compile(r"^\{\{BaseURL\}\}(/[A-Za-z0-9._~%:@!$&'()*+,;=/?-]*)?$")
SEVERITIES = {"info", "low", "medium", "high", "critical"}
MATCH_TYPES = {"word", "regex", "status"}
# Tags that signal active/intrusive behaviour even when the request is a GET.
DENY_TAGS = {
    "fuzz", "fuzzing", "intrusive", "dos", "brute-force", "bruteforce",
    "injection", "sqli", "rce", "lfi", "rfi", "ssrf", "xss", "xxe",
    "deserialization", "oast", "blind", "time-based",
}
MAX_TEMPLATE_BYTES = 64 * 1024


def normalize_id(raw):
    s = re.sub(r"[^a-z0-9_-]", "-", str(raw or "").strip().lower()).strip("-")
    return s[:100]


def _matcher(m):
    """Convert one source matcher to the narrow profile, or return None."""
    if not isinstance(m, dict):
        return None
    mt = m.get("type")
    if mt not in MATCH_TYPES:
        return None
    if m.get("negative"):
        # Dropping a negative matcher would invert the meaning; skip the whole
        # template instead of misrepresenting it.
        return None
    out = {"type": mt}
    cond = m.get("condition", "")
    if cond and cond not in ("and", "or"):
        return None
    part = m.get("part", "")
    if part in ("all", "response"):
        part = "body"
    if part not in ("", "header", "body"):
        return None
    if mt == "status":
        codes = m.get("status")
        if not isinstance(codes, list) or not (1 <= len(codes) <= 10):
            return None
        seen = []
        for c in codes:
            if not isinstance(c, int) or not (100 <= c <= 599) or c in seen:
                return None
            seen.append(c)
        out["status"] = seen
        return out
    values = m.get("words") if mt == "word" else m.get("regex")
    if not isinstance(values, list) or not (1 <= len(values) <= 8):
        return None
    clean = []
    for v in values:
        v = str(v)
        if not v or len(v) > 256 or any(ch in v for ch in "\r\n\x00"):
            return None
        if mt == "regex":
            try:
                re.compile(v)
            except re.error:
                return None
        clean.append(v)
    out["part"] = part or "body"
    out["words" if mt == "word" else "regex"] = clean
    if m.get("case-insensitive"):
        out["case-insensitive"] = True
    return out


def convert(doc):
    """Return a conforming template dict, or None if it cannot be represented
    as one read-only GET with supported matchers."""
    if not isinstance(doc, dict):
        return None
    info = doc.get("info")
    if not isinstance(info, dict):
        return None
    name = str(info.get("name", "")).strip()
    if not name:
        return None
    severity = str(info.get("severity", "info")).strip().lower()
    if severity not in SEVERITIES:
        return None
    tags = info.get("tags")
    tagset = set()
    if isinstance(tags, str):
        tagset = {t.strip().lower() for t in tags.split(",") if t.strip()}
    elif isinstance(tags, list):
        tagset = {str(t).strip().lower() for t in tags}
    if tagset & DENY_TAGS:
        return None
    requests = doc.get("http")
    if requests is None:
        requests = doc.get("requests")
    if not isinstance(requests, list) or len(requests) != 1:
        return None
    req = requests[0]
    if not isinstance(req, dict):
        return None
    # Only a plain matcher-only GET is representable; any other request key
    # (headers, body, payloads, fuzzing, raw, attack, ...) disqualifies it.
    if set(req.keys()) - {"method", "path", "matchers", "matchers-condition"}:
        return None
    if str(req.get("method", "GET")).upper() != "GET":
        return None
    paths = req.get("path")
    if not isinstance(paths, list) or len(paths) != 1:
        return None
    path = str(paths[0]).strip()
    if len(path) > 256 or not PATH_RE.match(path):
        return None
    cond = req.get("matchers-condition", "")
    if cond not in ("", "and", "or"):
        return None
    matchers = req.get("matchers")
    if not isinstance(matchers, list) or not (1 <= len(matchers) <= 8):
        return None
    out_matchers = []
    for m in matchers:
        converted = _matcher(m)
        if converted is None:
            return None
        out_matchers.append(converted)
    tid = normalize_id(doc.get("id"))
    if not ID_RE.match(tid):
        return None
    return {
        "id": tid,
        "info": {
            "name": name[:500],
            "author": "nuclei-templates (curated read-only)",
            "severity": severity,
            "description": "",
            "tags": ",".join(sorted(tagset))[:200] or "detect,read-only",
        },
        "http": [{
            "method": "GET",
            "path": [path],
            "matchers-condition": cond or "or",
            "matchers": out_matchers,
        }],
    }


def main(argv=None):
    import yaml  # imported lazily so unit tests need not install PyYAML
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path, help="nuclei-templates checkout")
    parser.add_argument("--output", required=True, type=Path, help="directory to write curated JSON")
    parser.add_argument("--max", type=int, default=4000, help="maximum templates to emit")
    args = parser.parse_args(argv)
    if not args.source.is_dir():
        parser.error("source must be an existing directory")
    args.output.mkdir(parents=True, exist_ok=True)
    kept, scanned, seen = 0, 0, set()
    for path in sorted(args.source.rglob("*.yaml")):
        if path.is_symlink() or not path.is_file():
            continue
        scanned += 1
        try:
            raw = path.read_bytes()
            if len(raw) > 512 * 1024:
                continue
            doc = yaml.safe_load(raw)
        except Exception:
            continue
        template = convert(doc)
        if template is None:
            continue
        encoded = json.dumps(template, ensure_ascii=False).encode("utf-8")
        if len(encoded) > MAX_TEMPLATE_BYTES:
            continue
        tid = template["id"]
        if tid in seen:
            continue
        seen.add(tid)
        (args.output / (tid + ".json")).write_bytes(encoded)
        kept += 1
        if kept >= args.max:
            break
    print(f"Curated {kept} read-only detection templates from {scanned} scanned (source {args.source}).")
    if kept == 0:
        parser.error("no templates matched the read-only profile; refusing to emit an empty set")


if __name__ == "__main__":
    main()
