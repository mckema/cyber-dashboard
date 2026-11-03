"""
Small on-disk state under STATE_DIR (default ./state).

  http/                 conditional-GET cache (ETag + body), owned by common.get()
  items/<module>.json   items from the last successful fetch, per feed module
  cursors/<module>.json free-form per-module cursor (e.g. cvelistV5 deltaLog fetchTime)
  seen.json             item key -> first_seen (UTC ISO); basis of the 1-hour SLA measurement
  runs.jsonl            one line per run: counts, errors, SLA lag

Writes are atomic (temp file + rename) so a killed run never leaves half a file.
"""

import json
import os
from datetime import datetime, timedelta, timezone

STATE_DIR = os.environ.get("STATE_DIR", "state")


def _path(name):
    p = os.path.join(STATE_DIR, name)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    return p


def _atomic_write(p, data, mode):
    tmp = p + ".tmp"
    with open(tmp, mode) as f:
        f.write(data)
    os.replace(tmp, p)


def load_json(name, default):
    p = os.path.join(STATE_DIR, name)
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(name, obj):
    _atomic_write(_path(name), json.dumps(obj, ensure_ascii=False, indent=1), "w")


def load_bytes(name):
    try:
        with open(os.path.join(STATE_DIR, name), "rb") as f:
            return f.read()
    except FileNotFoundError:
        return None


def save_bytes(name, data):
    _atomic_write(_path(name), data, "wb")


def mark_seen(keys, now, keep_days=30):
    """Record first_seen for keys not seen before. Returns {key: first_seen} for the new ones."""
    seen = load_json("seen.json", {})
    stamp = now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    new = {k: stamp for k in keys if k not in seen}
    seen.update(new)
    cutoff = (now - timedelta(days=keep_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    seen = {k: v for k, v in seen.items() if v >= cutoff}
    save_json("seen.json", seen)
    return new


def first_seen(key):
    return load_json("seen.json", {}).get(key)


def append_run(record):
    with open(_path("runs.jsonl"), "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def utcnow():
    return datetime.now(timezone.utc)
