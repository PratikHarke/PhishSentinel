import email, hashlib, mailbox, pathlib, random, re
from email import policy
from email.utils import parsedate_to_datetime
import pandas as pd

MAX_PER_MBOX = 100          # sample per monthly Apache mbox file (seeded, reproducible)
MAX_PER_GMAIL_LABEL = 3000  # sample per Gmail label file

# (path, source_name, label, kind)
SOURCES = [
    ("data/raw/phishing_pot/email", "phishing_pot", 1, "eml"),
]
for f in sorted(pathlib.Path("data/raw/legit_apache").glob("*/*.mbox")):
    SOURCES.append((str(f), "apache_" + f.parent.name, 0, "mbox"))

# Gmail Takeout label files. Spam/Trash/Sent/Drafts are never legitimate-class material.
SKIP_LABELS = ("spam", "trash", "sent", "draft")
for f in sorted(pathlib.Path("data/raw/legit_gmail").rglob("*.mbox")):
    if any(w in f.stem.lower() for w in SKIP_LABELS):
        continue
    SOURCES.append((str(f), "gmail_" + f.stem.replace(" ", "_").lower(), 0, "mbox_big"))

START = pd.Timestamp("2022-01-01", tz="UTC")

# Collapse vendor-specific verdict strings into a small shared vocabulary so values
# can't reveal which mail stack collected the email.
AUTH_NORM = {
    "pass": "pass", "fail": "fail", "softfail": "fail",
    "permerror": "error", "temperror": "error", "error": "error", "timeout": "error",
    "bestguesspass": "none", "none": "none", "neutral": "none",
    "ignore": "none", "test": "none", "policy": "none",
}

def _to_utc(s):
    try:
        return pd.to_datetime(parsedate_to_datetime(s.strip()), utc=True)
    except Exception:
        return pd.NaT

def arrival_time(msg):
    """Receiving server's timestamp (top Received header); Date header only as a fallback."""
    rec = msg.get_all("Received", [])
    if rec:
        t = _to_utc(str(rec[0]).rsplit(";", 1)[-1])
        if pd.notna(t):
            return t, 0
    return _to_utc(str(msg["Date"] or "")), 1

def auth_verdicts(ar):
    ar = (ar or "").lower()
    out = {}
    for k in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{k}=(\w+)", ar)
        out[f"a_{k}"] = AUTH_NORM.get(m.group(1), "none") if m else "absent"
    return out

def spf_domain(ar):
    m = re.search(r"smtp\.mailfrom=([^;\s]+)", (ar or "").lower())
    return m.group(1).split("@")[-1].strip("<>") if m else ""

def dkim_domain(msg):
    m = re.search(r"\bd=([^;\s]+)", str(msg["DKIM-Signature"] or ""))
    return m.group(1).lower() if m else ""

def bodies(msg):
    text, html, n_att = [], [], 0
    for part in msg.walk():
        if part.is_multipart():
            continue
        if part.get_content_disposition() == "attachment":
            n_att += 1
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            payload = part.get_content()
        except Exception:
            payload = (part.get_payload(decode=True) or b"").decode("utf-8", errors="replace")
        (text if ctype == "text/plain" else html).append(payload)
    return "\n".join(text), "\n".join(html), n_att

def to_row(msg, rid, source, label):
    text, html, n_att = bodies(msg)
    ar = str(msg["Authentication-Results"] or "")
    arrival, from_date = arrival_time(msg)
    return {
        "id": rid, "source": source, "label": label,
        "arrival": arrival,
        "sender": str(msg["From"] or ""), "reply_to": str(msg["Reply-To"] or ""),
        "return_path": str(msg["Return-Path"] or ""), "subject": str(msg["Subject"] or ""),
        **auth_verdicts(ar),
        "spf_domain": spf_domain(ar),
        "dkim_d": dkim_domain(msg), "n_attachments": n_att,
        "text": text, "html": html,
        # audit-only columns: used in the leakage check, never as model features
        "audit_n_received": len(msg.get_all("Received", [])),
        "audit_has_list_id": int(msg["List-Id"] is not None),
        "audit_arrival_from_date": from_date,
    }

def parse_bytes(raw, rid, source, label, errors):
    """Modern parser first; lenient legacy parser for malformed headers."""
    err = None
    for pol in (policy.default, policy.compat32):
        try:
            return to_row(email.message_from_bytes(raw, policy=pol), rid, source, label)
        except Exception as e:
            err = e
    errors.append(f"{rid}\t{err!r}")
    return None

def load_eml_dir(path, source, label, errors):
    rows = []
    for p in sorted(pathlib.Path(path).rglob("*.eml")):
        row = parse_bytes(p.read_bytes(), f"{source}:{p.name}", source, label, errors)
        if row:
            rows.append(row)
    return rows

def load_mbox(path, source, label, errors, cap=MAX_PER_MBOX):
    rows = []
    box = mailbox.mbox(path)
    keys = list(box.keys())
    if cap and len(keys) > cap:
        keys = sorted(random.Random(0).sample(keys, cap))
    stem = pathlib.Path(path).stem
    for key in keys:
        row = parse_bytes(box.get_bytes(key), f"{source}:{stem}:{key}", source, label, errors)
        if row:
            rows.append(row)
    return rows

LOADERS = {
    "eml": load_eml_dir,
    "mbox": load_mbox,
    "mbox_big": lambda p, s, l, e: load_mbox(p, s, l, e, cap=MAX_PER_GMAIL_LABEL),
}

def main():
    rows, errors, counts = [], [], {}
    for path, source, label, kind in SOURCES:
        got = LOADERS[kind](path, source, label, errors)
        counts[source] = counts.get(source, 0) + len(got)
        rows += got
    for s, n in counts.items():
        print(f"{s}: {n} parsed")
    df = pd.DataFrame(rows)

    n0 = len(df)
    df = df[df.arrival.notna() & (df.arrival >= START) & (df.arrival <= pd.Timestamp.now(tz="UTC"))]
    print(f"dropped {n0 - len(df)} with missing/out-of-range arrival time")

    body = df.text.where(df.text.str.strip() != "", df.html)
    df["body_hash"] = [hashlib.sha1(f"{s}|{b}".encode("utf-8", "ignore")).hexdigest()
                       for s, b in zip(df.subject, body)]
    n1 = len(df)
    df = df.sort_values("arrival").drop_duplicates("body_hash", keep="first")
    print(f"dropped {n1 - len(df)} exact duplicates")

    pathlib.Path("data/processed").mkdir(parents=True, exist_ok=True)
    df.reset_index(drop=True).to_parquet("data/processed/emails.parquet")
    pathlib.Path("data/processed/parse_errors.tsv").write_text("\n".join(errors), encoding="utf-8")
    print(f"saved {len(df)} rows; {len(errors)} parse errors logged")
    print(df.groupby("label").size().to_string())

if __name__ == "__main__":
    main()