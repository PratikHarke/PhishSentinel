import email, hashlib, mailbox, pathlib, re
from email import policy
from email.utils import parsedate_to_datetime
import pandas as pd

# (path, source_name, label, kind). Add legitimate sources here later.
SOURCES = [
    ("data/raw/phishing_pot/email", "phishing_pot", 1, "eml"),
    # ("data/raw/legit_outlook", "own_outlook", 0, "eml"),
    # ("data/raw/lists/example.mbox", "example_list", 0, "mbox"),
]
START = pd.Timestamp("2022-01-01", tz="UTC")

# Collapse vendor-specific verdict strings (e.g. Microsoft's "bestguesspass")
# into a small shared vocabulary so the value can't reveal which mail stack collected the email.
AUTH_NORM = {
    "pass": "pass", "fail": "fail", "softfail": "fail",
    "permerror": "error", "temperror": "error", "error": "error", "timeout": "error",
    "bestguesspass": "none", "none": "none", "neutral": "none",
    "ignore": "none", "test": "none", "policy": "none",
}

def arrival_time(msg):
    """Receiving server's timestamp (top Received header). Date header is sender-controlled."""
    rec = msg.get_all("Received", [])
    if not rec:
        return pd.NaT
    try:
        return pd.to_datetime(parsedate_to_datetime(str(rec[0]).rsplit(";", 1)[-1].strip()), utc=True)
    except Exception:
        return pd.NaT

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
    return {
        "id": rid, "source": source, "label": label,
        "arrival": arrival_time(msg),
        "sender": str(msg["From"] or ""), "reply_to": str(msg["Reply-To"] or ""),
        "return_path": str(msg["Return-Path"] or ""), "subject": str(msg["Subject"] or ""),
        **auth_verdicts(ar),
        "spf_domain": spf_domain(ar),
        "dkim_d": dkim_domain(msg), "n_attachments": n_att,
        "text": text, "html": html,
        # audit-only columns: used in the leakage check, never as model features
        "audit_n_received": len(msg.get_all("Received", [])),
        "audit_has_list_id": int(msg["List-Id"] is not None),
    }
def parse_bytes(raw, rid, source, label, errors):
    """Try the modern parser first; fall back to the lenient legacy one for malformed headers."""
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

def load_mbox(path, source, label, errors):
    rows = []
    box = mailbox.mbox(path)
    for key in box.keys():
        row = parse_bytes(box.get_bytes(key), f"{source}:{key}", source, label, errors)
        if row:
            rows.append(row)
    return rows

def main():
    rows, errors = [], []
    for path, source, label, kind in SOURCES:
        loader = load_eml_dir if kind == "eml" else load_mbox
        got = loader(path, source, label, errors)
        print(f"{source}: {len(got)} parsed")
        rows += got
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

if __name__ == "__main__":
    main()