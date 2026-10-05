import email, pathlib, collections
from email import policy
from email.utils import parsedate_to_datetime

root = pathlib.Path("data/raw/phishing_pot/email")
authserv, arrival_years, failed = collections.Counter(), collections.Counter(), 0

for p in sorted(root.glob("*.eml")):
    try:
        with open(p, "rb") as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
        ar = str(msg["Authentication-Results"] or "")
        authserv[(ar.split(";")[0].split() or ["none"])[0]] += 1
        rec = msg.get_all("Received", [])
        ts = str(rec[0]).rsplit(";", 1)[-1].strip() if rec else None
        arrival_years[parsedate_to_datetime(ts).year] += 1
    except Exception:
        failed += 1

print("authserv-id:", authserv.most_common(8))
print("arrival year:", sorted(arrival_years.items()))
print("failed:", failed)