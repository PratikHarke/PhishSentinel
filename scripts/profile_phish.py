import email, pathlib, collections
from email import policy
from email.utils import parsedate_to_datetime

root = pathlib.Path("data/raw/phishing_pot/email")
files = sorted(root.glob("*.eml"))
years, present, errors = collections.Counter(), collections.Counter(), 0
HEADERS = ["Date", "From", "Reply-To", "Return-Path", "Authentication-Results",
           "Received-SPF", "DKIM-Signature", "Message-ID", "List-Id"]

for p in files:
    try:
        with open(p, "rb") as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
        for h in HEADERS:
            if msg[h] is not None:
                present[h] += 1
        try:
            years[parsedate_to_datetime(msg["Date"]).year] += 1
        except Exception:
            years["bad/missing date"] += 1
    except Exception:
        errors += 1

print(f"files: {len(files)}  parse errors: {errors}")
print("by year:", sorted(years.items(), key=lambda kv: str(kv[0])))
for h in HEADERS:
    print(f"{h:24s} {present[h]:5d}  ({present[h]/max(len(files),1):.0%})")