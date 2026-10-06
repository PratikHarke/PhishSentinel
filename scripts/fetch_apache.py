import pathlib, time, urllib.request, urllib.error

BASE = "https://mail-archives.apache.org/mod_mbox"
LISTS = ["httpd-users", "kafka-users", "spark-user", "tomcat-users", "cassandra-user"]
MONTHS = [f"{y}{m:02d}" for y in range(2022, 2027) for m in range(1, 13) if (y, m) <= (2026, 9)]
OUT = pathlib.Path("data/raw/legit_apache")

for lst in LISTS:
    present, not_found, failed = 0, 0, 0
    for ym in MONTHS:
        dest = OUT / lst / f"{ym}.mbox"
        if dest.exists():
            present += 1
            continue
        req = urllib.request.Request(f"{BASE}/{lst}/{ym}.mbox",
                                     headers={"User-Agent": "PhishSentinel-research/0.1"})
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                data = r.read()
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            present += 1
        except urllib.error.HTTPError as e:
            if e.code == 404:
                not_found += 1
            else:
                failed += 1
                print(f"  {lst}/{ym}: HTTP {e.code}")
        except Exception as e:
            failed += 1
            print(f"  {lst}/{ym}: {e!r}")
        time.sleep(1)  # be polite to the server
    print(f"{lst}: {present} present, {not_found} not found, {failed} failed (re-run to retry)")