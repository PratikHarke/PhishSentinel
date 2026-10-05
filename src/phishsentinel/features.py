import math, re
from email.utils import parseaddr
from urllib.parse import urlparse
import pandas as pd
import tldextract
from bs4 import BeautifulSoup

_ext = tldextract.TLDExtract(suffix_list_urls=())  # bundled suffix list, no network

FREEMAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "aol.com",
            "icloud.com", "proton.me", "protonmail.com", "mail.com", "gmx.com", "yandex.com"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy"}
AUTH_CATS = ["pass", "fail", "error", "none", "absent"]
URL_RE = re.compile(r"https?://[^\s\"'<>\)\]]+", re.I)
HIDDEN_RE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0", re.I)
NAME_DOMAIN_RE = re.compile(r"[\w.-]+\.[a-z]{2,}")

def safe_urlparse(u):
    """urlparse raises ValueError on malformed URLs (e.g. 'Invalid IPv6 URL'); phishing has plenty."""
    try:
        return urlparse(u)
    except ValueError:
        return urlparse("")

def reg_domain(host):
    host = (host or "").split("@")[-1].strip().lower()
    if not host:
        return ""
    r = _ext(host)
    if hasattr(r, "top_domain_under_public_suffix"):
        return r.top_domain_under_public_suffix
    return r.registered_domain

def entropy(s):
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))

def _from_domain(r):
    _, addr = parseaddr(r["sender"])
    return reg_domain(addr) if "@" in addr else ""

def header_feats(r):
    name, addr = parseaddr(r["sender"])
    fd = _from_domain(r)
    rt, rp = parseaddr(r["reply_to"])[1], parseaddr(r["return_path"])[1]
    rtd = reg_domain(rt) if "@" in rt else ""
    rpd = reg_domain(rp) if "@" in rp else ""
    spf_d = reg_domain(r["spf_domain"]) if r["spf_domain"] else ""
    dkim_d = reg_domain(r["dkim_d"]) if r["dkim_d"] else ""
    name_domains = {reg_domain(m) for m in NAME_DOMAIN_RE.findall(name.lower())} - {""}
    return {
        "h_replyto": 0 if not rtd else (1 if rtd == fd else 2),       # absent / match / mismatch
        "h_returnpath_mismatch": int(bool(rpd) and rpd != fd),
        "h_spf_aligned": -1 if not spf_d else int(spf_d == fd),      # -1 = no SPF domain to compare
        "h_dkim_aligned": -1 if not dkim_d else int(dkim_d == fd),
        "h_name_domain_mismatch": int(bool(name_domains) and fd not in name_domains),
        "h_freemail": int(fd in FREEMAIL),
        "h_subject_len": len(r["subject"]),
        "h_n_attachments": int(r["n_attachments"]),
    }

def content_feats(r):
    """URL (u_) and HTML (x_) features from one parse of the HTML body."""
    html, text, fd = r["html"] or "", r["text"] or "", _from_domain(r)
    urls, mismatch = [], 0
    x = {"x_has_html": int(bool(html)), "x_html_len": len(html), "x_has_form": 0,
         "x_form_external": 0, "x_hidden": 0, "x_n_img": 0, "x_tiny_img": 0,
         "x_has_script": 0, "x_has_iframe": 0}
    visible = text
    if html:
        soup = BeautifulSoup(html, "lxml")
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href.lower().startswith(("http://", "https://")):
                continue
            urls.append(href)
            shown = URL_RE.search(a.get_text(" ", strip=True))
            if shown and reg_domain(safe_urlparse(shown.group()).hostname) != reg_domain(safe_urlparse(href).hostname):
                mismatch += 1
        forms = soup.find_all("form")
        x["x_has_form"] = int(bool(forms))
        x["x_form_external"] = int(any(
            str(f.get("action", "")).lower().startswith("http")
            and reg_domain(safe_urlparse(str(f["action"])).hostname) != fd for f in forms))
        x["x_hidden"] = sum(bool(HIDDEN_RE.search(t["style"])) for t in soup.find_all(style=True))
        imgs = soup.find_all("img")
        x["x_n_img"] = len(imgs)
        x["x_tiny_img"] = sum(str(i.get("width", "")).strip() in ("0", "1") or
                              str(i.get("height", "")).strip() in ("0", "1") for i in imgs)
        x["x_has_script"] = int(bool(soup.find("script")))
        x["x_has_iframe"] = int(bool(soup.find("iframe")))
        for t in soup(["script", "style"]):
            t.decompose()
        visible = soup.get_text(" ", strip=True)
    x["x_text_len"] = len(visible)
    x["x_img_only"] = int(x["x_n_img"] > 0 and len(visible) < 50)

    urls += URL_RE.findall(text)
    parsed = [safe_urlparse(u) for u in urls]
    hosts = [(p.hostname or "") for p in parsed]
    doms = {reg_domain(h) for h in hosts if h}
    u = {"u_count": len(urls), "u_distinct_domains": len(doms),
         "u_link_text_mismatch": mismatch,
         "u_has_ip_host": int(any(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", h) for h in hosts)),
         "u_has_punycode": int(any("xn--" in h for h in hosts)),
         "u_has_shortener": int(bool(doms & SHORTENERS)),
         "u_has_at_sign": int(any("@" in p.netloc for p in parsed)),
         "u_non_https": int(any(p.scheme == "http" for p in parsed)),
         "u_max_subdomains": max([h.count(".") for h in hosts], default=0),
         "u_max_len": max([len(u_) for u_ in urls], default=0),
         "u_max_entropy": max([entropy(u_) for u_ in urls], default=0.0)}
    return {**u, **x}

def build_features(df):
    rows = [{**header_feats(r), **content_feats(r)} for r in df.to_dict("records")]
    X = pd.DataFrame(rows, index=df.index)
    for c in ("a_spf", "a_dkim", "a_dmarc"):
        X[c] = pd.Categorical(df[c], categories=AUTH_CATS)
    return X

def groups(X):
    return {g: [c for c in X.columns if c.startswith(p)]
            for g, p in {"auth": "a_", "header": "h_", "url": "u_", "html": "x_"}.items()}