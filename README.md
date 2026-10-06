# PhishSentinel

A phishing-email detector built around a question most tutorials skip: **is the model detecting phishing, or detecting where the emails came from?**

PhishSentinel scores raw `.eml` messages using header, URL, and HTML-structure features, evaluates them with a chronological split, and ships with a leakage audit that measures how much of the apparent accuracy comes from dataset construction rather than from the threat.

> **Status: work in progress.** The pipeline, evaluation harness, and leakage audit are complete. The headline results are pending a second legitimate-mail source (see [Limitations](#limitations)). Numbers below are labeled as interim where they should not be quoted as performance.

## Pipeline

```
raw .eml / .mbox  ->  parse.py  ->  emails.parquet  ->  features.py  ->  features.parquet
                                                                    |
                         leakage_audit.py  <-----------------------+----->  train_eval.py
                         inspect_model.py                                    (time-split, ablation)
```

| Step | Script | What it does |
|---|---|---|
| 1 | `src/phishsentinel/parse.py` | Parses messages (modern parser with a lenient fallback for malformed headers), extracts arrival time from the top `Received` header, normalizes auth verdicts, removes exact duplicates |
| 2 | `scripts/build_features.py` | Builds 37 features in four groups: auth, header, URL, HTML |
| 3 | `scripts/leakage_audit.py` | Trains models on features that should carry no phishing signal and reports how well they still separate the classes |
| 4 | `scripts/train_eval.py` | Chronological train/validation/test split, ablation over feature groups, TF-IDF text baseline |
| 5 | `scripts/inspect_model.py` | Feature importance and an HTML-only control experiment |

## Data

| Class | Source | Notes |
|---|---|---|
| Phishing | [Phishing Pot](https://github.com/rf-peixoto/phishing_pot) | Real phishing `.eml` files, 8,614 parsed with 0 errors, 7,962 after cleaning |
| Legitimate | Public Apache mailing-list archives (httpd-users, kafka-users, spark-user, tomcat-users, cassandra-user), 2022-2026 | Random sample of up to 100 messages per monthly file; 16,552 after cleaning |
| Legitimate (planned) | Personal HTML bulk mail (newsletters, receipts, account notices) | TODO: see Limitations |

Design decisions that matter:

- **Time key is the `Received` timestamp, not `Date`.** The `Date` header is set by the sender. In the phishing corpus it produced messages "sent" in 2019-2021 and 2030-2033, and 92 messages had no usable date.
- **Both classes are compared over the same date window** so a model cannot learn the era.
- **Exact duplicates are removed** (campaign emails otherwise land in both train and test).
- **Raw mail is never committed.** `data/`, `*.eml`, and `*.mbox` are git-ignored; only code and extracted feature logic are in the repo.

## Features

37 features in four groups. Group prefixes make ablation a column filter.

| Prefix | Group | Examples |
|---|---|---|
| `a_` | Authentication verdicts | SPF / DKIM / DMARC result (normalized to pass, fail, error, none, absent) |
| `h_` | Header | Reply-To vs From mismatch, Return-Path mismatch, SPF/DKIM alignment, display-name vs address domain, free-mail sender |
| `u_` | URL | link-text vs href mismatch, IP host, punycode, shortener, `@` in URL, subdomain depth, URL length and entropy |
| `x_` | HTML | hidden elements, form to external domain, 1x1 images, image-only body, script/iframe presence |

Malformed URLs (which are common in real phishing and crash `urllib` by default) are handled by a safe parser wrapper.

## Evaluation protocol

- **Chronological split:** train on mail arriving before 2025, validate on 2025, test on 2026. Final test numbers are reported once.
- **Metrics:** recall at a fixed 1% and 0.1% false-positive rate, and ROC-AUC. PR-AUC and precision are deliberately not used for model comparison, because the class mix changes sharply by year in this dataset (about 96% legitimate in 2022, about 60% phishing in 2026), which makes them incomparable across splits.
- **Ablation** over feature-group combinations, on the validation split only.
- **Baseline:** TF-IDF + logistic regression on subject and body.
- **Recall at 0.1% FPR is flagged as unreliable** whenever the test set has fewer than 1,000 legitimate emails.

## Leakage audit

The audit trains models on feature sets that should say nothing about phishing and checks how well they still separate the two classes.

**Collection artifacts differ almost perfectly between the classes** (share of messages with the property, legitimate vs phishing):

| Property | Legitimate | Phishing |
|---|---|---|
| Has `List-Id` header | 1.00 | 0.10 |
| Has an SPF domain | 0.00 | 0.92 |
| Has a Reply-To | 0.81 | 0.24 |

**Test ROC-AUC from groups that should not detect phishing:**

| Feature set | ROC-AUC |
|---|---|
| Collection artifacts only (Received-hop count, List-Id presence) | 0.979 |
| Authentication verdicts only | 1.000 |
| Header presence only | 0.987 |

**Consequence:** the authentication group and the two auth-derived alignment features are excluded from training. Real-world finding along the way: 53% of the phishing corpus passes SPF, so "passed authentication" does not mean "legitimate."

**Feature importance of the current model:** `h_replyto` (25.6% of gain), `x_n_img` (24.3%), `h_freemail` (12.0%), and `h_returnpath_mismatch` (11.2%). These reflect mailing-list headers and the plain-text vs designed-mail style gap, not maliciousness.

**HTML-only control:** restricting both classes to messages with an HTML body barely changed performance (ROC-AUC 0.9979 to 0.9966). This does not rule out the confound, because the remaining legitimate HTML mail is still mailing-list mail with list headers. URL and HTML features alone, on HTML-only messages, reach ROC-AUC 0.982 and recall 0.853 at 1% FPR; treat that as an upper bound on content-only performance, since the style gap between the sources remains.

## Interim results (do not quote as performance)

Current dataset, chronological split, test on 2026:

| Model | recall @ 1% FPR | ROC-AUC |
|---|---|---|
| Structured (header + URL + HTML) | 0.979 | 0.9985 |
| TF-IDF text baseline | 0.998 | 0.9998 |

The text baseline beating the structured model by this margin is itself a symptom: the legitimate class is technical discussion of Kafka, Tomcat, and Spark, so topic alone separates the classes.

## Limitations

- **The legitimate class is too easy.** Plain-text developer mail differs from phishing in headers, formatting, topic, and sender behavior. All current results are inflated by this. A harder negative class is needed: HTML newsletters, receipts, and account notices, which are what phishing imitates. TODO: add this source and re-run the audit; the target is a clear drop in the content-only audit scores and a text baseline that no longer dominates.
- **Few legitimate test messages** (594 in the 2026 split), so low-FPR recall is noisy.
- **Phishing is from one corpus** with its own collection biases (Microsoft-style receiving headers in most samples).
- **No evaluation against adversarial mutation yet** (homoglyphs, zero-width characters, HTML padding). Planned.
- **Authentication results reflect the collecting mailbox**, not necessarily the original delivery path.

## Roadmap

- [ ] Add a realistic HTML legitimate-mail source; re-run the leakage audit
- [ ] Re-baseline and report final test metrics once
- [ ] Per-message explanations with SHAP
- [ ] Adversarial robustness: mutate test phishing, measure the drop, retrain with augmentation, re-measure
- [ ] FastAPI service: upload a `.eml`, get verdict, score, and top reasons (with an input size cap)

## Reproduce

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
pip install pandas numpy scikit-learn lightgbm shap joblib pyarrow tldextract beautifulsoup4 lxml typer matplotlib seaborn pytest

git clone --depth 1 https://github.com/rf-peixoto/phishing_pot.git data\raw\phishing_pot
python scripts\fetch_apache.py

python -m phishsentinel.parse
python scripts\build_features.py
python scripts\leakage_audit.py
python scripts\train_eval.py
pytest -q
```

## Data handling

Raw emails contain third-party addresses and live phishing content. They are not redistributed and never committed. Parse them as text only; do not open `.eml` files in a mail client.

## Author

Pratik Harke
