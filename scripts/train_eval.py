import itertools, re
import pandas as pd
import lightgbm as lgb
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_curve
from phishsentinel.features import AUTH_CATS, groups

FPR = 0.01
TRAIN_END = pd.Timestamp("2025-01-01", tz="UTC")
VAL_END = pd.Timestamp("2026-01-01", tz="UTC")
TAG = re.compile(r"<[^>]+>")

feat = pd.read_parquet("data/processed/features.parquet")
raw = pd.read_parquet("data/processed/emails.parquet", columns=["id", "subject", "text", "html"])
df = feat.merge(raw, on="id")
if df.label.nunique() < 2:
    raise SystemExit("Only one class present: add legitimate mail to SOURCES in parse.py, "
                     "then re-run parse and build_features.")

# Compare both classes over the same time window so the model can't learn the era
lo = max(df[df.label == c].arrival.min() for c in (0, 1))
hi = min(df[df.label == c].arrival.max() for c in (0, 1))
df = df[(df.arrival >= lo) & (df.arrival <= hi)].sort_values("arrival").copy()
for c in ("a_spf", "a_dkim", "a_dmarc"):
    df[c] = pd.Categorical(df[c].astype(str), categories=AUTH_CATS)

tr = df[df.arrival < TRAIN_END]
va = df[(df.arrival >= TRAIN_END) & (df.arrival < VAL_END)]
te = df[df.arrival >= VAL_END]
for name, d in (("train", tr), ("val", va), ("test", te)):
    print(name, len(d), d.label.value_counts().to_dict())
    if d.label.nunique() < 2:
        raise SystemExit(f"{name} split lacks one class; adjust TRAIN_END/VAL_END or collect more data.")

def body(d):
    b = d.text.where(d.text.str.strip() != "", d.html.map(lambda h: TAG.sub(" ", h[:50000])))
    return (d.subject + " " + b).str.lower()

def metrics(y, p):
    fpr, tpr, _ = roc_curve(y, p)
    ok = tpr[fpr <= FPR]
    return round(average_precision_score(y, p), 4), round(float(ok.max()) if len(ok) else 0.0, 4)

def text_baseline(train, test):
    tf = TfidfVectorizer(min_df=3, ngram_range=(1, 2), sublinear_tf=True, max_features=200000)
    lr = LogisticRegression(max_iter=2000, class_weight="balanced")
    lr.fit(tf.fit_transform(body(train)), train.label)
    return metrics(test.label, lr.predict_proba(tf.transform(body(test)))[:, 1])

def fit_eval(cols, train, test):
    m = lgb.LGBMClassifier(n_estimators=300, learning_rate=0.05, num_leaves=15,
                           class_weight="balanced", random_state=0, verbose=-1)
    m.fit(train[cols], train.label)
    return metrics(test.label, m.predict_proba(test[cols])[:, 1])

print("\nTF-IDF baseline (val): PR-AUC, recall@1%FPR =", text_baseline(tr, va))

# Ablation on VALIDATION only; the test split is touched once, at the end
G = groups(df)
rows = []
for k in range(1, len(G) + 1):
    for combo in itertools.combinations(G, k):
        cols = [c for g in combo for c in G[g]]
        rows.append(("+".join(combo), *fit_eval(cols, tr, va)))
abl = pd.DataFrame(rows, columns=["groups", "PR-AUC", "recall@1%FPR"]).sort_values("PR-AUC", ascending=False)
print("\nAblation (val):\n", abl.to_string(index=False))
abl.to_csv("ablation_val.csv", index=False)

best = abl.iloc[0].groups.split("+")
cols = [c for g in best for c in G[g]]
trva = pd.concat([tr, va])
print("\nFINAL (test), run once:")
print("  structured", best, fit_eval(cols, trva, te))
print("  tf-idf baseline", text_baseline(trva, te))