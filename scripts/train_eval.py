import itertools, pathlib, re
import joblib
import pandas as pd
import lightgbm as lgb
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, roc_curve
from phishsentinel.features import groups

TRAIN_END = pd.Timestamp("2025-01-01", tz="UTC")
VAL_END = pd.Timestamp("2026-01-01", tz="UTC")
# Features that identify the collection source (see scripts/leakage_audit.py)
EXCLUDE = {"h_spf_aligned", "h_dkim_aligned"}
TAG = re.compile(r"<[^>]+>")
COLS = ["recall@1%FPR", "recall@0.1%FPR", "ROC-AUC"]

feat = pd.read_parquet("data/processed/features.parquet")
raw = pd.read_parquet("data/processed/emails.parquet", columns=["id", "subject", "text", "html"])
df = feat.merge(raw, on="id")
if df.label.nunique() < 2:
    raise SystemExit("Only one class present: add legitimate mail in parse.py first.")

# Compare both classes over the same time window so the model can't learn the era
lo = max(df[df.label == c].arrival.min() for c in (0, 1))
hi = min(df[df.label == c].arrival.max() for c in (0, 1))
df = df[(df.arrival >= lo) & (df.arrival <= hi)].sort_values("arrival").copy()

tr = df[df.arrival < TRAIN_END]
va = df[(df.arrival >= TRAIN_END) & (df.arrival < VAL_END)]
te = df[df.arrival >= VAL_END]
for name, d in (("train", tr), ("val", va), ("test", te)):
    print(name, len(d), d.label.value_counts().to_dict())
    if d.label.nunique() < 2:
        raise SystemExit(f"{name} split lacks one class; adjust TRAIN_END/VAL_END or collect more data.")
n_neg_test = int((te.label == 0).sum())
if n_neg_test < 1000:
    print(f"WARNING: only {n_neg_test} legitimate emails in test, so recall@0.1%FPR is unreliable.")

def body(d):
    t = d.text.where(d.text.str.strip() != "", d.html.map(lambda h: TAG.sub(" ", h[:50000])))
    return (d.subject + " " + t).str.lower()

def recall_at(y, p, target):
    fpr, tpr, _ = roc_curve(y, p)
    ok = tpr[fpr <= target]
    return float(ok.max()) if len(ok) else 0.0

def metrics(y, p):
    return (round(recall_at(y, p, 0.01), 4), round(recall_at(y, p, 0.001), 4),
            round(float(roc_auc_score(y, p)), 4))

def text_baseline(train, test):
    tf = TfidfVectorizer(min_df=3, ngram_range=(1, 2), sublinear_tf=True, max_features=200000)
    lr = LogisticRegression(max_iter=2000, class_weight="balanced")
    lr.fit(tf.fit_transform(body(train)), train.label)
    return metrics(test.label, lr.predict_proba(tf.transform(body(test)))[:, 1])

def fit(cols, train):
    m = lgb.LGBMClassifier(n_estimators=300, learning_rate=0.05, num_leaves=15,
                           class_weight="balanced", random_state=0, verbose=-1)
    return m.fit(train[cols], train.label)

print("\nTF-IDF text baseline (val):", dict(zip(COLS, text_baseline(tr, va))))

G = groups(df)
G.pop("auth")                                           # leaks collection source
G = {g: [c for c in cols if c not in EXCLUDE] for g, cols in G.items()}

# Ablation on VALIDATION only; the test split is touched once, at the end
rows = []
for k in range(1, len(G) + 1):
    for combo in itertools.combinations(G, k):
        cols = [c for g in combo for c in G[g]]
        m = fit(cols, tr)
        rows.append(("+".join(combo), *metrics(va.label, m.predict_proba(va[cols])[:, 1])))
abl = pd.DataFrame(rows, columns=["groups"] + COLS).sort_values(["recall@1%FPR", "ROC-AUC"], ascending=False)
print("\nAblation (val):\n", abl.to_string(index=False))
abl.to_csv("ablation_val.csv", index=False)

best = abl.iloc[0].groups.split("+")
cols = [c for g in best for c in G[g]]
trva = pd.concat([tr, va])
m = fit(cols, trva)
print("\nFINAL (test), run once:")
print("  structured", best, dict(zip(COLS, metrics(te.label, m.predict_proba(te[cols])[:, 1]))))
print("  tf-idf baseline", dict(zip(COLS, text_baseline(trva, te))))
pathlib.Path("models").mkdir(exist_ok=True)
joblib.dump({"model": m, "cols": cols}, "models/phishsentinel_lgbm.joblib")
print("saved models/phishsentinel_lgbm.joblib")