import joblib
import pandas as pd
import lightgbm as lgb
from sklearn.metrics import roc_auc_score, roc_curve
from phishsentinel.features import groups

TRAIN_END = pd.Timestamp("2025-01-01", tz="UTC")
feat = pd.read_parquet("data/processed/features.parquet")
bundle = joblib.load("models/phishsentinel_lgbm.joblib")
cols = bundle["cols"]

# 1) Which features carry the model (share of total gain)
imp = pd.Series(bundle["model"].booster_.feature_importance(importance_type="gain"), index=cols)
print("Top features by gain share:")
print((imp / imp.sum()).sort_values(ascending=False).head(12).round(3).to_string())

# 2) Same evaluation, restricted to emails that have an HTML body in BOTH classes
def recall_at(y, p, target):
    fpr, tpr, _ = roc_curve(y, p)
    ok = tpr[fpr <= target]
    return float(ok.max()) if len(ok) else 0.0

def run(d, use_cols):
    tr, te = d[d.arrival < TRAIN_END], d[d.arrival >= TRAIN_END]
    if tr.label.nunique() < 2 or te.label.nunique() < 2:
        return None
    m = lgb.LGBMClassifier(n_estimators=300, learning_rate=0.05, num_leaves=15,
                           class_weight="balanced", random_state=0, verbose=-1)
    m.fit(tr[use_cols], tr.label)
    p = m.predict_proba(te[use_cols])[:, 1]
    return round(float(roc_auc_score(te.label, p)), 4), round(recall_at(te.label, p, 0.01), 4)

G = groups(feat)
subsets = {
    "all emails, header+url+html": (feat, cols),
    "HTML-only emails, header+url+html": (feat[feat.x_has_html == 1], cols),
    "HTML-only emails, url+html": (feat[feat.x_has_html == 1],
                                   [c for c in G["url"] + G["html"] if c in cols]),
}
print("\n(ROC-AUC, recall@1%FPR), trained on <2025, tested on >=2025")
for name, (d, c) in subsets.items():
    print(f"{name:38s} n={len(d):6d} legit={int((d.label == 0).sum()):6d} ->", run(d, c))