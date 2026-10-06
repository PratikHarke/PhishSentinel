import pandas as pd
import lightgbm as lgb
from sklearn.metrics import roc_auc_score
from phishsentinel.features import groups

feat = pd.read_parquet("data/processed/features.parquet")
raw = pd.read_parquet("data/processed/emails.parquet",
                      columns=["id", "return_path", "reply_to", "dkim_d", "spf_domain",
                               "audit_n_received", "audit_has_list_id", "audit_arrival_from_date"])
df = feat.merge(raw, on="id")
for c in ("a_spf", "a_dkim", "a_dmarc"):
    df[c] = pd.Categorical(df[c].astype(str)).codes
df["has_return_path"] = (df.return_path != "").astype(int)
df["has_reply_to"] = (df.reply_to != "").astype(int)
df["has_dkim_domain"] = (df.dkim_d != "").astype(int)
df["has_spf_domain"] = (df.spf_domain != "").astype(int)

print("Presence rate by label (0 = legit, 1 = phishing):")
cols = ["has_return_path", "has_reply_to", "has_dkim_domain", "has_spf_domain",
        "audit_has_list_id", "audit_arrival_from_date"]
print(df.groupby("label")[cols].mean().round(2).T.to_string())

train = df.arrival < pd.Timestamp("2025-01-01", tz="UTC")
def auc_for(feats, name):
    m = lgb.LGBMClassifier(n_estimators=200, learning_rate=0.05, num_leaves=15,
                           random_state=0, verbose=-1)
    m.fit(df.loc[train, feats], df.label[train])
    p = m.predict_proba(df.loc[~train, feats])[:, 1]
    print(f"{name:34s} test ROC-AUC = {roc_auc_score(df.label[~train], p):.3f}")

print()
auc_for(["audit_n_received", "audit_has_list_id"], "collection artifacts only")
auc_for(["a_spf", "a_dkim", "a_dmarc"], "auth verdicts only")
auc_for(["has_return_path", "has_reply_to", "has_dkim_domain", "has_spf_domain"], "header presence only")
G = groups(feat)
auc_for(G["url"] + G["html"], "url + html features")
auc_for([c for c in G["header"] if c not in ("h_spf_aligned", "h_dkim_aligned")], "header (minus auth-derived)")