import pandas as pd
from phishsentinel.features import build_features, groups

def reg_domain(host):
    host = (host or "").split("@")[-1].strip().lower()
    return _ext(host).registered_domain if host else ""

df = pd.read_parquet("data/processed/emails.parquet")
X = build_features(df)
out = pd.concat([df[["id", "source", "label", "arrival"]], X], axis=1)
out.to_parquet("data/processed/features.parquet")
print(out.shape, {g: len(c) for g, c in groups(X).items()})
print(X.drop(columns=["a_spf", "a_dkim", "a_dmarc"]).describe().T[["mean", "min", "max"]].round(2))