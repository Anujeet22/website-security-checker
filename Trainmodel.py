import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib

data = pd.read_csv("malicious_phish.csv")

# Select label column
if "type" in data.columns:
    y = data["type"]
elif "label" in data.columns:
    y = data["label"]
else:
    raise Exception("No label column found")

# Map labels
y = y.map({
    "benign": 0,
    "phishing": 1,
    "malware": 1,
    "defacement": 1
})

# Remove NaN
mask = ~y.isna()
X = data["url"][mask]
y = y[mask]

# Better vectorizer
vectorizer = TfidfVectorizer(
    max_features=5000,
    analyzer="char",
    ngram_range=(1, 3)
)

X = vectorizer.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Balanced model
model = LogisticRegression(max_iter=1000, class_weight="balanced")
model.fit(X_train, y_train)

joblib.dump((model, vectorizer), "url_model.pkl")

print("✅ Model trained properly")