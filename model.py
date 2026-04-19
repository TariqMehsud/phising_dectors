"""
model.py - ML model training & prediction for Phishing Email Detector

Uses TF-IDF + Random Forest (primary) with optional fallback to Logistic Regression.
Generates a realistic synthetic dataset if no real dataset is found.
"""

import os
import re
import json
import joblib
import random
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler

from utils import MODEL_DIR, DATA_DIR

MODEL_PATH    = MODEL_DIR / "phishing_model.pkl"
VECTORIZER_PATH = MODEL_DIR / "tfidf_vectorizer.pkl"
DATASET_PATH  = DATA_DIR  / "email_dataset.csv"

# ── Synthetic dataset generation ─────────────────────────────────────────────

PHISHING_TEMPLATES = [
    "Dear customer your account has been suspended click here to verify your identity immediately",
    "URGENT: Your PayPal account has been limited. Please confirm your information within 24 hours or your account will be closed",
    "Congratulations! You have been selected as our lucky winner. Claim your $1,000,000 prize now by clicking the link",
    "Your Apple ID has been locked due to suspicious activity. Verify your account now to restore access",
    "Important security alert: We detected unauthorized access to your account. Update your password immediately",
    "Your package could not be delivered. Click here to reschedule and verify your address and payment information",
    "IRS Notice: You have a pending tax refund of $3,248. Submit your bank details to receive payment",
    "Your Microsoft account will expire. Renew your subscription now to avoid service interruption",
    "Dear user we noticed unusual sign-in activity. Click here to secure your account and reset your password",
    "You owe $892 in unpaid taxes. Failure to respond within 48 hours will result in legal action and arrest",
    "Your Netflix subscription has been suspended due to a billing issue. Update your payment method now",
    "Verify your email address to continue using our services. Click the button below within 24 hours",
    "We have credited your account with a bonus of $500. Click here to claim your reward immediately",
    "Security breach detected on your bank account. Login now to prevent further unauthorized transactions",
    "Your password expires today. Reset it immediately or you will lose access to all your files and data",
    "Dear beneficiary your inheritance funds of $4.5 million has been approved for transfer. Provide your details",
    "Amazon: Your order cannot be processed. Update your payment information to complete your purchase",
    "Your Google account has been compromised. Verify your recovery information to regain access now",
    "FBI Cyber Division: Your IP address was used in illegal activity. Respond immediately to avoid prosecution",
    "Congratulations you won an iPhone 15. Fill out the form with your credit card details to pay for shipping",
]

LEGIT_TEMPLATES = [
    "Hi John, thanks for attending our team meeting today. Please find the attached notes from our discussion",
    "Your monthly statement is ready. You can view it by logging into your account at our official website",
    "Thank you for your recent purchase. Your order has been confirmed and will arrive in 3-5 business days",
    "Meeting reminder: Quarterly review scheduled for Friday at 2pm in conference room B",
    "Here is the project proposal you requested. Please review and let me know if you have any questions",
    "Happy birthday! Wishing you a wonderful day filled with joy and celebration",
    "Please find attached the invoice for our services rendered last month. Payment is due within 30 days",
    "Thank you for subscribing to our newsletter. You can unsubscribe at any time using the link below",
    "Your flight booking is confirmed. Check-in opens 24 hours before departure via our website or app",
    "The weekly team report is attached. Key highlights include completed tasks and upcoming milestones",
    "Your support ticket has been resolved. Please let us know if you need any further assistance",
    "New comment on your document from Alice: Great work on the introduction section, very well written",
    "Reminder: Annual performance reviews begin next week. Please complete your self-assessment by Friday",
    "Your subscription renewal is coming up. You can manage your plan in your account settings anytime",
    "Thank you for your feedback. We have forwarded your suggestions to our product development team",
    "The conference agenda has been updated. You can download the latest version from our event website",
    "Your password change request was successful. If you did not make this change, contact support",
    "Team lunch is scheduled for Thursday noon at the Italian restaurant on Main Street",
    "The code review you requested has been completed. Comments are available in the pull request",
    "Welcome to the platform! Your account has been set up and you can start using all features now",
]

PHISHING_SUBJECTS = [
    "URGENT: Account Suspended", "Action Required: Verify Your Account",
    "Security Alert - Immediate Action Needed", "You Have Won $1,000,000",
    "Your Account Will Be Closed", "Important: Update Your Information",
    "Final Warning: Account Termination", "Claim Your Prize Now",
    "Unauthorized Access Detected", "Payment Failed - Update Now",
]

LEGIT_SUBJECTS = [
    "Meeting Notes - Q3 Review", "Monthly Newsletter",
    "Project Update", "Invoice #12345",
    "Team Lunch Thursday", "Quarterly Report Attached",
    "Welcome to the Team!", "Your Order Confirmation",
    "Reminder: Code Review Due", "Happy Birthday!",
]


def generate_dataset(n_samples: int = 2000) -> pd.DataFrame:
    """Generate synthetic labeled email dataset."""
    random.seed(42)
    rows = []
    half = n_samples // 2

    # Phishing samples
    for _ in range(half):
        body = random.choice(PHISHING_TEMPLATES)
        # Add variation
        extras = [
            " Click here: http://secure-login.phish-site.xyz/verify",
            " http://paypa1-verify.com/account",
            " Your account: http://192.168.1.1/login.php",
            " Act now: http://bit.ly/2Xk9pLm",
            " Limited time offer!",
        ]
        body += random.choice(extras)
        rows.append({
            "subject":  random.choice(PHISHING_SUBJECTS),
            "body":     body,
            "label":    1,   # phishing
        })

    # Legit samples
    for _ in range(half):
        body = random.choice(LEGIT_TEMPLATES)
        rows.append({
            "subject": random.choice(LEGIT_SUBJECTS),
            "body":    body,
            "label":   0,   # legitimate
        })

    df = pd.DataFrame(rows).sample(frac=1, random_state=42).reset_index(drop=True)
    return df

# ── Feature engineering ───────────────────────────────────────────────────────

def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Create handcrafted numeric features from email fields."""
    from utils import (URGENT_KEYWORDS, FINANCIAL_KEYWORDS,
                       CREDENTIAL_KEYWORDS, THREAT_KEYWORDS,
                       count_keyword_hits, extract_urls, is_ip_url,
                       has_url_shortener)

    records = []
    for _, row in df.iterrows():
        text = f"{row.get('subject','')} {row.get('body','')}".lower()
        urls = extract_urls(text)

        urg_cnt, _  = count_keyword_hits(text, URGENT_KEYWORDS)
        fin_cnt, _  = count_keyword_hits(text, FINANCIAL_KEYWORDS)
        cred_cnt, _ = count_keyword_hits(text, CREDENTIAL_KEYWORDS)
        thr_cnt, _  = count_keyword_hits(text, THREAT_KEYWORDS)

        records.append({
            "n_urls":            len(urls),
            "has_ip_url":        int(any(is_ip_url(u) for u in urls)),
            "has_shortener":     int(any(has_url_shortener(u) for u in urls)),
            "urgent_score":      urg_cnt,
            "financial_score":   fin_cnt,
            "credential_score":  cred_cnt,
            "threat_score":      thr_cnt,
            "exclamation_count": text.count("!"),
            "caps_ratio":        sum(1 for c in text if c.isupper()) / max(len(text), 1),
            "text_len":          len(text),
        })
    return pd.DataFrame(records)


def build_combined_text(df: pd.DataFrame) -> pd.Series:
    """Combine subject + body for TF-IDF."""
    return df.apply(lambda r: f"{r.get('subject','')} {r.get('body','')} "
                              f"{r.get('from','')}", axis=1)

# ── Train ─────────────────────────────────────────────────────────────────────

def train_model(force_retrain: bool = False) -> dict:
    """Train and save the phishing detection model."""
    if MODEL_PATH.exists() and not force_retrain:
        return {"status": "loaded", "message": "Model loaded from disk."}

    print("📊 Generating / loading dataset …")
    if DATASET_PATH.exists():
        df = pd.read_csv(DATASET_PATH)
    else:
        df = generate_dataset(2000)
        df.to_csv(DATASET_PATH, index=False)
        print(f"  → Saved synthetic dataset to {DATASET_PATH}")

    X_text = build_combined_text(df)
    X_feats = engineer_features(df)
    y = df["label"]

    # TF-IDF text features
    vectorizer = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 2),
        stop_words="english",
        sublinear_tf=True,
    )
    X_tfidf = vectorizer.fit_transform(X_text)

    # Combine TF-IDF + hand-crafted features
    import scipy.sparse as sp
    X_combined = sp.hstack([X_tfidf, sp.csr_matrix(X_feats.values)])

    X_train, X_test, y_train, y_test = train_test_split(
        X_combined, y, test_size=0.2, random_state=42, stratify=y
    )

    print("🤖 Training Random Forest …")
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=4,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    report = classification_report(y_test, y_pred, output_dict=True)

    # Persist
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print(f"✅ Model saved. Accuracy: {report['accuracy']:.3f}")

    return {
        "status":   "trained",
        "accuracy": report["accuracy"],
        "report":   report,
    }

# ── Predict ───────────────────────────────────────────────────────────────────

def load_model():
    """Load trained model and vectorizer."""
    if not MODEL_PATH.exists():
        train_model()
    clf = joblib.load(MODEL_PATH)
    vec = joblib.load(VECTORIZER_PATH)
    return clf, vec


def predict_email(subject: str, body: str, sender: str = "") -> dict:
    """
    Predict phishing probability for an email.
    Returns: {"ml_score": float 0-1, "label": str, "confidence": float}
    """
    try:
        clf, vec = load_model()
    except Exception as e:
        return {"ml_score": 0.5, "label": "UNKNOWN", "confidence": 0.0, "error": str(e)}

    dummy_df = pd.DataFrame([{"subject": subject, "body": body, "from": sender}])
    text_combined = build_combined_text(dummy_df)
    feats = engineer_features(dummy_df)

    import scipy.sparse as sp
    X_tfidf = vec.transform(text_combined)
    X = sp.hstack([X_tfidf, sp.csr_matrix(feats.values)])

    proba = clf.predict_proba(X)[0]
    phish_prob = float(proba[1])

    return {
        "ml_score":   round(phish_prob * 100, 1),
        "confidence": round(max(proba) * 100, 1),
        "label":      "PHISHING" if phish_prob >= 0.5 else "SAFE",
    }


if __name__ == "__main__":
    result = train_model(force_retrain=True)
    print(json.dumps({k: v for k, v in result.items() if k != "report"}, indent=2))
