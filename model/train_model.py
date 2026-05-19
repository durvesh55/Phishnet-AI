"""
PhishNet AI — Model Trainer
────────────────────────────
Trains a TF-IDF + Logistic Regression classifier on a phishing email dataset.
Run this script once to generate model/phishnet_model.pkl

Usage:
    python model/train_model.py

Dataset: Uses the built-in sample dataset below.
For better accuracy, download the Kaggle phishing email dataset and replace
the samples with real data (see README.md).
"""

import pickle
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# ── Sample Dataset ────────────────────────────────────────────────────────────
# Label: 1 = Phishing, 0 = Safe
# Replace with a real CSV dataset for production use.

SAMPLES = [
    # Phishing emails (label = 1)
    ("URGENT: Your PayPal account has been suspended. Verify immediately at http://bit.ly/paypa1-restore or it will be deleted.", 1),
    ("Dear Customer, your Amazon account shows suspicious activity. Click here to verify your password and credit card number.", 1),
    ("Your bank account is locked. Enter your SSN and PIN at http://secure-bank-verify.xyz to restore access within 24 hours.", 1),
    ("ALERT: Unauthorized login detected. Confirm your identity NOW or your account will be permanently banned.", 1),
    ("Congratulations! You have won $5000. Click http://bit.ly/claim-prize-now to claim your reward. Limited time!", 1),
    ("Your Netflix subscription has expired. Update your credit card details immediately to avoid service interruption.", 1),
    ("IT Security Alert: Your password expires today. Click here to reset: http://corp-it-reset.ru/login", 1),
    ("Dear user, your email storage is full. Verify your account credentials to continue using our service.", 1),
    ("FINAL NOTICE: Your tax refund of $3,241 is pending. Submit your SSN and bank details to claim.", 1),
    ("Your Microsoft account will be closed in 24 hours. Verify at http://micros0ft-verify.tk now!", 1),
    ("Urgent: Suspicious transaction detected on your account. Call us immediately and provide your PIN.", 1),
    ("Your Apple ID has been disabled. Restore access by entering your password and security questions now.", 1),
    ("You have a pending inheritance of $2.5 million. Reply with your bank details to proceed with transfer.", 1),
    ("Security breach detected. All users must re-enter credentials at http://goo.gl/sec-update immediately.", 1),
    ("Your DHL package could not be delivered. Pay $2.99 customs fee at http://dhl-delivery.xyz to redeliver.", 1),

    # Safe emails (label = 0)
    ("Hi team, reminder about our weekly sync this Thursday at 3 PM in Conference Room B. Please prepare your updates.", 0),
    ("Monthly newsletter from GitHub: New features released this month including improved code review tools.", 0),
    ("Your order has been shipped! Track your package using the link in your account dashboard.", 0),
    ("Meeting agenda for tomorrow: Q3 review, budget planning, and team onboarding discussion.", 0),
    ("Hi Sarah, please find attached the project report for your review. Let me know if you have any feedback.", 0),
    ("Reminder: Company all-hands meeting on Friday at 10 AM. Zoom link shared in the calendar invite.", 0),
    ("Your annual subscription to Spotify Premium has been renewed. Receipt attached for your records.", 0),
    ("Welcome to the team! Your onboarding schedule and first-week plan are attached.", 0),
    ("Code review requested: Please review the pull request for the new authentication module.", 0),
    ("Happy to confirm your appointment on December 15th at 2 PM. Please reply to reschedule if needed.", 0),
    ("Your flight booking is confirmed. Boarding pass and itinerary attached. Have a great trip!", 0),
    ("This month's engineering blog is live. Topics: microservices, CI/CD pipelines, and load testing.", 0),
    ("Just checking in on the Q4 roadmap. Can we schedule a call this week to align on priorities?", 0),
    ("Your password was successfully changed. If you did not make this change, contact support.", 0),
    ("Team lunch is scheduled for Friday at noon. We'll be heading to the Italian place on Main Street.", 0),
]

# ── Train ─────────────────────────────────────────────────────────────────────

def train():
    texts  = [s[0] for s in SAMPLES]
    labels = [s[1] for s in SAMPLES]

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42
    )

    # TF-IDF Vectorizer
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),   # unigrams + bigrams
        max_features=5000,
        stop_words='english',
        sublinear_tf=True
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec  = vectorizer.transform(X_test)

    # Logistic Regression Classifier
    clf = LogisticRegression(max_iter=1000, C=1.0, solver='lbfgs')
    clf.fit(X_train_vec, y_train)

    # Evaluate
    y_pred = clf.predict(X_test_vec)
    acc    = accuracy_score(y_test, y_pred)
    print(f"\n✅ Model trained successfully!")
    print(f"   Accuracy: {acc * 100:.1f}%")
    print(f"\n{classification_report(y_test, y_pred, target_names=['Safe','Phishing'])}")

    # Save model
    os.makedirs('model', exist_ok=True)
    model_data = {'vectorizer': vectorizer, 'classifier': clf}
    with open('model/phishnet_model.pkl', 'wb') as f:
        pickle.dump(model_data, f)
    print("💾 Model saved to model/phishnet_model.pkl")

if __name__ == '__main__':
    train()
