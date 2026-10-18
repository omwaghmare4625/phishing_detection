"""
Email Phishing NLP Model Training Pipeline.
Trains a TF-IDF + Calibrated Logistic Regression classifier on email subject + body text.
Exports the trained model pipeline to backend/models/email_model.joblib.
"""
import os
import sys
from pathlib import Path
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# Curated dataset of representative phishing and benign email communications
TRAINING_DATA = [
    # --- Phishing: Account Suspension & Credential Theft ---
    ("Urgent: Your account will be suspended within 24 hours", "Please confirm your password immediately by clicking the verification link to avoid service interruption.", 1),
    ("Security Alert: Unauthorized login attempt detected", "Someone attempted to log into your account from an unknown location. Review activity and verify your credentials now.", 1),
    ("Important Notice: Immediate action required on your account", "Your billing information is outdated. Update payment details right away to maintain access.", 1),
    ("Action Required: Your mailbox is almost full", "To prevent losing emails, click here to validate your mailbox quota and re-authenticate your mailbox access.", 1),
    ("Notice: Your password expires today", "Your corporate network password will expire in 2 hours. Keep your existing password by verifying your login details here.", 1),
    ("Your subscription has been cancelled", "We could not process your latest payment. Re-enter your credit card number to avoid immediate cancellation.", 1),
    ("Urgent Notification: Bank account locked", "Suspicious transactions were detected on your debit card. Log in to your online banking portal to unlock your account.", 1),
    ("Final Warning: Service termination notice", "Failure to verify your identity within 12 hours will result in permanent deletion of your account records.", 1),
    ("Immediate action required: Tax refund available", "Submit your personal details and social security number to claim your pending tax refund before deadline.", 1),
    ("Security Update: Two-Factor authentication reset", "Click here to re-authorize your device and enter your authentication token to prevent unauthorized access.", 1),
    ("Payroll Update: Verify your direct deposit information", "We noticed discrepancies in your payroll routing. Please sign in to the employee portal to re-enter your banking details.", 1),
    ("IT Helpdesk: Critical security patch installation", "All staff members must verify their network credentials to initiate the mandatory security patch.", 1),
    ("Overdue Invoice: Payment required today", "Please find attached the past due invoice. Click the link to review charges and settle your account immediately.", 1),
    ("Delivery Notice: Package delivery failed", "Your courier parcel could not be delivered due to an invalid shipping address. Click to update your delivery address and pay the fee.", 1),
    ("Wire Transfer Request: Confidential inquiry", "Are you at your desk? I need an urgent wire transfer processed before end of business today for our vendor.", 1),
    ("Gift card purchase request", "Can you quickly purchase 5 Apple gift cards for a client presentation? Send the voucher codes to my personal email.", 1),
    ("Crypto wallet compromised", "Unauthorized withdrawal detected. Transfer your crypto assets to our secure cold-storage address immediately.", 1),
    ("Job Offer: Work from home position accepted", "Congratulations! Before we disburse your equipment stipend, send your banking credentials and government ID.", 1),
    ("Unusual sign-in activity on your Google Account", "We blocked a suspicious sign-in from Moscow. If this was not you, please secure your account by clicking here.", 1),
    ("Microsoft 365: Unusual volume of file deletions", "A high volume of files were deleted from OneDrive. Click here to restore files and authenticate your session.", 1),
    ("Invoice #84912 has been generated", "Your payment of $499.00 to Geek Squad will be debited. If you did not authorize this charge, call our hotline immediately.", 1),
    ("PayPal: Receipt for your payment to Digital Services", "You sent a payment of $899.99. If you did not make this purchase, click the dispute resolution link immediately.", 1),
    ("DHL Express: Shipment awaiting customs clearance", "Your package is held at customs. Pay the import fee of $2.95 through the secure link below to release your parcel.", 1),
    ("HR Announcement: Employee bonus scheme registration", "Review the attached compensation schedule and confirm your employee credentials to claim your holiday bonus.", 1),
    ("DocuSign: Please review and sign document", "A document has been shared with you regarding termination policy. Click here to review and enter your access code.", 1),
    ("Dropbox: File shared with you - Q4 Financials", "The finance team has shared a file with you. Sign in with your corporate email password to download.", 1),
    ("Zoom: Meeting recording ready for download", "Your scheduled video recording is ready. Please log in to your account to view the playback.", 1),
    ("Apple ID: Account flagged for fraudulent activity", "Your Apple ID has been temporarily locked for security precautions. Verify your payment method to unlock.", 1),
    ("Netflix: Update your payment information", "We were unable to process your monthly membership. Please update your billing details to continue watching.", 1),
    ("Amazon: Order confirmation #302-918239", "Thank you for purchasing Apple iPhone 15 Pro Max. If you did not place this order, cancel it immediately here.", 1),

    # --- Benign: Normal Work & Personal Communications ---
    ("Project sync meeting notes", "Hi team, attached are the action items from our weekly sync. Let me know if anything was missed before our Thursday check-in.", 0),
    ("Lunch plans today?", "Hey Aryan, are you free to grab lunch around 12:30 today? Let me know if the cafeteria works.", 0),
    ("Sprint 42 retrospective follow-up", "Thanks for participating in yesterday's retro. I've updated the Jira board with our key process improvement goals.", 0),
    ("Weekly engineering newsletter", "Here are the top tech articles and architecture updates from our internal engineering guild this week. Enjoy the read!", 0),
    ("Code review requested: PR #142", "Could someone take a look at the refactored database queries when you have a spare moment? All unit tests are passing.", 0),
    ("Quarterly roadmap planning session", "Please review the proposed OKR slide deck before our strategy meeting on Friday afternoon. Feedback is welcome.", 0),
    ("Out of office: Vacation notice", "I will be out of the office from Monday to Wednesday with limited access to email. For urgent issues please reach out to Dave.", 0),
    ("Documentation updates on the wiki", "I updated the onboarding instructions for new developers on the internal wiki page. Please check if the steps are clear.", 0),
    ("Happy birthday Sarah!", "Wishing you a wonderful birthday and a great year ahead! There is cake in the second-floor break room.", 0),
    ("Conference tickets confirmation", "Your registration for PyCon 2026 has been confirmed. You can find the event schedule and venue details attached.", 0),
    ("Feedback on presentation draft", "Great job on the initial slides. I left a few minor formatting comments on slide 4 and slide 8 for your review.", 0),
    ("Monthly cloud infrastructure cost summary", "Here is the summary of our AWS spend for the previous month. Our costs remained within the approved operational budget.", 0),
    ("Gym membership discount for staff", "The company wellness program now includes discounted annual memberships at local fitness centers.", 0),
    ("Release notes for version 2.4.0", "Version 2.4.0 has been deployed to production. This release includes bug fixes for search filtering and minor UI improvements.", 0),
    ("Mentorship program sign-up", "The annual peer mentorship program is accepting applications this month. Sign up if you'd like to participate as a mentor or mentee.", 0),
    ("Book recommendation from our conversation", "Here is that distributed systems book we discussed yesterday. Chapter 3 specifically covers consensus algorithms nicely.", 0),
    ("Design system workshop reminder", "A quick reminder that the UI design system walkthrough will start in 30 minutes in conference room B.", 0),
    ("API rate limit adjustment", "We adjusted the rate limits on the staging cluster to facilitate our load testing session this afternoon.", 0),
    ("Thank you for your help on the customer migration", "Wanted to send a quick note expressing gratitude for your hard work on the database migration over the weekend.", 0),
    ("Office building maintenance schedule", "Please be advised that the building elevators will undergo routine quarterly maintenance on Saturday morning.", 0),
    ("Team coffee break tomorrow", "Let's take a 15-minute coffee break tomorrow at 10 AM to welcome our new frontend intern to the team.", 0),
    ("Customer support ticket #8210 resolved", "The reported billing anomaly for customer ACME Corp has been investigated and resolved in the database.", 0),
    ("Quarterly company all-hands calendar invite", "The leadership team invites everyone to our quarterly all-hands meeting next Tuesday at 2 PM PST.", 0),
    ("Research paper on graph neural networks", "Thought you might find this recent publication on graph learning interesting given our current fraud detection work.", 0),
    ("New coffee machine instructions", "A new espresso machine has been installed in the kitchen. Please read the quick instruction card before first use.", 0),
    ("Interview feedback form for candidate", "Please remember to submit your interview scorecards and notes for the senior backend developer candidate by EOD.", 0),
    ("Order confirmation: Office supplies delivered", "Your requested standing desk converter has arrived at the reception desk. You can pick it up anytime today.", 0),
    ("Flight itinerary for upcoming business trip", "Here is the finalized travel itinerary and hotel booking confirmation for the security summit in Chicago.", 0),
    ("Volunteer day opportunities this autumn", "Our community outreach team has organized three volunteer service projects this month. Review the sign-up sheet.", 0),
    ("Weekly security metrics dashboard", "The weekly vulnerability triage dashboard shows 100% of critical patches were applied within our 7-day SLA.", 0),
]


def train_email_model(output_path: str = None) -> Pipeline:
    """Train TF-IDF + Logistic Regression model on email subject and body texts."""
    if output_path is None:
        project_root = Path(__file__).resolve().parent.parent.parent.parent
        output_path = project_root / "backend" / "models" / "email_model.joblib"
    else:
        output_path = Path(output_path)

    # Combine subject and body text into a single representation
    texts = [f"{subject} {body}" for subject, body, _ in TRAINING_DATA]
    labels = [label for _, _, label in TRAINING_DATA]

    # Split for validation
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.25, random_state=42, stratify=labels
    )

    # Create NLP pipeline
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),
            sublinear_tf=True,
            max_features=5000,
            lowercase=True
        )),
        ("classifier", LogisticRegression(
            C=1.5,
            max_iter=1000,
            solver="lbfgs",
            random_state=42
        ))
    ])

    print(f"Training email NLP classifier on {len(X_train)} samples...")
    pipeline.fit(X_train, y_train)

    # Evaluate
    predictions = pipeline.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)
    print(f"Validation Accuracy: {accuracy * 100:.2f}%")
    print(classification_report(y_test, predictions, target_names=["Benign", "Phishing"]))

    # Fit on all samples for maximum vocabulary coverage in production
    pipeline.fit(texts, labels)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, output_path)
    print(f"Email NLP model saved successfully to: {output_path}")

    return pipeline


if __name__ == "__main__":
    train_email_model()
