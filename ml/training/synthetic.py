"""Template-based SYNTHETIC email generator used to bootstrap the model.

IMPORTANT: this data is machine-generated from hand-written templates. It is NOT
real-world email. Metrics measured on it are optimistic and say little about
real-world accuracy. Replace/augment it with a properly sourced, licensed
corpus (see docs/ML_PIPELINE.md, "Importing a real dataset").
"""
from __future__ import annotations

import random

BRANDS = ["PayPal", "Amazon", "Microsoft", "Apple", "Netflix", "Google", "DHL", "Chase Bank", "Facebook", "DocuSign", "LinkedIn", "Dropbox"]
SPOOF_DOMAINS = ["paypa1-secure.com", "micros0ft-verify.tk", "amazon-billing.xyz", "app1e-id-support.ru", "g00gle-account.cc", "secure-login-update.top",
                 "netfIix-billing.com", "dhl-redelivery.xyz", "chase-secure-alerts.pw", "docusign-review.click", "bit.ly/3xRq9z", "tinyurl.com/acct-restore", "192.168.44.12/login"]
GOOD_DOMAINS = ["github.com", "docs.company.com", "calendar.google.com", "intranet.example.org", "zoom.us/j/123456789", "www.wikipedia.org"]
NAMES = ["Sarah", "Michael", "Priya", "David", "Elena", "Tom", "Aisha", "Carlos", "Mei", "Jonas"]
AMOUNTS = ["$149.99", "$2,350.00", "$89.00", "$4,999", "$320.45"]
TOPICS = ["Q3 budget review", "onboarding plan", "sprint retrospective", "vendor contract", "customer workshop", "annual leave schedule", "release checklist", "design review", "hiring panel", "security training"]

PHISH = [
    "URGENT: Your {b} account has been suspended. Verify your password immediately at http://{d} or it will be permanently deleted.",
    "Dear Customer, we detected suspicious activity on your {b} account. Click here to confirm your identity: http://{d}",
    "{b} Security Alert: unusual sign-in. Enter your password and credit card number at http://{d} within 24 hours to restore access.",
    "FINAL NOTICE: Your payment of {a} failed. Update your billing details now at http://{d} to avoid account termination.",
    "Congratulations! You have been selected to receive a {a} reward from {b}. Claim your prize now: http://{d}. Limited time offer!",
    "Your {b} package could not be delivered. Pay a small customs fee of $2.99 at http://{d} to schedule redelivery.",
    "Action required: confirm your {b} account or it will be locked. Provide your SSN and bank details to verify your identity.",
    "Dear user, your mailbox storage is full and will be closed. Re-enter your login credentials at http://{d} to keep your emails.",
    "{b} Invoice overdue {a}. Open the attached invoice.pdf.exe and sign in with your password to view the payment details.",
    "We noticed a login from a new device. If this wasn't you, verify your account at http://{d} immediately and enter the one-time code we texted you.",
    "Your tax refund of {a} is pending. Submit your social security number and card number at http://{d} to receive the transfer.",
    "Hello, I am a prince with an inheritance of {a}. Reply with your bank account number and a processing fee via wire transfer or gift cards.",
    "IT Helpdesk: your password expires today. Click here to keep your password: http://{d}. Failure to act will lock your account.",
    "{b} Support: your account has been limited. Confirm your PIN and security questions at http://{d} now.",
    "Voicemail from {n} could not be played. Sign in with your email password at http://{d} to listen. Act now.",
    "Shared document: 'Salary_Review.html' needs your {b} login. Verify your account at http://{d} to open the file.",
]
HAM = [
    "Hi {n}, reminder that the {t} is on Thursday at 3 PM in Conference Room B. Please bring your updates.",
    "Hello team, attached is the agenda for the {t}. Let me know if you would like to add anything before the meeting.",
    "Hi {n}, thanks for the update. I reviewed the {t} document and left comments in the shared folder at https://{g}.",
    "Your order #48213 has shipped and should arrive on Friday. You can track it from your account dashboard at https://{g}.",
    "Thanks for your payment of {a}. Your receipt is attached for your records. No further action is needed.",
    "Hi {n}, are you free for a quick call tomorrow to align on the {t}? Happy to work around your schedule.",
    "Weekly newsletter: this month's engineering blog covers CI pipelines, load testing and code review tips. Read more at https://{g}.",
    "Welcome to the team, {n}! Your onboarding schedule and first-week plan are attached. See you Monday.",
    "Your password was successfully changed. If you did not make this change, contact our support team through the official app.",
    "Calendar invite: {t} on Tuesday at 10:30 AM. Zoom link: https://{g}. Please accept if you can attend.",
    "Hi {n}, please find the minutes of the {t} below. Action items are assigned in the tracker. Best regards, {n2}.",
    "Your flight booking is confirmed. The itinerary is attached. Have a great trip, and let us know if plans change.",
    "Reminder: the library book you borrowed is due next week. You can renew it online or at the front desk.",
    "Great work on the release, {n}! The {t} went smoothly and customers have been happy. Kind regards, {n2}.",
    "Code review requested: please look at pull request 128 for the new authentication module when you get a chance.",
    "Security notice: we updated our privacy policy effective next month. No action is required; read the summary at https://{g}.",
]


def generate(n_per_class: int = 600, seed: int = 42) -> list[tuple[str, int]]:
    rng = random.Random(seed)
    rows: list[tuple[str, int]] = []
    for _ in range(n_per_class):
        t = rng.choice(PHISH).format(b=rng.choice(BRANDS), d=rng.choice(SPOOF_DOMAINS), a=rng.choice(AMOUNTS), n=rng.choice(NAMES))
        rows.append((t, 1))
        h = rng.choice(HAM).format(n=rng.choice(NAMES), n2=rng.choice(NAMES), t=rng.choice(TOPICS), g=rng.choice(GOOD_DOMAINS), a=rng.choice(AMOUNTS))
        rows.append((h, 0))
    return rows
