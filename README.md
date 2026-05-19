# 🛡️ PhishNet AI — Complete Phishing Detection System

Full-stack AI-powered phishing email detection with ML, authentication, admin panel, API access, and PDF/CSV export.

---

## 🚀 Quick Start (Local)

```bash
pip install -r requirements.txt
python model/train_model.py
python app.py
# Open: http://localhost:5000
```

---

## 📁 Project Structure

```
phishnet-final/
├── app.py                  ← Flask backend (all routes + ML)
├── wsgi.py                 ← Gunicorn entry point (production)
├── requirements.txt        ← All dependencies
├── render.yaml             ← Render auto-deploy config
├── .env.example            ← Environment variable template
├── model/
│   └── train_model.py      ← ML trainer (run once)
├── templates/
│   ├── login.html          ← Login page with 2FA OTP
│   ├── register.html       ← Registration page
│   └── dashboard.html      ← Main dashboard
└── static/
    ├── css/auth.css        ← Auth page styles
    ├── css/dashboard.css   ← Dashboard styles
    └── js/dashboard.js     ← All frontend logic
```

---

## ✨ Features

| Feature | Details |
|---|---|
| ML Detection | TF-IDF + Logistic Regression, 0–100% risk score |
| Confidence Score | Shows model confidence % |
| Keyword Highlighting | Shows which words triggered detection |
| Header Analysis | Extracts & checks From, Subject, Domain |
| 2FA Login | OTP-based two-factor authentication |
| SHA-256 Auth | Secure password hashing |
| Rate Limiting | Brute-force & spam protection |
| Scan History | Full audit trail per user |
| Feedback System | Mark verdicts correct/wrong |
| 7-Day Trend Chart | Canvas-based scan activity graph |
| Export CSV | Download full scan history |
| Export PDF | Professional report via ReportLab |
| API Key Access | Integrate via REST API with X-API-Key header |
| Admin Panel | View all users & global stats (first user = admin) |
| PostgreSQL Ready | Supabase + Render deployment |

---

## 🌐 Deploy to Production (Free)

### Step 1 — Supabase (PostgreSQL)
1. Go to https://supabase.com → New Project
2. Settings → Database → copy Connection URI

### Step 2 — Render
1. Push to GitHub
2. render.com → New Web Service → connect repo
3. Build: `pip install -r requirements.txt && python model/train_model.py`
4. Start: `gunicorn wsgi:app`
5. Add env vars: `DATABASE_URL` + `SECRET_KEY`
6. Deploy → live at `https://phishnet-ai.onrender.com`

---

## 🔌 API Usage

```bash
# Analyze an email via API
curl -X POST https://your-app.onrender.com/api/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"email_text": "Your email content here"}'
```

---

## 🛠 Tech Stack

`Python` · `Flask` · `SQLAlchemy` · `SQLite/PostgreSQL` · `Scikit-learn` · `ReportLab` · `HTML/CSS/JS`
