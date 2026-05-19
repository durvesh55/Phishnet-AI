# 🛡️ PhishNet AI — Production Deployment Guide
### PostgreSQL (Supabase) + Render Hosting

---

## 📁 Project Structure

```
phishnet-live/
├── app.py                  ← Flask app (PostgreSQL ready)
├── wsgi.py                 ← Gunicorn entry point
├── requirements.txt        ← All dependencies
├── render.yaml             ← Render auto-deploy config
├── .env.example            ← Environment variable template
├── model/
│   └── train_model.py
├── templates/
│   ├── login.html
│   ├── register.html
│   └── dashboard.html
└── static/
    ├── css/
    └── js/
```

---

## 🗄️ STEP 1 — Setup PostgreSQL on Supabase (Free)

1. Go to **https://supabase.com** → Sign up free
2. Click **"New Project"**
   - Name: `phishnet`
   - Set a strong DB password (save it!)
   - Region: pick closest to you
3. Wait ~2 minutes for project to start
4. Go to **Settings → Database**
5. Scroll to **"Connection string"** → select **URI**
6. Copy the string — looks like:
   ```
   postgresql://postgres:[YOUR-PASSWORD]@db.xxxx.supabase.co:5432/postgres
   ```
7. **Save this** — you'll need it in Step 2

---

## 🚀 STEP 2 — Deploy on Render (Free)

### Option A — Auto Deploy (Easiest)
1. Push your project to **GitHub**
   ```bash
   git init
   git add .
   git commit -m "PhishNet AI initial commit"
   git remote add origin https://github.com/YOUR_USERNAME/phishnet-ai.git
   git push -u origin main
   ```

2. Go to **https://render.com** → Sign up free
3. Click **"New +"** → **"Web Service"**
4. Connect your GitHub → select `phishnet-ai` repo
5. Fill in settings:
   | Setting | Value |
   |---|---|
   | Name | phishnet-ai |
   | Runtime | Python 3 |
   | Build Command | `pip install -r requirements.txt && python model/train_model.py` |
   | Start Command | `gunicorn wsgi:app` |
   | Instance Type | Free |

6. Click **"Advanced"** → **"Add Environment Variable"**:
   | Key | Value |
   |---|---|
   | `DATABASE_URL` | *(paste your Supabase URI from Step 1)* |
   | `SECRET_KEY` | *(any long random string e.g. `phishnet-secret-2024-xyz`)* |

7. Click **"Create Web Service"**
8. Wait ~3 minutes → your app will be live at:
   ```
   https://phishnet-ai.onrender.com
   ```

---

## 🔑 Environment Variables Reference

| Variable | Description | Example |
|---|---|---|
| `DATABASE_URL` | Supabase PostgreSQL URI | `postgresql://postgres:pass@db.xxx.supabase.co:5432/postgres` |
| `SECRET_KEY` | Flask session secret | `any-long-random-string` |

---

## 🧪 Test Locally with PostgreSQL

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Fill in your values in `.env`:
   ```
   SECRET_KEY=my-local-secret-key
   DATABASE_URL=postgresql://postgres:password@db.xxx.supabase.co:5432/postgres
   ```

3. Install and run:
   ```bash
   pip install -r requirements.txt
   python model/train_model.py
   python app.py
   ```

---

## ✅ Post-Deployment Checklist

- [ ] App loads at your Render URL
- [ ] Register a new account
- [ ] Login works
- [ ] Paste a phishing email → get PHISHING verdict
- [ ] Scan history saves correctly
- [ ] Check Supabase dashboard → Tables → data appears

---

## 🔧 Troubleshooting

**App crashes on Render?**
→ Check Render logs → most common issue is wrong `DATABASE_URL`

**`psycopg2` error?**
→ Make sure `psycopg2-binary` is in `requirements.txt` ✓

**Tables not created?**
→ The app auto-creates tables on first run via `db.create_all()`

**Render free tier sleeps after 15 min of inactivity**
→ First request after sleep takes ~30 seconds. Upgrade to paid ($7/mo) to avoid this.

---

## 🌐 After Going Live

Share your URL:
```
https://phishnet-ai.onrender.com
```

Anyone can register and use PhishNet AI from anywhere in the world! 🌍
