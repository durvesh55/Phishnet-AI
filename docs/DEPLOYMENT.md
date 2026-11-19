# Deployment

Nothing has been deployed by this project; these are instructions for you to follow.

## Topology
```
Internet ─HTTPS→ Nginx (TLS, redirect 80→443) ─→ Gunicorn :8000 (127.0.0.1) ─→ MySQL 8 (private) / Redis (private)
```
## Docker Compose (single host)
1. `cp .env.example .env`; set `FLASK_ENV=production`, a 64-hex `SECRET_KEY`, `MYSQL_PASSWORD`, `MYSQL_ROOT_PASSWORD`, `BASE_URL=https://your.domain`, `MAIL_BACKEND=smtp` + `MAIL_*`.
2. `docker compose up -d --build` — the web container runs `flask db upgrade`, registers the model, then Gunicorn. The image trains a bootstrap model at build time if none is shipped (replace it with a properly trained one: see ML_PIPELINE.md).
3. Local HTTP trial only: `FLASK_ENV=development` (production sets Secure cookies and needs HTTPS).

## Nginx (example)
```nginx
server {
  listen 443 ssl http2; server_name your.domain;
  ssl_certificate     /etc/letsencrypt/live/your.domain/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/your.domain/privkey.pem;
  client_max_body_size 300k;
  location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;   # overwrite, do not append client-supplied values
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
server { listen 80; server_name your.domain; return 301 https://$host$request_uri; }
```
The app trusts exactly one proxy hop (`TRUSTED_PROXY_HOPS`, default 1 in production).

## Without Docker
Python 3.12 venv → `pip install -r requirements.txt` → set env → `flask --app run db upgrade` → `python -m ml.training.train` → `gunicorn -w 3 -b 127.0.0.1:8000 run:app` under systemd.

## Operations
* Probes: `/health` (liveness), `/ready` (DB, model, Redis; 503 if degraded).
* Scheduled retention: `flask --app run purge-expired` daily (cron).
* Backups: see DATABASE_SCHEMA.md.
* Firewall: expose only 80/443; never publish 3306/6379.

## CI/CD secrets
`.github/workflows/ci.yml` uses only throw-away values for its service container. For deployment jobs add secrets under *Repository → Settings → Secrets and variables → Actions* (e.g. `SSH_HOST`, `SSH_KEY`, `PROD_ENV_FILE`) and reference them as `${{ secrets.NAME }}`; never commit them.
