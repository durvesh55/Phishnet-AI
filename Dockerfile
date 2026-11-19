FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv/app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
# Train a model at build time ONLY if none was shipped (the model dir is baked into the image).
RUN test -f ml/models/active.json || python -m ml.training.train --min-f1 0.5
RUN useradd --system --uid 10001 --no-create-home phishnet && chown -R phishnet /srv/app/instance 2>/dev/null || true
USER phishnet
ENV FLASK_ENV=production PORT=8000
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=3).status==200 else 1)"
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "60", "--access-logfile", "-", "run:app"]
