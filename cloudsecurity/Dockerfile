# ──────────────────────────────────────────────────────────────────────────
# CloudSec Production Dockerfile
# ──────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim-bullseye

LABEL maintainer="CloudSec Team"
LABEL description="CloudSec — Cloud Security Platform with Adaptive MFA & ML"

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    gettext \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Create non-root user
RUN addgroup --system cloudsec && adduser --system --group cloudsec

# Create required directories
RUN mkdir -p media staticfiles logs ml_module/models && \
    chown -R cloudsec:cloudsec /app

USER cloudsec

# Collect static files
RUN python manage.py collectstatic --noinput

EXPOSE 8000

# Use gunicorn in production
CMD ["gunicorn", "cloudsec.wsgi:application", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "4", \
     "--threads", "2", \
     "--worker-class", "gthread", \
     "--timeout", "120", \
     "--access-logfile", "logs/gunicorn_access.log", \
     "--error-logfile", "logs/gunicorn_error.log"]
