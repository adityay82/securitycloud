# AWS Deployment Guide — CloudSec Platform

## Architecture Overview

```
Internet → Route 53 → Elastic Load Balancer
                             ↓
                      EC2 (Ubuntu 22.04)
                      Nginx → Gunicorn → Django
                             ↓          ↓
                           S3 Bucket   RDS MySQL
                         (Encrypted    (User data,
                          file store)   logs, etc.)
```

---

## Step 1: Launch EC2 Instance

### AWS Console → EC2 → Launch Instance

```
AMI:          Ubuntu Server 22.04 LTS
Instance Type: t3.small (2 vCPU, 2 GB RAM) — minimum
              t3.medium recommended for production
Storage:      20 GB gp3
Key Pair:     Create or use existing .pem key
```

### Security Group Rules

| Type | Protocol | Port | Source | Purpose |
|------|----------|------|--------|---------|
| SSH | TCP | 22 | Your IP only | Server management |
| HTTP | TCP | 80 | 0.0.0.0/0 | Web traffic |
| HTTPS | TCP | 443 | 0.0.0.0/0 | Secure web traffic |
| Custom TCP | TCP | 8000 | Your IP | Django dev (optional) |

---

## Step 2: Server Setup

```bash
# SSH into EC2
ssh -i your-key.pem ubuntu@your-ec2-public-ip

# Update packages
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3.10 python3.10-venv python3-pip \
    nginx mysql-client libmysqlclient-dev \
    git certbot python3-certbot-nginx

# Create app user
sudo adduser --system --group cloudsec
sudo mkdir -p /var/www/cloudsec
sudo chown cloudsec:cloudsec /var/www/cloudsec
```

---

## Step 3: Deploy Application

```bash
# Switch to app directory
cd /var/www/cloudsec

# Clone repository
sudo -u cloudsec git clone https://github.com/yourusername/cloudsec-platform.git .

# Create virtualenv
sudo -u cloudsec python3 -m venv venv
sudo -u cloudsec venv/bin/pip install -r requirements.txt

# Configure environment
sudo -u cloudsec cp .env.example .env
sudo nano .env   # Fill in production values
```

### Production .env values:
```ini
SECRET_KEY=generate-with-python-secrets-module
DEBUG=False
ALLOWED_HOSTS=your-domain.com,your-ec2-ip

# Email
EMAIL_HOST=smtp.gmail.com
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password

# RDS MySQL
DB_NAME=cloudsec_prod
DB_USER=cloudsec_user
DB_PASSWORD=strong-password-here
DB_HOST=your-rds-endpoint.rds.amazonaws.com
DB_PORT=3306

# S3
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_STORAGE_BUCKET_NAME=cloudsec-files-prod
AWS_S3_REGION_NAME=us-east-1
```

```bash
# Run setup
sudo -u cloudsec venv/bin/python manage.py migrate
sudo -u cloudsec venv/bin/python manage.py create_admin
sudo -u cloudsec venv/bin/python manage.py collectstatic --noinput
```

---

## Step 4: Configure AWS RDS (MySQL)

```
Engine:       MySQL 8.0
Instance:     db.t3.micro (free tier) / db.t3.small (production)
Storage:      20 GB gp2
DB Name:      cloudsec_prod
Master user:  cloudsec_user
```

### RDS Security Group
- Allow MySQL (port 3306) from EC2 security group only

### In settings.py, uncomment MySQL config:
```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': config('DB_NAME'),
        'USER': config('DB_USER'),
        'PASSWORD': config('DB_PASSWORD'),
        'HOST': config('DB_HOST'),
        'PORT': config('DB_PORT', default='3306'),
    }
}
```

---

## Step 5: Configure AWS S3

### Create S3 Bucket
```
Bucket name:      cloudsec-files-prod
Region:           us-east-1
Block all public access: YES (private bucket)
Versioning:       Enable (recommended)
```

### IAM Policy for EC2/S3 Access
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::cloudsec-files-prod",
        "arn:aws:s3:::cloudsec-files-prod/*"
      ]
    }
  ]
}
```

### In settings.py, uncomment S3 storage:
```python
DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'
```

---

## Step 6: Configure Gunicorn

```bash
# Create Gunicorn systemd service
sudo nano /etc/systemd/system/cloudsec.service
```

```ini
[Unit]
Description=CloudSec Gunicorn Daemon
After=network.target

[Service]
User=cloudsec
Group=cloudsec
WorkingDirectory=/var/www/cloudsec
ExecStart=/var/www/cloudsec/venv/bin/gunicorn \
    --access-logfile - \
    --workers 3 \
    --bind unix:/run/cloudsec/cloudsec.sock \
    cloudsec.wsgi:application
RuntimeDirectory=cloudsec
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable cloudsec
sudo systemctl start cloudsec
sudo systemctl status cloudsec
```

---

## Step 7: Configure Nginx

```bash
sudo nano /etc/nginx/sites-available/cloudsec
```

```nginx
server {
    listen 80;
    server_name your-domain.com www.your-domain.com;

    client_max_body_size 100M;

    location = /favicon.ico { access_log off; log_not_found off; }

    location /static/ {
        alias /var/www/cloudsec/staticfiles/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    location /media/ {
        alias /var/www/cloudsec/media/;
    }

    location / {
        include proxy_params;
        proxy_pass http://unix:/run/cloudsec/cloudsec.sock;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/cloudsec /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## Step 8: SSL Certificate (HTTPS)

```bash
sudo certbot --nginx -d your-domain.com -d www.your-domain.com
sudo systemctl status certbot.timer   # Auto-renewal
```

---

## Step 9: Security Hardening

```bash
# Firewall
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable

# Fail2ban (brute force protection)
sudo apt install fail2ban -y
sudo systemctl enable fail2ban

# Set production settings
# In .env: DEBUG=False
# In settings.py: SECURE_SSL_REDIRECT=True (already configured)
```

---

## Deployment Checklist

- [ ] DEBUG=False in production
- [ ] ALLOWED_HOSTS set correctly
- [ ] SECRET_KEY is unique and secret
- [ ] Database migrated
- [ ] Static files collected
- [ ] S3 bucket configured (private)
- [ ] RDS security group restricts to EC2 only
- [ ] SSL certificate installed
- [ ] Firewall configured
- [ ] Admin password changed from default
- [ ] Email SMTP configured and tested
- [ ] Gunicorn service running
- [ ] Nginx proxy working
- [ ] Fail2ban active

---

## Monitoring

```bash
# Application logs
sudo journalctl -u cloudsec -f

# Nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log

# Django logs
tail -f /var/www/cloudsec/logs/django.log
```
