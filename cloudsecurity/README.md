# 🛡️ CloudSec — Enhancing Cloud Security using Multi-Factor Authentication, Adaptive Cryptography & Machine Learning

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![Django](https://img.shields.io/badge/Django-4.2-green?logo=django)
![ML](https://img.shields.io/badge/ML-Random_Forest%2C_XGBoost%2C_IsolationForest-orange)
![Security](https://img.shields.io/badge/Security-AES--128%2F192%2F256-critical)
![API](https://img.shields.io/badge/REST_API-JWT_Auth-purple)
![Docker](https://img.shields.io/badge/Docker-Production_Ready-blue?logo=docker)

**An enterprise-grade cloud security platform demonstrating industry-standard security engineering practices, adaptive machine learning threat detection, and adaptive cryptography.**

[Demo](#getting-started) · [Architecture](#architecture) · [API Docs](#rest-api) · [Security Model](#security-model)

</div>

---

## 🎯 Project Overview

CloudSec is a full-stack cloud security platform built for **Final Year Project**, **Internship Presentation**, and **GitHub Portfolio** demonstration. It showcases competency across:

- **Cloud Security Architecture** — Defense in depth, zero-trust principles
- **Multi-Factor Authentication** — Adaptive 3-tier MFA based on ML risk scores
- **Adaptive Cryptography** — Auto-selects AES-128/192/256 based on file size and threat level
- **Machine Learning Security** — 4 trained models for login anomaly detection
- **Intrusion Detection System** — Real-time brute force, IP change, and anomaly detection
- **REST API** — JWT-authenticated endpoints with rate limiting
- **Production Deployment** — Docker, gunicorn, nginx, PostgreSQL ready

---

## 🚀 Key Features

### 🔐 Adaptive Multi-Factor Authentication
- **3-Tier MFA** based on ML risk score:
  - **Low Risk** (< 0.4): Password + Email OTP
  - **Medium Risk** (0.4–0.7): Password + OTP + Security Question
  - **High Risk** (≥ 0.7): Password + OTP + Admin Approval
- **6-digit OTP** with auto-advance UI, AJAX resend, 60s cooldown
- **Brute-force protection**: Progressive delays (2^n seconds), lockout at 5/10/15 attempts
- **Account lockout**: 30 min → 2 hr → 24 hr escalation

### 🤖 Machine Learning Threat Detection
| Model | Purpose | Accuracy |
|---|---|---|
| Random Forest | Primary classifier (ensemble) | ~92% |
| Logistic Regression | Interpretable baseline | ~87% |
| XGBoost | Boosting classifier | ~91% |
| Isolation Forest | Unsupervised anomaly detection | ~85% |

- **Features**: Login hour, day, failed attempts, session duration, device type, browser, IP change
- **Output**: Risk score (0.0–1.0), risk level, probability scores, feature importance
- **Caching**: Models cached in memory — no retraining on page load (critical bug fixed)

### 🔒 Adaptive File Encryption
- **AES-128**: Files < 1MB (fast encryption for small files)
- **AES-192**: Files 1–10MB (balanced performance/security)
- **AES-256**: Files > 10MB OR high-risk login session (maximum security)
- **GCM Mode**: Authenticated encryption with integrity tags
- **SHA-256 Integrity**: Each file has a stored hash for tamper detection
- **Key Wrapping**: AES keys wrapped with master key (AWS KMS ready)

### 🚨 Intrusion Detection System
Automatically detects and creates SecurityEvent records for:
- Brute force attacks (≥5 failures/hr from same IP)
- Multiple auth failures per user (≥3/hr)
- Unusual login hours (00:00–06:00 UTC)
- IP address changes between sessions

### 🌐 REST API
- **17 endpoints** covering auth, files, ML, audit, dashboard
- **JWT Bearer token authentication** (access + refresh tokens)
- **Rate limiting**: 20/min anon, 100/min authenticated
- **CSV audit export** for compliance (SOC 2, ISO 27001)

---

## 🏗️ Architecture

```
cloudsec_project/
├── authentication/          # MFA, OTP, CBV views, user model
│   ├── models.py            # CustomUser (UUID PK), OTPVerification, LoginHistory
│   ├── views.py             # CBVs: Login, Register, VerifyOTP, SecurityQuestion
│   ├── services.py          # AuthenticationService (business logic layer)
│   ├── decorators.py        # @admin_required, @mfa_verified_required
│   └── forms.py             # Registration, OTP, PasswordReset forms
├── encryption/              # Adaptive AES encryption
│   ├── crypto.py            # AES-GCM encrypt/decrypt, key wrapping
│   ├── services.py          # EncryptionService (file validation + storage)
│   ├── models.py            # EncryptedFile (sensitivity, risk score, access count)
│   └── views.py             # CBVs: Upload, Decrypt, Integrity check
├── ml_module/               # ML threat detection
│   ├── predictor.py         # RF + LR + XGBoost + IsolationForest + caching
│   └── views.py             # ML dashboard, metrics API, retrain endpoint
├── audit/                   # Security audit & IDS
│   ├── models.py            # AuditLog, SecurityEvent
│   ├── middleware.py        # AuditMiddleware
│   ├── intrusion_detection.py  # IDS: brute force, IP change, unusual hours
│   └── views.py             # CBVs: logs with pagination/filtering, CSV export
├── dashboard/               # Admin and user dashboards
│   └── views.py             # AdminDashboard, UserDashboard, ApproveUser
├── api/                     # REST API v1
│   ├── views.py             # 17 DRF API endpoints
│   ├── serializers.py       # DRF serializers
│   ├── permissions.py       # IsAdminUser, IsActiveUser, IsFileOwner
│   └── urls.py              # /api/v1/* routes
└── templates/               # Professional dark-mode UI templates
```

---

## ⚡ Getting Started

### Prerequisites
- Python 3.11+
- pip

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/cloudsec-platform.git
cd cloudsec-platform/cloudsec_project

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env — the defaults work for development (SQLite + console email)

# 5. Run migrations
python manage.py migrate

# 6. Create admin user
python manage.py createsuperuser

# 7. Run the development server
python manage.py runserver

# 8. Open http://localhost:8000
```

> **OTP in Development**: With the default console email backend, OTP codes are printed to your terminal. No email setup required!

### Docker Deployment

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f web

# Stop services
docker-compose down
```

---

## 🔌 REST API

Base URL: `http://localhost:8000/api/v1/`

### Authentication Flow
```bash
# 1. Start login (triggers OTP)
POST /api/v1/auth/login/
Body: {"username": "alice", "password": "SecurePass123!"}

# 2. Verify OTP → receive JWT tokens
POST /api/v1/auth/verify-otp/
Body: {"user_id": "<uuid>", "otp_code": "123456", "purpose": "login"}

# 3. Use Bearer token
GET /api/v1/files/
Authorization: Bearer <access_token>
```

### Key Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/auth/register/` | Register new account |
| POST | `/auth/login/` | Initiate MFA login |
| POST | `/auth/verify-otp/` | Complete login → get JWT |
| GET | `/files/` | List encrypted files |
| POST | `/files/upload/` | Upload + encrypt file |
| GET | `/files/{id}/integrity/` | SHA-256 integrity check |
| GET | `/ml/risk-score/` | Real-time risk assessment |
| GET | `/ml/model-metrics/` | Model performance metrics |
| POST | `/ml/retrain/` | Force model retrain (admin) |
| GET | `/audit/logs/` | Paginated audit log |
| GET | `/audit/export/` | CSV audit export |
| GET | `/dashboard/stats/` | Aggregated statistics |

---

## 🔬 Security Model

### Threat Model
| Attack | Defence |
|---|---|
| Brute Force | Progressive delays (2^n sec), lockout at 5/10/15 attempts |
| Credential Stuffing | ML anomaly detection, IP change alerts |
| Session Hijacking | CSRF, Secure/HttpOnly/SameSite cookies |
| OTP Bypass | **REMOVED** — OTP mandatory, not bypassable |
| File Tampering | SHA-256 integrity on every download |
| SQL Injection | Django ORM parameterised queries |
| XSS | Django auto-escape + CSP headers |
| CSRF | Django CSRF middleware on all POST forms |
| File Spoofing | MIME type + magic bytes validation on upload |
| Enumeration | Anti-enumeration: same message for unknown email/user |

### Compliance Alignment
- **ISO 27001**: Audit logs, access control, incident management
- **SOC 2 Type II**: Audit trail CSV export, security event tracking
- **NIST Cybersecurity Framework**: Identify → Protect → Detect → Respond → Recover

---

## 🧪 Tech Stack

| Layer | Technology |
|---|---|
| Backend Framework | Django 4.2 (Python 3.11) |
| REST API | Django REST Framework 3.14 + JWT |
| Machine Learning | Scikit-learn, XGBoost, NumPy, Pandas, Joblib |
| Cryptography | PyCryptodome (AES-GCM, SHA-256) |
| Database | SQLite (dev) / PostgreSQL (prod) |
| Cloud Storage | Local disk (dev) / AWS S3 (prod toggle) |
| Frontend | Bootstrap 5, Chart.js 4, Google Fonts Inter |
| Production Server | gunicorn + nginx |
| Containerisation | Docker + docker-compose |

---

## 📄 License

MIT License — Free for educational and portfolio use.

---

<div align="center">
Built as a Final Year Project demonstrating enterprise cloud security engineering.
</div>
