# CloudSec — Viva Questions & Answers

## Section 1: Project Overview

**Q1. What is the objective of your project?**  
A: The project aims to enhance cloud security by implementing a three-level Multi-Factor Authentication system combined with an Adaptive Cryptography module and a Machine Learning-based threat detection engine. The system protects user accounts and files from unauthorized access in cloud environments.

**Q2. What problem does your project solve?**  
A: Traditional username-password authentication is vulnerable to brute force, credential stuffing, and phishing attacks. Static encryption also doesn't adapt to file sensitivity. Our system solves both: MFA prevents unauthorized access even if credentials are compromised, adaptive cryptography ensures appropriate security strength, and ML detects suspicious patterns that rule-based systems would miss.

**Q3. What is the significance of combining MFA with ML?**  
A: Standard MFA is static — it always requires the same steps. By incorporating ML-based risk scoring, the system adds a dynamic "Level 3" that only triggers additional verification when suspicious behavior is detected. This improves security without sacrificing user experience during normal logins.

---

## Section 2: Multi-Factor Authentication

**Q4. Explain the three levels of MFA in your system.**  
A:  
- **Level 1 (Knowledge Factor):** Username + password — traditional credential check with account lockout after 5 failed attempts.  
- **Level 2 (Possession Factor):** Email OTP — a 6-digit code sent to the registered email, valid for 10 minutes.  
- **Level 3 (Behavior Factor):** ML Risk-Based — if the ML model assigns a risk score ≥ 0.7, an additional OTP is required and the event is logged as suspicious.

**Q5. How is the OTP generated and what makes it secure?**  
A: OTPs are generated using Python's `secrets` module, which provides cryptographically secure random numbers (uses OS entropy sources, not `random`). Each OTP is 6 digits, has a 10-minute expiry, is single-use (marked as used after first successful verification), allows maximum 3 verification attempts before being invalidated, and old OTPs for the same purpose are invalidated when a new one is issued.

**Q6. What happens if the OTP expires?**  
A: The user can request a new OTP using the "Resend OTP" button. The existing unverified OTPs for that purpose are invalidated in the database before a new one is generated and emailed.

**Q7. How does account lockout work?**  
A: After 5 consecutive failed login attempts, the `account_locked_until` field is set to 30 minutes in the future. All subsequent login attempts check this field and reject the attempt with a message until the lockout period expires.

---

## Section 3: Adaptive Cryptography

**Q8. What is adaptive cryptography and why did you implement it?**  
A: Adaptive cryptography automatically selects the appropriate encryption strength based on the file size. The rationale is that larger files typically represent more valuable or complex data, and also that AES-256 has higher computational cost. Smaller files can be encrypted quickly with AES-128, while large files warrant the stronger AES-256. This balances security and performance.

**Q9. Explain AES-CBC mode.**  
A: AES (Advanced Encryption Standard) in CBC (Cipher Block Chaining) mode is a symmetric block cipher. In CBC mode, each 16-byte plaintext block is XORed with the previous ciphertext block before encryption. This means identical plaintext blocks produce different ciphertext, preventing pattern analysis. A random Initialization Vector (IV) is used for the first block, and we store it alongside the encrypted file for decryption.

**Q10. How do you select between AES-128, AES-192, and AES-256?**  
A:  
- Files < 1 MB → AES-128 (16-byte key, 10 encryption rounds)  
- Files 1–10 MB → AES-192 (24-byte key, 12 encryption rounds)  
- Files > 10 MB → AES-256 (32-byte key, 14 encryption rounds)  
The key is generated using `secrets.token_bytes()` for cryptographic randomness.

**Q11. How is file integrity verified?**  
A: Before encryption, a SHA-256 hash of the original file data is computed and stored in the database. During decryption, a new SHA-256 hash is computed on the decrypted data and compared with the stored hash. If they don't match, the file may have been tampered with and the user is alerted.

**Q12. Where is the encryption key stored? Is this secure?**  
A: Currently the key is stored as a hex string in the SQLite database, which is acceptable for a development/demo environment. In production, keys should be stored in AWS Key Management Service (KMS) or HashiCorp Vault, which provides hardware security module (HSM) backed key storage and access control. The application would fetch the key from KMS on demand rather than storing it directly.

---

## Section 4: Machine Learning

**Q13. What ML algorithms did you use and why?**  
A: We used **Random Forest** as the primary model and **Logistic Regression** as a comparison baseline.  
- **Random Forest** was chosen because it handles non-linear relationships, is robust to outliers, provides feature importance scores, and performs well on tabular data without extensive preprocessing.  
- **Logistic Regression** provides a linear baseline and is highly interpretable, useful for explaining predictions to non-technical stakeholders.

**Q14. What features does your ML model use for risk prediction?**  
A: Seven features:  
1. **Login Hour** — logins at unusual hours (midnight–6am) are riskier  
2. **Day of Week** — weekend logins may indicate anomaly  
3. **Failed Attempts** — prior failures increase suspicion score  
4. **Session Duration** — very short sessions may indicate scripted attacks  
5. **Device Type** — encoded as Desktop=1, Mobile=2, Tablet=3, Unknown=0  
6. **Browser Type** — Chrome=1, Firefox=2, Safari=3, Edge=4, Unknown=0  
7. **IP Changed** — binary flag if IP differs from the user's typical IP

**Q15. What is your model's accuracy and how did you evaluate it?**  
A: The Random Forest model achieves approximately 95% accuracy on a 20% held-out test set. We evaluate using:  
- **Accuracy** — overall correct predictions  
- **Precision** — of predicted suspicious logins, how many are actually suspicious  
- **Recall** — of actual suspicious logins, how many did the model catch  
- **Confusion Matrix** — shows True Positives, False Positives, True Negatives, False Negatives

**Q16. What is the training dataset?**  
A: For this prototype, we generate a synthetic dataset of 2000 login records with realistic distributions — normal logins are clustered in business hours (9am–9pm) with low failure counts, while suspicious logins are generated for unusual hours, high failure counts, and IP changes. In a production system, this would be replaced with real login history from the database after sufficient data collection.

**Q17. What is overfitting and how did you prevent it?**  
A: Overfitting occurs when a model learns the training data too well and fails to generalize to new data. We prevented it by:  
- Using train/test split (80/20) with `random_state=42` for reproducibility  
- Limiting Random Forest `max_depth=10` to prevent over-complex trees  
- Using `class_weight='balanced'` to handle class imbalance  
- Adding 5% label noise to the synthetic dataset for realism

---

## Section 5: Cloud & Architecture

**Q18. How is your project cloud-ready?**  
A:  
- **AWS EC2:** The Django app runs on Gunicorn behind Nginx on any Linux EC2 instance  
- **AWS S3:** `django-storages` with `S3Boto3Storage` is pre-configured — uncomment two lines to switch file storage from local to S3  
- **AWS RDS:** MySQL configuration is pre-written in settings.py — switch from SQLite by uncommenting the MySQL `DATABASES` config  
- **Environment variables:** All secrets are in `.env` using `python-decouple`, making the app 12-factor compliant  
- **WhiteNoise:** Static files are served efficiently without a separate static file server

**Q19. Explain the role of Nginx and Gunicorn.**  
A:  
- **Gunicorn** (Green Unicorn) is a Python WSGI HTTP server that runs the Django application. It handles multiple concurrent requests using worker processes.  
- **Nginx** acts as a reverse proxy in front of Gunicorn. It handles static file serving (which Gunicorn shouldn't do), SSL termination, load balancing, request buffering, and security headers. This architecture is the industry standard for Django deployment.

**Q20. What security headers does your application set?**  
A: In production (`DEBUG=False`), the application sets:  
- `X-XSS-Protection` via `SECURE_BROWSER_XSS_FILTER`  
- `X-Content-Type-Options: nosniff`  
- `X-Frame-Options: DENY` (prevents clickjacking)  
- `Strict-Transport-Security` (HSTS, 1 year)  
- `CSRF` cookies are `HttpOnly` and `Secure`  
- `SESSION_COOKIE_SECURE=True`

---

## Section 6: Database & Design

**Q21. Why did you use a UUID primary key instead of integer?**  
A: UUIDs (Universally Unique Identifiers) are 128-bit random values that:  
- Cannot be guessed or enumerated (unlike sequential integers like `/user/1/`, `/user/2/`)  
- Prevent IDOR (Insecure Direct Object Reference) attacks  
- Work across distributed systems without collision  
- Don't reveal the number of records in the database

**Q22. What is Role-Based Access Control (RBAC) and how is it implemented?**  
A: RBAC restricts system access based on user roles. We have two roles:  
- **Admin:** Can view all users, all files, approve/suspend users, view all audit logs, and access security events  
- **User:** Can only see their own files, logs, and dashboard  
Implementation uses a `role` field on `CustomUser` and decorators/checks in views: `if request.user.role != 'admin': return redirect(...)`. Django's built-in `@login_required` handles authentication, and our custom checks handle authorization.

---

## Section 7: General Security

**Q23. What is CSRF and how does Django handle it?**  
A: Cross-Site Request Forgery (CSRF) tricks authenticated users into submitting malicious requests. Django includes a `CsrfViewMiddleware` that:  
- Generates a unique token per session  
- Embeds it as a hidden field in forms via `{% csrf_token %}`  
- Validates it on every POST request  
- Rejects requests without a valid token

**Q24. What is SQL Injection and how is your app protected?**  
A: SQL Injection inserts malicious SQL code into queries to manipulate the database. Django's ORM (Object-Relational Mapper) completely prevents this by using parameterized queries — all user input is treated as data, never as SQL code. We never use raw SQL with user input.

**Q25. What future enhancements would you make?**  
A:  
1. Replace synthetic ML dataset with real behavioral data over time  
2. Integrate AWS KMS for encryption key management  
3. Add TOTP (Google Authenticator) as an additional MFA option  
4. Implement anomaly detection using unsupervised learning (Isolation Forest)  
5. Add API rate limiting using Redis  
6. Integrate threat intelligence feeds for IP reputation checking  
7. Add WebAuthn/FIDO2 passwordless authentication  
8. Implement zero-trust network access principles
