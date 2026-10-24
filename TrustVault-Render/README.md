# TrustVault — Render deployment

## Deploy
1. Extract this ZIP and push its contents to a GitHub repository.
2. In Render, choose **New → Blueprint**, select the repository, and deploy `render.yaml`.
3. Set `BOOTSTRAP_ADMIN_PASSWORD` to a strong unique password (16+ characters) when prompted.
4. Open the generated Render URL and sign in as `admin` with that password.
5. Create `owner` and `viewer` accounts under **Users**.

The Blueprint provisions a persistent disk at `/var/data`; charges may apply.

## Roles
- **Admin:** all documents, user administration, audit view.
- **Owner:** upload/manage own documents and grant/revoke per-document access.
- **Viewer:** read explicitly shared documents. An `edit` grant permits metadata edits.
- Every document route performs server-side authorization. Unauthorized IDs return 404.
- Revocation is checked against the database on each request. It cannot recall files already downloaded.

## Included controls
Password hashing, encrypted-at-rest file blobs (Fernet), allow-listed extensions, upload size limit, SHA-256 integrity verification, per-document read/edit grants, success/denial audit events, HMAC-SHA256 chained audit records, search by name/category, and admin activity view.

## Local run
```bash
pip install -r requirements.txt
# Set unique APP_SECRET, FILE_MASTER_KEY, AUDIT_HMAC_KEY and BOOTSTRAP_ADMIN_PASSWORD
python app.py
```

## Production limitations
This is a hackathon MVP, not a certified security product. Add CSRF protection, MFA/SSO, rate limiting, content-based MIME validation, malware scanning, immutable external audit export, backups, key rotation, monitoring, and penetration testing. HMAC chaining is tamper-evident only while the key is protected; store checkpoints outside the app/database. The audit UI shows the latest 500 events. Do not use default development secrets in production.
