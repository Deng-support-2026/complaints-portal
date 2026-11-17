# Student Complaints Portal (Option A)

Flask + SQLite. Roles: student, staff, admin.

## Install & run
```bash
python -m venv venv && source venv/bin/activate     # Windows: venv\Scripts\activate
pip install flask
export SECRET_KEY=$(python -c "import secrets;print(secrets.token_hex(32))")
export FLASK_APP=app.py
flask init-db
flask run
```
Open http://127.0.0.1:5000. Behind HTTPS set `COOKIE_SECURE=1`.

## Test accounts (demo only)
| Role    | Username | Password        |
|---------|----------|-----------------|
| Student | deng     | Student#2026pw  |
| Student | john     | Student#2026pw  |
| Staff   | sarah    | Staff#2026pw!   |
| Admin   | admin    | Admin#2026pw!   |

## Security controls
- scrypt password hashing, strength policy, lockout after 5 failures, generic errors
- Session: HttpOnly/SameSite cookies, 30 min expiry, session reset on login
- CSRF token on every POST
- Server-side RBAC + object-level checks (students see only own complaints)
- Parameterised SQL only; Jinja autoescape (XSS); security headers + CSP
- Uploads: allowlist, magic-byte check, 2 MB cap, random names, stored outside web root, authorised download
- Secrets via environment variables; `debug=False`
- `security.log`: logins, denials, IDOR attempts, CSRF failures, rejected uploads

## Testing
```bash
pip install bandit && bandit -r app.py
# ZAP: run baseline scan against http://127.0.0.1:5000 with an authenticated context
```
