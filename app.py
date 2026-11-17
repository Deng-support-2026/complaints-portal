"""Student Complaints Portal - secure by design (Flask + SQLite)."""
import os, re, secrets, sqlite3, logging, uuid
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, g, request, session, redirect, url_for, abort,
                   render_template, flash, send_from_directory)
from jinja2 import DictLoader
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "portal.db")
UPLOADS = os.path.join(BASE, "uploads")          # outside static/: never served directly
os.makedirs(UPLOADS, exist_ok=True)

app = Flask(__name__)
# SECRETS: from environment, never hard-coded. Random fallback = dev only (sessions reset on restart).
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",  # set 1 behind HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,           # 2 MB upload cap
)

# ---------- Security logging ----------
slog = logging.getLogger("security")
slog.setLevel(logging.INFO)
_h = logging.FileHandler(os.path.join(BASE, "security.log"))
_h.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
slog.addHandler(_h)
def audit(event, **kw):
    uid = session.get("uid", "-")
    extra = " ".join(f"{k}={v}" for k, v in kw.items())
    slog.info(f"{event} user={uid} ip={request.remote_addr} {extra}")

# ---------- Database (parameterised queries only) ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db
@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d: d.close()

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN('student','staff','admin')),
  failed INTEGER DEFAULT 0, locked_until TEXT);
CREATE TABLE IF NOT EXISTS complaints(id INTEGER PRIMARY KEY, student_id INTEGER NOT NULL REFERENCES users(id),
  subject TEXT NOT NULL, category TEXT NOT NULL, description TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Pending', assigned_to INTEGER REFERENCES users(id),
  filename TEXT, original_name TEXT, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS responses(id INTEGER PRIMARY KEY, complaint_id INTEGER NOT NULL REFERENCES complaints(id),
  staff_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL, created TEXT NOT NULL);
"""
CATEGORIES = ["Academic", "IT Support", "Finance", "Accommodation", "Other"]
STATUSES = ["Pending", "In Progress", "Resolved"]

@app.cli.command("init-db")
def init_db():
    """Create tables and demo accounts (CHANGE these passwords outside of testing)."""
    c = sqlite3.connect(DB); c.executescript(SCHEMA)
    demo = [("deng", "deng@uni.ac", "Student#2026pw", "student"),
            ("john", "john@uni.ac", "Student#2026pw", "student"),
            ("sarah", "sarah@uni.ac", "Staff#2026pw!", "staff"),
            ("admin", "admin@uni.ac", "Admin#2026pw!", "admin")]
    for u, e, p, r in demo:
        c.execute("INSERT OR IGNORE INTO users(username,email,pw_hash,role) VALUES(?,?,?,?)",
                  (u, e, generate_password_hash(p), r))
    c.commit(); print("Database ready.")

# ---------- Auth helpers ----------
def current_user():
    uid = session.get("uid")
    return db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone() if uid else None

def login_required(*roles):
    def deco(f):
        @wraps(f)
        def wrap(*a, **kw):
            u = current_user()
            if not u:
                return redirect(url_for("login"))
            if roles and u["role"] not in roles:       # SERVER-SIDE role check
                audit("ACCESS_DENIED", path=request.path, role=u["role"])
                abort(403)
            g.user = u
            return f(*a, **kw)
        return wrap
    return deco

def strong_password(p):
    return len(p) >= 10 and re.search(r"[a-z]", p) and re.search(r"[A-Z]", p) and re.search(r"\d", p)

# CSRF protection for every state-changing request
@app.before_request
def csrf_protect():
    if request.method == "POST":
        if not secrets.compare_digest(session.get("csrf", ""), request.form.get("csrf", "")):
            audit("CSRF_FAIL", path=request.path)
            abort(400)
def csrf_token():
    session.setdefault("csrf", secrets.token_hex(16))
    return session["csrf"]
app.jinja_env.globals["csrf_token"] = csrf_token

@app.after_request
def headers(r):
    r.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; frame-ancestors 'none'"
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "no-referrer"
    r.headers["Cache-Control"] = "no-store"
    return r

# ---------- Routes: auth ----------
@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ident = request.form.get("username", "").strip()
        pw = request.form.get("password", "")
        u = db().execute("SELECT * FROM users WHERE username=? OR email=?", (ident, ident)).fetchone()
        generic = "Invalid credentials."                # no user enumeration
        if u and u["locked_until"] and datetime.fromisoformat(u["locked_until"]) > datetime.utcnow():
            audit("LOGIN_LOCKED", target=u["username"]); flash(generic); return render_template("login.html")
        if u and check_password_hash(u["pw_hash"], pw):
            db().execute("UPDATE users SET failed=0, locked_until=NULL WHERE id=?", (u["id"],)); db().commit()
            session.clear()                              # prevents session fixation
            session.permanent = True
            session["uid"] = u["id"]
            audit("LOGIN_OK"); return redirect(url_for("dashboard"))
        if u:
            n = u["failed"] + 1
            lock = (datetime.utcnow() + timedelta(minutes=15)).isoformat() if n >= 5 else None
            db().execute("UPDATE users SET failed=?, locked_until=? WHERE id=?", (0 if lock else n, lock, u["id"])); db().commit()
        audit("LOGIN_FAIL", attempted=ident[:40])
        flash(generic)
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        un, em, pw = (request.form.get(k, "").strip() for k in ("username", "email", "password"))
        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", un) or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", em):
            flash("Invalid username or email."); return render_template("register.html")
        if not strong_password(pw):
            flash("Password needs 10+ chars with upper, lower and a digit."); return render_template("register.html")
        try:   # role is forced to 'student' server-side - never taken from the form
            db().execute("INSERT INTO users(username,email,pw_hash,role) VALUES(?,?,?,'student')",
                         (un, em, generate_password_hash(pw))); db().commit()
        except sqlite3.IntegrityError:
            flash("Username or email already in use."); return render_template("register.html")
        audit("REGISTER", username=un); return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/logout", methods=["POST"])
def logout():
    audit("LOGOUT"); session.clear(); return redirect(url_for("login"))

# ---------- Dashboards ----------
@app.context_processor
def inject_user():
    return {"user": current_user()}

def fetch_rows(u):
    q = ("SELECT c.*, s.username AS student, a.username AS assignee FROM complaints c "
         "JOIN users s ON s.id=c.student_id LEFT JOIN users a ON a.id=c.assigned_to")
    if u["role"] == "student":
        return db().execute(q + " WHERE c.student_id=? ORDER BY c.id DESC", (u["id"],)).fetchall()
    if u["role"] == "staff":
        return db().execute(q + " WHERE c.assigned_to=? ORDER BY c.id DESC", (u["id"],)).fetchall()
    return db().execute(q + " ORDER BY c.id DESC").fetchall()

def staff_list(u):
    return db().execute("SELECT id, username FROM users WHERE role='staff'").fetchall() if u["role"] == "admin" else []

@app.route("/dashboard")
@login_required()
def dashboard():
    u, d = g.user, db()
    stats = None
    if u["role"] == "admin":
        one = lambda sql: d.execute(sql).fetchone()[0]
        stats = {"total": one("SELECT COUNT(*) FROM complaints"),
                 "resolved": one("SELECT COUNT(*) FROM complaints WHERE status='Resolved'"),
                 "pending": one("SELECT COUNT(*) FROM complaints WHERE status='Pending'"),
                 "users": one("SELECT COUNT(*) FROM users")}
    return render_template("dashboard.html", rows=fetch_rows(u), staff=staff_list(u), stats=stats)

@app.route("/complaints")
@login_required()
def complaints_list():
    u = g.user
    title = {"student": "My Complaints", "staff": "Assigned Complaints", "admin": "All Complaints"}[u["role"]]
    return render_template("list.html", rows=fetch_rows(u), staff=staff_list(u), title=title)

@app.route("/profile", methods=["GET", "POST"])
@login_required()
def profile():
    if request.method == "POST":
        cur, new = request.form.get("current", ""), request.form.get("new", "")
        if not check_password_hash(g.user["pw_hash"], cur):
            audit("PASSWORD_CHANGE_FAIL"); flash("Current password is incorrect.")
        elif not strong_password(new):
            flash("New password is too weak.")
        else:
            db().execute("UPDATE users SET pw_hash=? WHERE id=?", (generate_password_hash(new), g.user["id"])); db().commit()
            audit("PASSWORD_CHANGED"); flash("Password updated.")
    return render_template("profile.html")

# ---------- Admin: manage users ----------
ROLES = ["student", "staff", "admin"]

@app.route("/users", methods=["GET", "POST"])
@login_required("admin")
def manage_users():
    if request.method == "POST":
        un, em, pw = (request.form.get(k, "").strip() for k in ("username", "email", "password"))
        role = request.form.get("role", "")
        if role not in ROLES or not re.fullmatch(r"[A-Za-z0-9_]{3,30}", un) \
                or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", em):
            flash("Invalid username, email or role.")
        elif not strong_password(pw):
            flash("Password needs 10+ chars with upper, lower and a digit.")
        else:
            try:
                db().execute("INSERT INTO users(username,email,pw_hash,role) VALUES(?,?,?,?)",
                             (un, em, generate_password_hash(pw), role)); db().commit()
                audit("USER_CREATED", username=un, role=role)
                flash(f"Account created for {un} ({role}).", "ok")
            except sqlite3.IntegrityError:
                flash("Username or email already in use.")
        return redirect(url_for("manage_users"))
    users = db().execute("SELECT id, username, email, role FROM users ORDER BY id").fetchall()
    return render_template("users.html", users=users, roles=ROLES)

# ---------- Student: submit / view ----------
PNG, JPG, PDF = b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"%PDF-"
def valid_upload(f):
    ext = os.path.splitext(f.filename)[1].lower()
    head = f.stream.read(8); f.stream.seek(0)
    ok = {".png": head.startswith(PNG), ".jpg": head.startswith(JPG),
          ".jpeg": head.startswith(JPG), ".pdf": head.startswith(PDF)}
    return ok.get(ext, False), ext

@app.route("/complaints/new", methods=["GET", "POST"])
@login_required("student")
def new_complaint():
    if request.method == "POST":
        subj = request.form.get("subject", "").strip()
        cat = request.form.get("category", "")
        desc = request.form.get("description", "").strip()
        if not (3 <= len(subj) <= 120) or not (10 <= len(desc) <= 3000) or cat not in CATEGORIES:
            flash("Please complete all fields correctly."); return render_template("new.html", cats=CATEGORIES)
        stored = orig = None
        f = request.files.get("file")
        if f and f.filename:
            ok, ext = valid_upload(f)
            if not ok:
                audit("UPLOAD_REJECTED", name=secure_filename(f.filename)[:40])
                flash("Only genuine PNG, JPG or PDF files up to 2 MB are allowed.")
                return render_template("new.html", cats=CATEGORIES)
            stored = uuid.uuid4().hex + ext            # random name: no path traversal / overwrite
            f.save(os.path.join(UPLOADS, stored)); orig = secure_filename(f.filename)
        cur = db().execute("INSERT INTO complaints(student_id,subject,category,description,filename,original_name,created) "
                           "VALUES(?,?,?,?,?,?,?)", (g.user["id"], subj, cat, desc, stored, orig, datetime.utcnow().date().isoformat()))
        db().commit(); audit("COMPLAINT_CREATED", id=cur.lastrowid)
        return redirect(url_for("dashboard"))
    return render_template("new.html", cats=CATEGORIES)

def get_complaint_or_404(cid):
    """Central object-level authorisation (prevents IDOR). 404 hides existence."""
    u = g.user
    sql = "SELECT c.*, s.username AS student FROM complaints c JOIN users s ON s.id=c.student_id WHERE c.id=?"
    c = db().execute(sql, (cid,)).fetchone()
    allowed = c and (u["role"] == "admin" or (u["role"] == "student" and c["student_id"] == u["id"])
                     or (u["role"] == "staff" and c["assigned_to"] == u["id"]))
    if not allowed:
        audit("IDOR_BLOCKED", complaint=cid); abort(404)
    return c

@app.route("/complaints/<int:cid>")
@login_required()
def view_complaint(cid):
    c = get_complaint_or_404(cid)
    resp = db().execute("SELECT r.*, u.username FROM responses r JOIN users u ON u.id=r.staff_id "
                        "WHERE complaint_id=? ORDER BY r.id", (cid,)).fetchall()
    return render_template("view.html", c=c, resp=resp, statuses=STATUSES, user=g.user)

@app.route("/complaints/<int:cid>/file")
@login_required()
def download(cid):
    c = get_complaint_or_404(cid)
    if not c["filename"]: abort(404)
    return send_from_directory(UPLOADS, c["filename"], as_attachment=True, download_name=c["original_name"])

# ---------- Staff: respond ----------
@app.route("/complaints/<int:cid>/respond", methods=["POST"])
@login_required("staff")
def respond(cid):
    get_complaint_or_404(cid)
    body, status = request.form.get("body", "").strip(), request.form.get("status", "")
    if not (1 <= len(body) <= 3000) or status not in STATUSES: abort(400)
    db().execute("INSERT INTO responses(complaint_id,staff_id,body,created) VALUES(?,?,?,?)",
                 (cid, g.user["id"], body, datetime.utcnow().isoformat(timespec="seconds")))
    db().execute("UPDATE complaints SET status=? WHERE id=?", (status, cid)); db().commit()
    audit("RESPONSE_ADDED", complaint=cid, status=status)
    return redirect(url_for("view_complaint", cid=cid))

# ---------- Admin: assign ----------
@app.route("/complaints/<int:cid>/assign", methods=["POST"])
@login_required("admin")
def assign(cid):
    sid = request.form.get("staff_id", type=int)
    if not db().execute("SELECT 1 FROM users WHERE id=? AND role='staff'", (sid,)).fetchone(): abort(400)
    db().execute("UPDATE complaints SET assigned_to=?, status='In Progress' WHERE id=?", (sid, cid)); db().commit()
    audit("ASSIGNED", complaint=cid, staff=sid)
    return redirect(url_for("dashboard"))

@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(400)
@app.errorhandler(413)
def err(e):   # no stack traces or internals leaked
    return render_template("error.html", code=e.code), e.code

# ---------- Templates ----------
from templates import T
app.jinja_loader = DictLoader(T)

if __name__ == "__main__":
    app.run(debug=False)   # NEVER debug=True in production (Werkzeug console = RCE)
