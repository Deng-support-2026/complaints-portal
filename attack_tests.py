"""Attack tests for the Student Complaints Portal.
Run from the project folder:  python attack_tests.py
It starts its own copy of the app on port 5055, attacks it, prints the results
and the matching security.log lines, then stops the app."""
import http.client, os, re, subprocess, sys, time, uuid, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = 5055
LOG = os.path.join(HERE, "security.log")
PW = {"deng": "Student#2026pw", "john": "Student#2026pw"}


class Client:
    def __init__(self):
        self.cookies = {}

    def req(self, method, path, fields=None, files=None):
        headers, body = {}, None
        if self.cookies:
            headers["Cookie"] = "; ".join("%s=%s" % kv for kv in self.cookies.items())
        if files is not None:
            b = "----atk" + uuid.uuid4().hex
            parts = []
            for k, v in (fields or {}).items():
                parts.append(('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' % (b, k, v)).encode())
            for k, (fname, content, ctype) in files.items():
                parts.append(('--%s\r\nContent-Disposition: form-data; name="%s"; filename="%s"\r\nContent-Type: %s\r\n\r\n' % (b, k, fname, ctype)).encode() + content + b"\r\n")
            parts.append(("--%s--\r\n" % b).encode())
            body = b"".join(parts)
            headers["Content-Type"] = "multipart/form-data; boundary=" + b
        elif fields is not None:
            body = urllib.parse.urlencode(fields).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=15)
        c.request(method, path, body=body, headers=headers)
        r = c.getresponse()
        text = r.read().decode("utf-8", "replace")
        for h, v in r.getheaders():
            if h.lower() == "set-cookie":
                k, _, val = v.split(";", 1)[0].partition("=")
                self.cookies[k] = val
        loc = r.getheader("Location")
        c.close()
        return r.status, text, loc

    def csrf(self, path):
        m = re.search(r'name="csrf" value="(\w+)"', self.req("GET", path)[1])
        return m.group(1) if m else ""

    def login(self, user, pw):
        return self.req("POST", "/login", {"username": user, "password": pw, "csrf": self.csrf("/login")})


def start_app():
    env = dict(os.environ)
    env["SECRET_KEY"] = uuid.uuid4().hex + uuid.uuid4().hex
    p = subprocess.Popen([sys.executable, "-m", "flask", "--app", "app", "run", "--port", str(PORT)],
                         cwd=HERE, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(40):
        try:
            c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=2)
            c.request("GET", "/login"); c.getresponse().read(); c.close()
            return p
        except OSError:
            time.sleep(0.5)
    p.terminate()
    sys.exit("The app did not start. Run this from the project folder (the one with app.py).")


def new_complaint(cl, subject, files=None):
    f = {"subject": subject, "category": "Other", "description": "Created by the attack test script.",
         "csrf": cl.csrf("/complaints/new")}
    return cl.req("POST", "/complaints/new", f, files=files)


def main():
    offset = os.path.getsize(LOG) if os.path.exists(LOG) else 0
    proc = start_app()
    rows = []

    def add(name, expected, ok, actual):
        rows.append((name, expected, actual, "PASS" if ok else "FAIL"))

    try:
        for payload in ("' OR 1=1--", "admin'--"):
            st, text, loc = Client().login(payload, "x")
            ok = st == 200 and "Invalid credentials" in text and not loc
            add("SQL injection at login: " + payload, "Login refused", ok, "HTTP %s, %s" % (st, "Invalid credentials" if "Invalid credentials" in text else "UNEXPECTED"))

        deng = Client()
        st, _, _ = deng.login("deng", PW["deng"])
        if st != 302:
            sys.exit("Could not log in as deng. Check the demo password in README.md.")
        ids = re.findall(r'href="/complaints/(\d+)"', deng.req("GET", "/dashboard")[1])
        if not ids:
            new_complaint(deng, "Attack test complaint")
            ids = re.findall(r'href="/complaints/(\d+)"', deng.req("GET", "/dashboard")[1])
        cid = ids[0]
        st, _, _ = deng.req("GET", "/complaints/" + cid)
        add("Control: owner opens own complaint", "200", st == 200, "HTTP %s" % st)

        john = Client()
        st, _, _ = john.login("john", PW["john"])
        if st != 302:
            sys.exit("Could not log in as john. Check the demo password in README.md.")
        st, _, _ = john.req("GET", "/complaints/" + cid)
        add("Student opens another student's complaint (IDOR)", "404", st == 404, "HTTP %s" % st)
        st, _, _ = john.req("GET", "/users")
        add("Student opens admin page /users", "403", st == 403, "HTTP %s" % st)
        st, _, _ = john.req("POST", "/complaints/%s/assign" % cid, {"staff_id": "3", "csrf": john.csrf("/dashboard")})
        add("Student calls admin action: assign complaint", "403", st == 403, "HTTP %s" % st)

        if "&lt;script&gt;" not in deng.req("GET", "/dashboard")[1]:
            new_complaint(deng, "<script>alert('XSS')</script>")
        page = deng.req("GET", "/dashboard")[1]
        ok = "&lt;script&gt;" in page and "<script>alert" not in page
        add("Script tag in complaint subject (XSS)", "Shown as text, not run", ok, "escaped as &lt;script&gt;" if ok else "UNEXPECTED")

        st, _, _ = deng.req("POST", "/complaints/new", {"subject": "no token", "category": "Other", "description": "Request sent without a CSRF token."})
        add("POST without CSRF token", "400", st == 400, "HTTP %s" % st)

        st, text, _ = new_complaint(deng, "Fake PDF upload", files={"file": ("shell.pdf", b"<?php echo 1;", "application/pdf")})
        add("Upload script renamed to .pdf", "Rejected", "Only genuine" in text, "rejected with message" if "Only genuine" in text else "HTTP %s, UNEXPECTED" % st)

        lock = Client()
        name = "locktest" + uuid.uuid4().hex[:6]
        lock.req("POST", "/register", {"username": name, "email": name + "@uni.ac", "password": "Lock#Test2026x", "csrf": lock.csrf("/register")})
        st, _, _ = lock.login(name, "Lock#Test2026x")
        control = st == 302
        for _ in range(5):
            Client().login(name, "wrong-password")
        st, text, loc = Client().login(name, "Lock#Test2026x")
        add("Five wrong passwords, then the right one", "Account locked", control and st == 200 and "Invalid credentials" in text and not loc, "correct password refused while locked" if st == 200 else "HTTP %s" % st)

        st, _, loc = Client().req("GET", "/dashboard")
        add("Open dashboard without logging in", "Redirect to /login", st == 302 and "/login" in (loc or ""), "HTTP %s to %s" % (st, loc))
    finally:
        proc.terminate()

    lines = ["", "ATTACK TEST RESULTS", "=" * 78]
    for name, expected, actual, res in rows:
        lines.append("[%s] %s\n       expected: %s | actual: %s" % (res, name, expected, actual))
    keys = ("LOGIN_FAIL", "IDOR_BLOCKED", "ACCESS_DENIED", "CSRF_FAIL", "UPLOAD_REJECTED", "LOGIN_LOCKED")
    lines += ["", "MATCHING security.log LINES", "=" * 78]
    if os.path.exists(LOG):
        with open(LOG, "rb") as f:
            f.seek(offset)
            for ln in f.read().decode("utf-8", "replace").splitlines():
                if any(k in ln for k in keys):
                    lines.append(ln)
    failed = sum(1 for r in rows if r[3] == "FAIL")
    lines += ["", "%d of %d tests passed." % (len(rows) - failed, len(rows))]
    out = "\n".join(lines)
    print(out)
    os.makedirs(os.path.join(HERE, "evidence"), exist_ok=True)
    with open(os.path.join(HERE, "evidence", "attack-test-results.txt"), "w", encoding="utf-8") as f:
        f.write(out + "\n")
    sys.exit(1 if failed else 0)


main()