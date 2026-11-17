"""Jinja templates (autoescape is ON for all variables => XSS-safe)."""
CSRF = '<input type="hidden" name="csrf" value="{{ csrf_token() }}">'

T = {
"base.html": """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Student Complaints Portal</title>
<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
{% if user %}
{% set links = [('/dashboard','Dashboard','🏠')] %}
{% if user.role == 'student' %}{% set links = links + [('/complaints/new','Submit Complaint','✏️'),('/complaints','My Complaints','📋'),('/profile','Profile','👤')] %}
{% elif user.role == 'staff' %}{% set links = links + [('/complaints','Assigned Complaints','📋'),('/profile','Profile','👤')] %}
{% else %}{% set links = links + [('/complaints','All Complaints','📋'),('/profile','Profile','👤')] %}{% endif %}
<header class="top">
  <div class="brand"><span class="logo">🎓</span> Student Complaints Portal</div>
  <div class="who"><span>👤 Hello, {{ user.username|title }} ({{ user.role|title }})</span>
    <form method="post" action="/logout">""" + CSRF + """<button class="link">Logout ➜</button></form></div>
</header>
<div class="shell"><aside>
  {% for href, label, icon in links %}<a href="{{ href }}" class="{{ 'active' if request.path == href }}"><span>{{ icon }}</span>{{ label }}</a>{% endfor %}
</aside><main>
{% for m in get_flashed_messages() %}<div class="flash">{{ m }}</div>{% endfor %}
{% endif %}
{% block body %}{% endblock %}
{% if user %}</main></div>{% endif %}</html>""",

"login.html": """{% extends 'base.html' %}{% block body %}
<div class="auth">
  <div class="hero"><div class="big">🎓</div><h1>Student<br>Complaints Portal</h1><p>Speak Up • Get Help • Make a Difference</p></div>
  <div class="auth-card"><h2>Login to Your Account</h2>
    {% for m in get_flashed_messages() %}<div class="flash">{{ m }}</div>{% endfor %}
    <form method="post">""" + CSRF + """
      <input name="username" placeholder="👤  Username or Email" autocomplete="username" required>
      <input name="password" type="password" placeholder="🔒  Password" autocomplete="current-password" required>
      <button class="btn">➜ Login</button></form>
    <p class="center">Don't have an account? <a href="/register"><b>Register here</b></a></p></div>
</div>{% endblock %}""",

"register.html": """{% extends 'base.html' %}{% block body %}
<div class="auth"><div class="hero"><div class="big">🎓</div><h1>Create your<br>student account</h1><p>Speak Up • Get Help • Make a Difference</p></div>
  <div class="auth-card"><h2>Student Registration</h2>
    {% for m in get_flashed_messages() %}<div class="flash">{{ m }}</div>{% endfor %}
    <form method="post">""" + CSRF + """
      <input name="username" placeholder="Username (letters, digits, _)" required>
      <input name="email" type="email" placeholder="Email" required>
      <input name="password" type="password" placeholder="Password (10+ chars, upper, lower, digit)" required>
      <button class="btn">Register</button></form>
    <p class="center"><a href="/login">Back to login</a></p></div></div>{% endblock %}""",

"table.html": """<div class="tbl-wrap"><table>
<tr><th>#</th><th>Subject</th>{% if user.role != 'student' %}<th>Student</th>{% endif %}<th>Category</th><th>Status</th><th>Submitted On</th>
{% if user.role == 'admin' %}<th>Assigned To</th>{% endif %}<th>Action</th></tr>
{% for r in rows %}<tr><td>{{ loop.index }}</td><td>{{ r.subject }}</td>{% if user.role != 'student' %}<td>{{ r.student }}</td>{% endif %}
<td>{{ r.category }}</td><td><span class="badge {{ r.status|lower|replace(' ','-') }}">{{ r.status }}</span></td><td>{{ r.created }}</td>
{% if user.role == 'admin' %}<td><form method="post" action="/complaints/{{ r.id }}/assign" class="inline">""" + CSRF + """
<select name="staff_id">{% for s in staff %}<option value="{{ s.id }}" {{ 'selected' if s.id == r.assigned_to }}>{{ s.username }}</option>{% endfor %}</select>
<button class="btn sm">Assign</button></form></td>{% endif %}
<td><a class="btn sm" href="/complaints/{{ r.id }}">{{ 'Respond' if user.role == 'staff' else 'View' }}</a></td></tr>
{% else %}<tr><td colspan="8">No complaints to show.</td></tr>{% endfor %}</table></div>""",

"dashboard.html": """{% extends 'base.html' %}{% block body %}
{% if user.role == 'student' %}
  <section class="welcome"><h1>Welcome, {{ user.username|title }}!</h1><p>You can submit a complaint and track its status here.</p></section>
  <a class="btn" href="/complaints/new">➤ Submit a New Complaint</a>
  <section class="card"><h2>My Complaints</h2>{% include 'table.html' %}</section>
{% elif user.role == 'staff' %}
  <section class="card"><h2>Assigned Complaints</h2>{% include 'table.html' %}</section>
{% else %}
  <div class="stats">
    <div class="stat s-blue"><small>Total Complaints</small><b>{{ stats.total }}</b></div>
    <div class="stat s-green"><small>Resolved</small><b>{{ stats.resolved }}</b></div>
    <div class="stat s-orange"><small>Pending</small><b>{{ stats.pending }}</b></div>
    <div class="stat s-purple"><small>Users</small><b>{{ stats.users }}</b></div></div>
  <section class="card"><h2>Recent Complaints</h2>{% include 'table.html' %}</section>
{% endif %}{% endblock %}""",

"list.html": """{% extends 'base.html' %}{% block body %}
<section class="card"><h2>{{ title }}</h2>{% include 'table.html' %}</section>{% endblock %}""",

"new.html": """{% extends 'base.html' %}{% block body %}
<section class="card"><h2>Submit a Complaint</h2>
<form method="post" enctype="multipart/form-data">""" + CSRF + """
<label>Subject *</label><input name="subject" maxlength="120" required>
<label>Category *</label><select name="category">{% for c in cats %}<option>{{ c }}</option>{% endfor %}</select>
<label>Description *</label><textarea name="description" rows="5" maxlength="3000" required></textarea>
<label>Attach File (Optional, PNG/JPG/PDF, max 2 MB)</label><input type="file" name="file" accept=".png,.jpg,.jpeg,.pdf">
<button class="btn">➤ Submit Complaint</button></form></section>{% endblock %}""",

"view.html": """{% extends 'base.html' %}{% block body %}
<section class="card"><h2>{{ c.subject }}</h2>
<div class="meta"><span class="badge {{ c.status|lower|replace(' ','-') }}">{{ c.status }}</span>
<span>📂 {{ c.category }}</span><span>📅 {{ c.created }}</span><span>👤 {{ c.student }}</span></div>
<p>{{ c.description }}</p>
{% if c.filename %}<p>📎 <a href="/complaints/{{ c.id }}/file">Download attachment</a></p>{% endif %}</section>
<section class="card"><h2>Responses</h2>
{% for r in resp %}<div class="reply"><b>{{ r.username }}</b> · {{ r.created }}<br>{{ r.body }}</div>{% else %}<p>No responses yet.</p>{% endfor %}
{% if user.role == 'staff' %}<form method="post" action="/complaints/{{ c.id }}/respond">""" + CSRF + """
<label>Your response</label><textarea name="body" rows="3" required></textarea>
<label>Status</label><select name="status">{% for s in statuses %}<option {{ 'selected' if s == c.status }}>{{ s }}</option>{% endfor %}</select>
<button class="btn">Send Response</button></form>{% endif %}</section>{% endblock %}""",

"profile.html": """{% extends 'base.html' %}{% block body %}
<section class="card"><h2>Profile</h2><p><b>Username:</b> {{ user.username }}<br><b>Email:</b> {{ user.email }}<br><b>Role:</b> {{ user.role|title }}</p></section>
<section class="card"><h2>Change Password</h2><form method="post">""" + CSRF + """
<label>Current password</label><input type="password" name="current" autocomplete="current-password" required>
<label>New password (10+ chars, upper, lower, digit)</label><input type="password" name="new" autocomplete="new-password" required>
<button class="btn">Update Password</button></form></section>{% endblock %}""",

"error.html": """{% extends 'base.html' %}{% block body %}
<section class="card"><h2>Error {{ code }}</h2><p>This request could not be completed.</p><a class="btn" href="/dashboard">Back to dashboard</a></section>{% endblock %}""",
}
