#!/usr/bin/env python3
"""
Bug Bounty Labs - Pydroid-friendly single-file training app (WAF + SQLi + SSRF)

This version adds:
 - Local, configurable WAF (permissive/balanced/strict) implemented as Flask before_request middleware.
 - WAF logging and UI (/waf/config, /waf/logs, /waf/clear, /waf/whitelist).
 - Intentionally vulnerable SQL Injection route (/vuln/sql) for offline testing (string-concatenation query) — gated for lab use.
 - Simulated SSRF route (/vuln/ssrf) that does NOT perform outbound network calls; it simulates local/remote responses and teaches SSRF concepts.
 - WAF interacts with scoring: bypassing the WAF yields bonuses; being blocked prevents points until bypass achieved.

Safety: everything is local and simulated. No outbound network calls are made by SSRF simulation.
"""

import os
import sqlite3
import secrets
import hashlib
import json
import re
from functools import wraps
from datetime import datetime, timedelta
from flask import Flask, g, render_template_string, request, redirect, url_for, session, jsonify, send_from_directory, abort

# Try to import secure_filename; if unavailable in environment, provide a simple fallback
try:
    from werkzeug.utils import secure_filename
except Exception:
    def secure_filename(filename: str) -> str:
        name = os.path.basename(filename)
        name = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
        return name

# -------------------------
# Configuration
# -------------------------
DB_PATH = "lab_pydroid.db"
UPLOAD_FOLDER = "uploads"
WAF_MODES = ("permissive", "balanced", "strict")
# thresholds per mode (total score threshold to block)
WAF_THRESHOLDS = {"permissive": 1000, "balanced": 60, "strict": 30}
# warn threshold (log but allow)
WAF_WARN = {"permissive": 1000, "balanced": 30, "strict": 10}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
# default WAF mode
app.config["WAF_MODE"] = "balanced"

# -------------------------
# Password & Token helpers
# -------------------------
def hash_password_static(password: str) -> str:
    salt = secrets.token_hex(8)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${h}"

def hash_password(password: str) -> str:
    salt = secrets.token_hex(8)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${h}"

def verify_password(stored: str, provided: str) -> bool:
    if "$" not in stored:
        return stored == provided
    salt, h = stored.split("$", 1)
    return hashlib.sha256((salt + provided).encode()).hexdigest() == h

# Token helpers
def create_token_for_user(user_id: int, days_valid: int = 7) -> str:
    token = secrets.token_hex(16)
    expires = (datetime.utcnow() + timedelta(days=days_valid)).isoformat()
    execute_db("INSERT INTO tokens (token, user_id, expires_at) VALUES (?, ?, ?)", (token, user_id, expires))
    return token

def parse_iso_datetime(s: str):
    try:
        return datetime.fromisoformat(s)
    except Exception:
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(s, fmt)
            except Exception:
                pass
    return datetime(1970, 1, 1)

def get_user_by_token(token: str):
    row = query_db("SELECT user_id, expires_at FROM tokens WHERE token=?", (token,), one=True)
    if not row:
        return None
    try:
        expires = parse_iso_datetime(row["expires_at"])
    except Exception:
        return None
    if expires < datetime.utcnow():
        return None
    return query_db("SELECT * FROM users WHERE id=?", (row["user_id"],), one=True)

# -------------------------
# Utilities (DB access)
# -------------------------
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        create = not os.path.exists(DB_PATH)
        db = g._db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        if create:
            init_db(db)
    return db

def init_db(db):
    cur = db.cursor()
    cur.executescript("""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'user'
    );
    CREATE TABLE posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        body TEXT,
        owner INTEGER
    );
    CREATE TABLE files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        owner INTEGER
    );
    CREATE TABLE dns_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        type TEXT,
        value TEXT,
        allow_axfr INTEGER DEFAULT 0
    );
    CREATE TABLE tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT UNIQUE,
        user_id INTEGER,
        expires_at TEXT
    );
    CREATE TABLE scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        points INTEGER DEFAULT 0
    );
    CREATE TABLE discoveries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        vuln_key TEXT,
        discovered_at TEXT
    );
    CREATE TABLE waf_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT,
        ip TEXT,
        user_id INTEGER,
        path TEXT,
        method TEXT,
        matched_rules TEXT,
        score INTEGER,
        mode TEXT,
        raw_payload TEXT,
        blocked INTEGER
    );
    CREATE TABLE waf_whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        path TEXT
    );
    """)
    # seed users: alice plaintext, bob hashed
    cur.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("alice", "password123", "user"))
    bob_pass = hash_password_static("hunter2")
    cur.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("bob", bob_pass, "user"))
    cur.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("admin", "adminpass", "admin"))
    cur.execute("INSERT INTO posts (title, body, owner) VALUES (?, ?, ?)", ("Welcome", "This is a public post. Try XSS!", 1))
    cur.executemany("INSERT INTO dns_records (name, type, value, allow_axfr) VALUES (?, ?, ?, ?)", [
        ("lab.local", "A", "127.0.0.1", 0),
        ("api.lab.local", "CNAME", "unclaimed-service.example.com", 0),
        ("dev.lab.local", "A", "127.0.0.1", 1),
    ])
    cur.executemany("INSERT INTO scores (user_id, points) VALUES (?, ?)", [(1, 0), (2, 0), (3, 0)])
    db.commit()

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def execute_db(query, args=()):
    db = get_db()
    cur = db.cursor()
    cur.execute(query, args)
    db.commit()
    return cur.lastrowid

# -------------------------
# Scoring helpers
# -------------------------
VULN_SCORES = {
    "stored_xss": 50,
    "path_traversal": 40,
    "idor_profile": 60,
    "axfr_zone_transfer": 30,
    "subdomain_takeover": 80,
    "api_insecure_upload": 20,
    "plaintext_password_account": 10,
    "sqli_vuln": 70,
    "ssrf_vuln": 65
}
WAF_BYPASS_BONUS = 30

def award_points(user_id: int, vuln_key: str, bypassed: bool = False) -> bool:
    if vuln_key not in VULN_SCORES:
        return False
    existing = query_db("SELECT * FROM discoveries WHERE user_id=? AND vuln_key=?", (user_id, vuln_key), one=True)
    if existing:
        return False
    pts = VULN_SCORES[vuln_key]
    if bypassed:
        pts += WAF_BYPASS_BONUS
    execute_db("INSERT INTO discoveries (user_id, vuln_key, discovered_at) VALUES (?, ?, ?)", (user_id, vuln_key, datetime.utcnow().isoformat()))
    existing_score = query_db("SELECT * FROM scores WHERE user_id=?", (user_id,), one=True)
    if not existing_score:
        execute_db("INSERT INTO scores (user_id, points) VALUES (?, ?)", (user_id, 0))
    execute_db("UPDATE scores SET points = points + ? WHERE user_id=?", (pts, user_id))
    print(f"[score] user={user_id} +{pts} for {vuln_key} (bypassed={bypassed})")
    return True

# -------------------------
# WAF rule definitions and helpers
# -------------------------
# compile regexes
SQLI_RE = re.compile(r"(?i)(\bor\b|\band\b).*(=|like)|union(\s+all)?\s+select|\bselect\b.*\bfrom\b|--|#|/\*|\bsleep\(|benchmark\(|information_schema\b")
XSS_RE = re.compile(r"(?i)<script\b|on\w+\s*=|javascript:|<iframe\b|<img[^>]+onerror=|<svg[^>]+onload=|<iframe")
TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\|%2e%2e|\b/etc/passwd\b)")
SSRF_PRIVATE_RE = re.compile(r"(?i)(http://127\.|http://localhost|file://|http://169\.254\.|\b10\.|\b172\.1[6-9]|\b172\.2[0-9]|\b172\.3[0-1]|\b192\.168\.)")
ENCODED_DETECTION = re.compile(r"%25|%2[0-9A-Fa-f]")
HIGH_ENTROPY_RE = re.compile(r"[A-Za-z0-9+/]{40,}|[A-Fa-f0-9]{40,}")

# in-memory rate limits: {ip: [(timestamp1),(timestamp2),...]} simple sliding window
RATE_LIMITS = {}
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_COUNT = {"permissive": 100, "balanced": 30, "strict": 10}

def waf_is_whitelisted(path: str) -> bool:
    row = query_db("SELECT * FROM waf_whitelist WHERE path=?", (path,), one=True)
    return bool(row)

def waf_log_entry(ip, user_id, path, method, matched_rules, score, mode, raw_payload, blocked):
    execute_db(
        "INSERT INTO waf_logs (ts, ip, user_id, path, method, matched_rules, score, mode, raw_payload, blocked) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (datetime.utcnow().isoformat(), ip, user_id, path, method, json.dumps(matched_rules), score, mode, raw_payload[:200] if raw_payload else None, int(blocked))
    )

def waf_rate_limit_exceeded(ip, mode):
    now = datetime.utcnow().timestamp()
    window = RATE_LIMIT_WINDOW
    RATE_LIMITS.setdefault(ip, [])
    # prune old
    RATE_LIMITS[ip] = [t for t in RATE_LIMITS[ip] if now - t < window]
    RATE_LIMITS[ip].append(now)
    limit = RATE_LIMIT_COUNT.get(mode, 30)
    return len(RATE_LIMITS[ip]) > limit

def waf_check_request(req):
    """Return (blocked:bool, matched_rules:list, score:int, reason:str)
    Also set g.waf_info for downstream handlers."""
    mode = app.config.get("WAF_MODE", "balanced")
    path = req.path
    if waf_is_whitelisted(path):
        return (False, [], 0, "whitelisted")
    # build payload blob
    payload_parts = []
    try:
        payload_parts.append(req.method)
        payload_parts.append(path)
        payload_parts.append(req.query_string.decode() if req.query_string else "")
        # headers (selective)
        payload_parts.append(str(dict(req.headers)))
        # body safe size
        data = req.get_data(as_text=True)[:1000]
        payload_parts.append(data)
    except Exception:
        data = ""
    blob = "\n".join(payload_parts)
    score = 0
    matched = []
    # signatures
    if SQLI_RE.search(blob):
        score += 40
        matched.append("sqli_signature")
    if XSS_RE.search(blob):
        score += 35
        matched.append("xss_signature")
    if TRAVERSAL_RE.search(blob):
        score += 30
        matched.append("path_traversal")
    if SSRF_PRIVATE_RE.search(blob):
        score += 50
        matched.append("ssrf_private_target")
    if ENCODED_DETECTION.search(blob):
        score += 10
        matched.append("encoding_obfuscation")
    if HIGH_ENTROPY_RE.search(blob):
        score += 15
        matched.append("high_entropy")
    # parameter-based SSRF check for common param names
    for k, v in dict(req.args).items():
        if k.lower() in ("url", "uri", "callback", "redirect"):
            if SSRF_PRIVATE_RE.search(v):
                score += 50
                matched.append("ssrf_param_private")
    # rate limiting
    ip = req.remote_addr or "127.0.0.1"
    if waf_rate_limit_exceeded(ip, mode):
        matched.append("rate_limit")
        # immediate block in strict/balanced
        if mode in ("balanced", "strict"):
            waf_log_entry(ip, session.get("user_id"), path, req.method, matched, score, mode, blob, True)
            return (True, matched, score, "rate_limit")
    # thresholds
    threshold = WAF_THRESHOLDS.get(mode, 60)
    warn = WAF_WARN.get(mode, 30)
    blocked = False
    reason = None
    if score >= threshold:
        blocked = True
        reason = "signature_threshold"
    elif score >= warn:
        reason = "warn_threshold"
    # write log
    waf_log_entry(ip, session.get("user_id"), path, req.method, matched, score, mode, blob, blocked)
    return (blocked, matched, score, reason)

# WAF before_request middleware
@app.before_request
def waf_middleware():
    # allow access to WAF UI endpoints regardless
    if request.path.startswith('/waf') or request.path.startswith('/static'):
        return None
    # run checker
    blocked, matched, score, reason = waf_check_request(request)
    # store for handlers
    g.waf_info = {"blocked": blocked, "matched": matched, "score": score, "reason": reason}
    if blocked:
        # block with learning response
        return render_template_string("""
            <h3>Request blocked by WAF (mode: {{mode}})</h3>
            <p>Reason: {{reason}}</p>
            <p>Matched rules: {{matched}}</p>
            <p>Tip: review <a href="/waf/logs">WAF logs</a> for details and try to craft a bypass or change mode to 'permissive' for learning.</p>
            <p><a href="/">Back</a></p>
        """, mode=app.config.get("WAF_MODE"), reason=reason, matched=matched), 403
    return None

# -------------------------
# WAF UI endpoints
# -------------------------
@app.route('/waf/config', methods=['GET', 'POST'])
def waf_config():
    # lightweight control UI — no auth required for lab, but you can restrict to admin if desired
    if request.method == 'POST':
        mode = request.form.get('mode')
        if mode in WAF_MODES:
            app.config['WAF_MODE'] = mode
    mode = app.config.get('WAF_MODE')
    return render_template_string("""
        <h3>WAF Configuration</h3>
        <form method="post">
            Mode: <select name="mode">
                {% for m in modes %}
                  <option value="{{m}}" {% if m==mode %}selected{% endif %}>{{m}}</option>
                {% endfor %}
            </select>
            <button>Set Mode</button>
        </form>
        <p>Current mode: {{mode}}</p>
        <p><a href="/waf/logs">View Logs</a> | <a href="/waf/clear">Clear Counters</a></p>
        <p><a href="/">Back</a></p>
    """, modes=WAF_MODES, mode=mode)

@app.route('/waf/logs')
def waf_logs():
    rows = query_db('SELECT * FROM waf_logs ORDER BY id DESC LIMIT 200')
    return render_template_string("""
        <h3>WAF Logs (most recent)</h3>
        <table border=1>
          <tr><th>id</th><th>ts</th><th>ip</th><th>user</th><th>path</th><th>score</th><th>matched</th><th>blocked</th></tr>
          {% for r in rows %}
            <tr>
              <td>{{r['id']}}</td>
              <td>{{r['ts']}}</td>
              <td>{{r['ip']}}</td>
              <td>{{r['user_id']}}</td>
              <td>{{r['path']}}</td>
              <td>{{r['score']}}</td>
              <td>{{r['matched_rules']}}</td>
              <td>{{'yes' if r['blocked'] else 'no'}}</td>
            </tr>
          {% endfor %}
        </table>
        <p><a href="/waf/config">Back</a> | <a href="/">Home</a></p>
    """, rows=rows)

@app.route('/waf/clear')
def waf_clear():
    # clear in-memory rate counters
    RATE_LIMITS.clear()
    return redirect(url_for('waf_logs'))

@app.route('/waf/whitelist', methods=['GET', 'POST'])
def waf_whitelist_ui():
    if request.method == 'POST':
        path = request.form.get('path')
        if path:
            execute_db('INSERT INTO waf_whitelist (path) VALUES (?)', (path,))
    rows = query_db('SELECT * FROM waf_whitelist')
    return render_template_string("""
        <h3>WAF Whitelist</h3>
        <form method="post">Path to whitelist: <input name="path"><button>Add</button></form>
        <ul>{% for r in rows %}<li>{{r['path']}}</li>{% endfor %}</ul>
        <p><a href="/waf/config">Back</a></p>
    """, rows=rows)

# -------------------------
# Scoring / Lab core (web, api, domain)
# -------------------------
@app.route('/')
def index():
    return render_template_string("""
    <h1>Bug Bounty Labs (Pydroid) — WAF + Vulnerabilities</h1>
    <p>WAF mode: <b>{{mode}}</b> — <a href="/waf/config">WAF Settings</a> | <a href="/waf/logs">WAF Logs</a></p>
    <ul>
      <li><a href="/web/">Traditional Web App Lab</a></li>
      <li><a href="/api/">API Lab</a></li>
      <li><a href="/domain/">Domain Lab</a></li>
      <li><a href="/vuln/sql">SQL Injection Lab</a></li>
      <li><a href="/vuln/ssrf">SSRF Lab</a></li>
      <li><a href="/scores">Scoring / Leaderboard</a></li>
    </ul>
    """, mode=app.config.get('WAF_MODE'))

# Reuse earlier web/app code (kept concise here)
@app.route('/web/')
def web_index():
    return render_template_string("""
    <h2>Traditional Web App Lab</h2>
    <p><a href="/web/login">Login</a> | <a href="/web/create">Create Post</a> | <a href="/web/upload">Upload</a></p>
    <p><a href="/">Back</a></p>
    """)

# simplified login (seeded accounts exist)
@app.route('/web/login', methods=['GET', 'POST'])
def web_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = query_db('SELECT * FROM users WHERE username=?', (username,), one=True)
        if not user or not verify_password(user['password'], password):
            return 'Invalid credentials', 401
        session['user_id'] = user['id']
        # award plaintext discovery if applicable
        if '$' not in user['password']:
            award_points(user['id'], 'plaintext_password_account')
        if not query_db('SELECT * FROM scores WHERE user_id=?', (user['id'],), one=True):
            execute_db('INSERT INTO scores (user_id, points) VALUES (?, ?)', (user['id'], 0))
        return redirect(url_for('index'))
    return render_template_string("""
      <form method='post'>User: <input name='username'> Pass: <input name='password' type='password'><button>Login</button></form>
      <p><a href='/'>Back</a></p>
    """)

@app.route('/web/create', methods=['GET', 'POST'])
def web_create_post():
    if 'user_id' not in session:
        return redirect(url_for('web_login'))
    if request.method == 'POST':
        title = request.form.get('title')
        body = request.form.get('body')
        execute_db('INSERT INTO posts (title, body, owner) VALUES (?, ?, ?)', (title, body, session['user_id']))
        lowered = (body or '').lower()
        xss_indicators = ['<script', 'onerror=', 'alert(', 'javascript:', '<svg', 'onload=', 'data:text/html', '<iframe', '<img']
        if any(tok in lowered for tok in xss_indicators):
            # check WAF info: if request was blocked, mark not awarded; if not blocked but matched rules then consider bypass
            waf_info = getattr(g, 'waf_info', None)
            bypassed = False
            if waf_info:
                if waf_info.get('blocked'):
                    # cannot award until bypass
                    print('[waf] post creation blocked; no points')
                else:
                    # if matched rules present (suspicious) but not blocked -> considered bypass
                    bypassed = bool(waf_info.get('matched'))
                    award_points(session['user_id'], 'stored_xss', bypassed=bypassed)
            else:
                award_points(session['user_id'], 'stored_xss')
        return redirect(url_for('web_index'))
    return render_template_string("""
      <form method='post'>Title: <input name='title'><br>Body:<br><textarea name='body'></textarea><br><button>Create</button></form>
      <p><a href='/'>Back</a></p>
    """)

@app.route('/web/upload', methods=['GET', 'POST'])
def web_upload():
    if 'user_id' not in session:
        return redirect(url_for('web_login'))
    if request.method == 'POST':
        f = request.files.get('file')
        if not f:
            return 'No file', 400
        filename = f.filename
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        try:
            f.save(save_path)
        except Exception as e:
            print('[upload error]', e)
            return 'Save failed', 500
        execute_db('INSERT INTO files (filename, owner) VALUES (?, ?)', (filename, session['user_id']))
        if '..' in filename or filename.startswith('/'):
            waf_info = getattr(g, 'waf_info', None)
            bypassed = waf_info and not waf_info.get('blocked') and bool(waf_info.get('matched'))
            award_points(session['user_id'], 'path_traversal', bypassed=bypassed)
        return 'Uploaded', 200
    files = query_db('SELECT * FROM files')
    return render_template_string("""
      <form method='post' enctype='multipart/form-data'>File: <input type='file' name='file'><button>Upload</button></form>
      <h4>Uploaded</h4>
      <ul>{% for f in files %}<li>{{f['filename']}}</li>{% endfor %}</ul>
      <p><a href='/'>Back</a></p>
    """, files=files)

# -------------------------
# Vulnerable SQLi Route (intentionally unsafe for lab)
# -------------------------
@app.route('/vuln/sql', methods=['GET', 'POST'])
def vuln_sql():
    if request.method == 'POST':
        # intentionally vulnerable: constructing SQL using string concatenation
        param = request.form.get('q', '')
        # Build a demo query — DO NOT USE THIS PATTERN IN REAL CODE
        query = f"SELECT id, username FROM users WHERE username = '{param}'"
        print('[sqli] executing unsafe query ->', query)
        try:
            cur = get_db().execute(query)
            rows = cur.fetchall()
            cur.close()
            # if attacker used a payload like ' OR '1'='1', rows will be multiple -> award
            waf_info = getattr(g, 'waf_info', None)
            blocked = waf_info and waf_info.get('blocked')
            matched = waf_info.get('matched') if waf_info else []
            if rows:
                # detect common SQLi markers
                if SQLI_RE.search(param) or "' or '" in param.lower() or 'union select' in param.lower():
                    # award if not blocked, or award as bypass if suspicious matched but not blocked
                    bypassed = not blocked and bool(matched)
                    if not blocked:
                        award_points(session.get('user_id', 0) or 0, 'sqli_vuln', bypassed=bypassed)
                        return render_template_string('<p>Query returned rows (vulnerable). Points awarded (if logged in).</p><p><a href="/">Back</a></p>')
                    else:
                        return render_template_string('<p>Your payload was blocked by the WAF. Check <a href="/waf/logs">WAF logs</a> to iterate.</p>')
            return render_template_string('<p>No interesting results. Try SQLi payloads (lab only).</p>')
        except Exception as e:
            print('[sqli error]', e)
            return f'Error executing query: {e}', 500
    return render_template_string("""
      <h3>SQL Injection Lab (INTENTIONAL VULN - DO NOT COPY)</h3>
      <form method='post'>username param: <input name='q'><button>Query</button></form>
      <p>Try payloads like: <code>' OR '1'='1</code> or <code>admin' --</code></p>
      <p>WAF mode: {{mode}}</p>
      <p><a href='/'>Back</a></p>
    """, mode=app.config.get('WAF_MODE'))

# -------------------------
# Simulated SSRF Route
# -------------------------
@app.route('/vuln/ssrf', methods=['GET', 'POST'])
def vuln_ssrf():
    if request.method == 'POST':
        url = request.form.get('url', '')
        # WAF may have flagged the request already (g.waf_info)
        waf_info = getattr(g, 'waf_info', None)
        blocked = waf_info and waf_info.get('blocked')
        matched = waf_info.get('matched') if waf_info else []
        # Simulate fetching the URL but never perform outbound calls
        # If URL targets private/internal patterns, simulate internal metadata
        if blocked:
            return render_template_string('<p>Request blocked by WAF. Check <a href="/waf/logs">WAF logs</a>.</p>')
        # simulate behavior
        if re.search(r'127\.0\.0\.1|localhost', url):
            content = 'Simulated internal service response: admin panel html...'
            # award SSRF if logged in
            if session.get('user_id'):
                bypassed = not blocked and bool(matched)
                award_points(session['user_id'], 'ssrf_vuln', bypassed=bypassed)
            return render_template_string('<h4>Simulated fetch result (internal)</h4><pre>{{content}}</pre><p><a href="/">Back</a></p>', content=content)
        elif re.search(r'unreachable-service.example.com', url):
            return render_template_string('<p>Remote service appears unclaimed — simulated takeover scenario (no network used).</p>')
        else:
            return render_template_string('<p>Simulated fetch of remote URL returned 200 OK (no real network request performed).</p>')
    return render_template_string("""
      <h3>SSRF Lab (Simulated)</h3>
      <form method='post'>URL: <input name='url' size=80><button>Fetch (simulated)</button></form>
      <p>Try: <code>http://127.0.0.1/admin</code> or <code>http://localhost/metadata</code> or <code>http://169.254.169.254/latest/meta-data/</code></p>
      <p>WAF mode: {{mode}}</p>
      <p><a href='/'>Back</a></p>
    """, mode=app.config.get('WAF_MODE'))

# -------------------------
# API / Domain routes (kept concise)
# -------------------------
@app.route('/api/')
def api_index():
    return render_template_string('<h3>API Lab</h3><p>Use /api/login and /api/profile/&lt;id&gt;</p><p><a href="/">Back</a></p>')

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get('username', '')
    password = data.get('password', '')
    user = query_db('SELECT * FROM users WHERE username=?', (username,), one=True)
    if not user or not verify_password(user['password'], password):
        return jsonify({'msg': 'bad credentials'}), 401
    token = create_token_for_user(user['id'])
    if not query_db('SELECT * FROM scores WHERE user_id=?', (user['id'],), one=True):
        execute_db('INSERT INTO scores (user_id, points) VALUES (?, ?)', (user['id'], 0))
    return jsonify({'token': token})

@app.route('/api/profile/<int:uid>')
def api_profile(uid):
    token = request.headers.get('X-API-Token') or request.args.get('token')
    user = None
    if token:
        user = get_user_by_token(token)
    target = query_db('SELECT id,username,role FROM users WHERE id=?', (uid,), one=True)
    if not target:
        return jsonify({'msg': 'not found'}), 404
    if user and user['id'] != uid:
        award_points(user['id'], 'idor_profile')
    return jsonify(dict(target))

@app.route('/domain/')
def domain_index():
    return render_template_string('<h3>Domain Lab</h3><p><a href="/domain/records">Records</a></p><p><a href="/">Back</a></p>')

@app.route('/domain/records')
def domain_records():
    records = query_db('SELECT * FROM dns_records')
    out = [{ 'id': r['id'], 'name': r['name'], 'type': r['type'], 'value': r['value'], 'allow_axfr': bool(r['allow_axfr']) } for r in records]
    return render_template_string('<pre>{{out|tojson(indent=2)}}</pre><p><a href="/">Back</a></p>', out=out)

# -------------------------
# Scoring UI / Leaderboard
# -------------------------
@app.route('/scores')
def scores_index():
    user = None
    if 'user_id' in session:
        user = query_db('SELECT * FROM users WHERE id=?', (session['user_id'],), one=True)
    rows = query_db('SELECT users.username, scores.points FROM scores JOIN users ON scores.user_id=users.id ORDER BY scores.points DESC')
    discoveries = []
    if user:
        discoveries = query_db('SELECT vuln_key, discovered_at FROM discoveries WHERE user_id=?', (user['id'],))
    return render_template_string("""
      <h3>Scoring / Leaderboard</h3>
      {% if user %}
        <p>Logged in as {{user['username']}} — <a href='/web/logout'>Logout</a></p>
        <h4>Your discoveries</h4>
        <ul>{% for d in discoveries %}<li>{{d['vuln_key']}} at {{d['discovered_at']}}</li>{% endfor %}</ul>
      {% else %}
        <p><a href='/web/login'>Login</a> to claim points</p>
      {% endif %}
      <h4>Leaderboard</h4>
      <ol>{% for r in rows %}<li>{{r['username']}} — {{r['points']}}</li>{% endfor %}</ol>
      <p><a href='/'>Back</a></p>
    """, user=user, rows=rows, discoveries=discoveries)

@app.route('/web/logout')
def web_logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/help')
def help_index():
    return render_template_string("""
      <h3>Help</h3>
      <ul>
        <li>WAF modes: permissive (log-only), balanced (default), strict (aggressive).</li>
        <li>SQLi lab demonstrates vulnerable query building; try payloads like <code>' OR '1'='1</code>.</li>
        <li>SSRF lab simulates internal fetches; no real network calls are made.</li>
      </ul>
      <p><a href='/'>Back</a></p>
    """)

# -------------------------
# Run
# -------------------------
if __name__ == '__main__':
    print('Bug Bounty Labs (Pydroid) with WAF running locally.')
    print('Open http://127.0.0.1:5000/ in a browser on the device.')
    app.run(debug=True, host='127.0.0.1', port=5000)
