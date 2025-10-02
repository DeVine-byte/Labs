
A self-contained local lab for learning and practicing common web vulnerabilities using **Flask + SQLite**. Runs inside **Pydroid 3** on Android or any Python 3 environment.

⚠️ **For educational use only.** Do not expose this to the public internet. Keep it local.

---

## Features

* 3 Labs: **Traditional Web App**, **API**, **Domain (DNS)**
* Beginner → Advanced challenge levels
* Built-in scoring / leaderboard system
* Pre-seeded test accounts:

  * `alice / password123` (plaintext password)
  * `bob / hunter2` (hashed password)
  * `admin / adminpass` (admin role)

---

## OWASP Top 10 Vulnerabilities Included

### 1. Stored XSS (Beginner Web App)

* Posts accept unsanitized HTML → executed on viewing.
* **Exploit:** create a post body with `<script>alert(1)</script>` or `<img src=x onerror=alert(1)>`.
* **Bypass notes:** Try using mixed case (`<ScRiPt>`), event handlers (`onload`), or data URIs.

### 2. Path Traversal (Web Upload)

* File uploads do not sanitize filenames.
* **Exploit:** Upload a file named `../../app.py` → attempt overwrite.
* **Bypass notes:** Use URL encoding (`..%2f..%2f`) to bypass naive filters.

### 3. Insecure Direct Object Reference (IDOR)

* API profile endpoint leaks other users’ data.
* **Exploit:** Login with `bob`, obtain token, then GET `/api/profile/1` → view `alice`’s data.
* **Bypass notes:** Tokens don’t enforce ownership; increment IDs.

### 4. Broken Access Control (CSRF-like Admin)

* `/web/delete_post/<id>` is a GET request without CSRF tokens.
* **Exploit:** As admin, visit a malicious link `<img src="/web/delete_post/1">`.
gger through hidden HTML elements.

### 5. Zone Transfer (DNS AXFR)

* Some DNS records allow AXFR.
* **Exploit:** Visit `/domain/axfr` to dump records.
* **Bypass notes:** Try variations like adding `;` or `--` in real-world tools.

### 6. Subdomain Takeover (CNAME)

* DNS contains CNAMEs pointing to unclaimed services.
* **Exploit:** Check `/domain/claim` for vulnerable entries, then simulate takeover.
* **Bypass notes:** Change record to attacker-controlled domain.

### 7. Plaintext Password Storage

* `alice` has an unsalted plaintext password in DB.
* **Exploit:** Login as `alice/password123`.
* **Bypass notes:** Highlight as weak storage.

### 8. Insecure Uploads (API)

* API `/api/upload` saves files without sanitization.
* **Exploit:** Upload file with traversal chars `../../evil.txt`.
* **Bypass notes:** Works with double encoding (`..%252f`).

---

## WAF Bypass Tutorial

Real-world apps may use Web Application Firewalls (WAFs). Here are techniques:

### Regex Signatures

* WAFs often block `script`, `onerror`, `alert`, `union select`.
* Bypass: break signatures with comments or case changes: `ScRiPt`, `al<!--x-->ert(1)`.

### Encoding Tricks

* URL Encoding: `/etc/passwd` → `%2fetc%2fpasswd`
* Double Encoding: `..%252f..%252f`
* HTML Entities: `<script>` → `&#x3c;script&#x3e;`

### Alternate Syntax

* For SQLi: use case differences, inline comments, `/*!UNION*/ SELECT`.
* For XSS: use SVG tags (`<svg/onload=alert(1)>`), data URIs, or JavaScript URLs.

### Logical Bypasses

* Sometimes WAF only checks POST, but GET may bypass.
* Some only inspect headers, not body.

---

## Walkthrough (Step-by-Step)

### Stored XSS

1. Login as `alice`.
2. Go to `/web/create`.
3. Post `<script>alert('XSS')</script>`.
4. Reload dashboard → popup fires → points awarded.

### Path Traversal

1. Login as `bob`.
2. Go to `/web/upload`.
3. Upload a text file named `../../hack.txt`.
4. File saved outside uploads folder → vulnerability confirmed.

### IDOR

1. Login via API with `bob/hunter2`.
2. Copy token.
3. Request `/api/profile/1` with `X-API-Token` header.
4. You see Alice’s details → IDOR.

### Admin CSRF

1. Login as `admin`.
2. Open `/web/admin`.
3. Insert an `<img src="/web/delete_post/1">` in a malicious page.
4. When admin views page → post auto-deletes.

### Zone Transfer

1. Visit `/domain/axfr`.
2. See all records with `allow_axfr=1`.
3. Points awarded.

### Subdomain Takeover

1. Go to `/domain/claim`.
2. Select vulnerable CNAME.
3. Claim takeover → record changes.

### Plaintext Passwords

1. Open `/scores`.
2. Notice `alice`’s account is weak.
3. Login with `alice/password123`.

### Insecure Upload (API)

1. Login via API with `bob`.
2. Upload file `../../evil.txt`.
3. Confirm path traversal works.

---

## Disclaimer

This lab is intentionally insecure. It is a **teaching environment** only. Do not:

* Deploy it to a server exposed to the internet.
* Use discovered techniques on systems you do not own.

---

✅ Happy Hacking & Learning!
