# 🐍 Python Web Vulnerabilities & Fast Patch Bible (Flask / Django / FastAPI)

> **Panduan Lengkap Menemukan Celah & Melakukan Patching pada Web Stack Python di CTF Attack-Defense.**

---

## 📑 Daftar Isi
1. [Server-Side Template Injection (SSTI - Jinja2 / Flask)](#1-server-side-template-injection-ssti)
2. [Python Insecure Deserialization (Pickle & PyYAML)](#2-insecure-deserialization-pickle--yaml)
3. [Command Injection & Subprocess RCE](#3-command-injection--subprocess-rce)
4. [SQL Injection pada Python (SQLite, MySQL, PostgreSQL)](#4-sql-injection-di-python)
5. [Flask Session Forging & Weak Secret Key](#5-flask-session-forging--weak-secret-key)
6. [Path Traversal & Insecure File Serving](#6-path-traversal--file-serving)

---

## 1. Server-Side Template Injection (SSTI)

### 🔴 Indikasi Celah SSTI di Flask:
Penggunaan `render_template_string` yang menggabungkan input user secara langsung ke dalam string template:
```python
# ❌ [RENTAN: SSTI via render_template_string]
from flask import Flask, request, render_template_string

@app.route('/hello')
def hello():
    name = request.args.get('name', 'Guest')
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)
```
*Attacker mengirim payload: `?name={{config.__class__.__init__.__globals__['os'].popen('cat /flag').read()}}`*

### ✅ [CARA PATCH 1: Gunakan `render_template` dengan Context Variable]
```python
# ✅ [PATCH BENAR]
from flask import render_template

@app.route('/hello')
def hello():
    name = request.args.get('name', 'Guest')
    # Di dalam template file (templates/hello.html): <h1>Hello {{ name }}</h1>
    return render_template('hello.html', name=name)
```

### ✅ [CARA PATCH 2 (1-Detik In-Line Fix): Kirim parameter sebagai context]
```python
# ✅ [PATCH 1-DETIK TANPA BUAT FILE HTML BARU]
@app.route('/hello')
def hello():
    name = request.args.get('name', 'Guest')
    # Template string statis, data dikirim terpisah melalui parameter context!
    return render_template_string("<h1>Hello {{ name }}!</h1>", name=name)
```

---

## 2. Insecure Deserialization (Pickle & YAML)

### 🔴 Kasus 1: `pickle.loads()` pada Cookie / Token
```python
import base64, pickle
from flask import request

# ❌ [RENTAN: RCE via Pickle __reduce__ method]
@app.route('/profile')
def profile():
    cookie = request.cookies.get('session')
    user_data = pickle.loads(base64.b64decode(cookie))
    return f"Welcome {user_data.get('user')}"

# ✅ [PATCH: Ganti ke JSON (100% Aman dari RCE)]
import json

@app.route('/profile')
def profile():
    cookie = request.cookies.get('session', '')
    try:
        user_data = json.loads(base64.b64decode(cookie).decode('utf-8'))
    except Exception:
        user_data = {}
    return f"Welcome {user_data.get('user', 'Guest')}"
```

### 🔴 Kasus 2: PyYAML `yaml.load()`
```python
import yaml

# ❌ [RENTAN: yaml.load() mengeksekusi tag python/object/apply]
data = yaml.load(user_input, Loader=yaml.Loader)

# ✅ [PATCH: Gunakan yaml.safe_load()]
data = yaml.safe_load(user_input)
```

---

## 3. Command Injection & Subprocess RCE

### 🔴 Kasus: `os.system` atau `subprocess` dengan `shell=True`
```python
import os, subprocess
from flask import request

# ❌ [RENTAN: host = "127.0.0.1; cat /flag"]
@app.route('/ping')
def ping():
    host = request.args.get('host')
    output = os.popen(f"ping -c 1 {host}").read()
    # atau: subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return output

# ✅ [PATCH: Validasi Format IP + List Argument + shell=False]
import ipaddress

@app.route('/ping')
def ping():
    host = request.args.get('host', '').strip()
    try:
        # Validasi bahwa input benar-benar IP Address murni
        ipaddress.ip_address(host)
    except ValueError:
        return "Invalid IP format", 400

    # Gunakan format LIST argument dan shell=False!
    res = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=2.0)
    return res.stdout
```

---

## 4. SQL Injection di Python

### 🔴 Kasus 1: SQLite (`sqlite3`)
```python
import sqlite3

# ❌ [RENTAN: f-string formatting]
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# ✅ [PATCH: Parameter Placeholder (?)]
cursor.execute("SELECT * FROM users WHERE id = ?", (int(user_id),))
```

### 🔴 Kasus 2: MySQL / PostgreSQL (`mysql.connector` / `psycopg2`)
```python
# ❌ [RENTAN]
cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")

# ✅ [PATCH: Parameter Placeholder (%s)]
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
```

### 🔴 Kasus 3: SQLAlchemy Raw Query
```python
# ❌ [RENTAN]
db.session.execute(text(f"SELECT * FROM products WHERE name = '{name}'"))

# ✅ [PATCH: Bind Parameter (:name)]
db.session.execute(text("SELECT * FROM products WHERE name = :name"), {"name": name})
```

---

## 5. Flask Session Forging & Weak Secret Key

Jika `app.secret_key` di hardcode atau lemah (misal: `'secret'`, `'admin'`, `'123456'`), lawan bisa membuat cookie session palsu (`flask-unsign`) untuk menjadi admin!

```python
# ❌ [RENTAN: Hardcoded Weak Secret Key]
app.secret_key = "secret_key_123"

# ✅ [PATCH: Generate Random Hex Key Saat Startup]
import os
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32).hex())
```

---

## 6. Path Traversal & File Serving

```python
import os
from flask import request, send_file, send_from_directory, abort

# ❌ [RENTAN: filename = "../../../../etc/passwd" atau "/etc/shadow"]
# Di Python, os.path.join('/var/www/uploads', '/etc/passwd') menghasilkan '/etc/passwd'!
@app.route('/download')
def download():
    filename = request.args.get('file')
    path = os.path.join('/var/www/uploads', filename)
    return send_file(path)

# ✅ [PATCH 1: Gunakan send_from_directory() bawaan Flask (Aman Otomatis)]
@app.route('/download')
def download():
    filename = request.args.get('file', '')
    # Flask send_from_directory otomatis memblokir path traversal ../
    return send_from_directory('/var/www/uploads', filename)

# ✅ [PATCH 2: Pathlib Resolve & Whitelist Base Directory]
from pathlib import Path

@app.route('/download')
def download():
    filename = os.path.basename(request.args.get('file', ''))
    base_dir = Path('/var/www/uploads').resolve()
    target_path = (base_dir / filename).resolve()

    # Pastikan target_path berada di dalam base_dir
    if not str(target_path).startswith(str(base_dir)) or not target_path.is_file():
        abort(404)

    return send_file(str(target_path))
```
