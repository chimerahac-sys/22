#!/usr/bin/env python3
"""Comprehensive Before & After Code Patching Library for CTF Attack-Defense.

Contains ready-to-copy code fixes for:
  - SQL Injection (PHP PDO, MySQLi, Python cursor, Node.js)
  - Local File Inclusion (PHP basename whitelist, Python Path.resolve)
  - Remote Code Execution (PHP escapeshellarg, Python subprocess list)
  - Server-Side Template Injection (Flask render_template vs render_template_string)
  - Cross-Site Scripting (HTML escaping, Content-Type JSON)
  - Insecure Deserialization (JSON decoding instead of unserialize / pickle)
  - SSRF (IP filtering, URL whitelist)
"""

from typing import Dict, List, NamedTuple

try:
    from .colors import Colors, colorize, print_banner, safe_print
except ImportError:
    from colors import Colors, colorize, print_banner, safe_print


class PatchSnippet(NamedTuple):
    title: str
    category: str
    language: str
    vulnerable_code: str
    patched_code: str
    explanation: str


SNIPPETS: List[PatchSnippet] = [
    # 1. SQL Injection - PHP PDO
    PatchSnippet(
        title="SQL Injection in PHP (PDO Prepared Statements)",
        category="SQLi",
        language="PHP",
        vulnerable_code="""// VULNERABLE: String concatenation
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $id;
$result = $pdo->query($query);""",
        patched_code="""// PATCHED: Prepared statement with parameter binding
$id = (int)($_GET['id'] ?? 0);
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute([':id' => $id]);
$result = $stmt->fetchAll();""",
        explanation="Menggunakan parameter binding :id agar karakter kutip dan SQL injection diparsing sebagai literal data, bukan syntax query.",
    ),

    # 2. SQL Injection - PHP MySQLi
    PatchSnippet(
        title="SQL Injection in PHP (MySQLi)",
        category="SQLi",
        language="PHP",
        vulnerable_code="""// VULNERABLE: Direct variable interpolation
$user = $_POST['user'];
$res = mysqli_query($conn, "SELECT * FROM users WHERE username = '$user'");""",
        patched_code="""// PATCHED: MySQLi Prepared Statement
$user = $_POST['user'] ?? '';
$stmt = mysqli_prepare($conn, "SELECT * FROM users WHERE username = ?");
mysqli_stmt_bind_param($stmt, "s", $user);
mysqli_stmt_execute($stmt);
$res = mysqli_stmt_get_result($stmt);""",
        explanation="Prepared statement pada MySQLi memisahkan tahapan kompilasi query dengan pengiriman parameter data.",
    ),

    # 3. SQL Injection - Python SQLite / MySQL
    PatchSnippet(
        title="SQL Injection in Python (sqlite3 / mysql-connector)",
        category="SQLi",
        language="Python",
        vulnerable_code="""# VULNERABLE: f-string or string format
user_id = request.args.get('id')
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")""",
        patched_code="""# PATCHED: Parameterized tuple
user_id = int(request.args.get('id', 0))
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))  # sqlite: ? | mysql: %s
rows = cursor.fetchall()""",
        explanation="Gunakan parameter placeholder (?) untuk SQLite atau (%s) untuk MySQL dengan tuple terpisah.",
    ),

    # 4. Local File Inclusion (LFI) - PHP
    PatchSnippet(
        title="Local File Inclusion / Path Traversal in PHP",
        category="LFI",
        language="PHP",
        vulnerable_code="""// VULNERABLE: Direct include from user input
$page = $_GET['page'];
include("pages/" . $page . ".php");""",
        patched_code="""// PATCHED: Whitelist array + basename()
$page = basename($_GET['page'] ?? 'home');
$allowed_pages = ['home', 'about', 'contact', 'login'];
if (!in_array($page, $allowed_pages, true)) {
    http_response_code(403);
    die("Access Denied");
}
include("pages/" . $page . ".php");""",
        explanation="Gunakan basename() untuk membuang '../' dan periksa nilai terhadap whitelist eksplisit.",
    ),

    # 5. Remote Code Execution (RCE) - PHP
    PatchSnippet(
        title="Command Injection / RCE in PHP (ping / tools)",
        category="RCE",
        language="PHP",
        vulnerable_code="""// VULNERABLE: Unsanitized shell execution
$ip = $_POST['ip'];
system("ping -c 1 " . $ip);""",
        patched_code="""// PATCHED: IP Validation + escapeshellarg()
$ip = $_POST['ip'] ?? '';
if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    http_response_code(400);
    die("Invalid IP Address format");
}
exec("ping -c 1 " . escapeshellarg($ip), $output);""",
        explanation="Validasi tipe data dengan filter_var() dan bungkus variabel dengan escapeshellarg().",
    ),

    # 6. Remote Code Execution (RCE) - Python Subprocess
    PatchSnippet(
        title="Command Injection in Python (subprocess)",
        category="RCE",
        language="Python",
        vulnerable_code="""# VULNERABLE: shell=True with user input
host = request.args.get('host')
os.system("ping -c 1 " + host)
# or: subprocess.run(f"ping -c 1 {host}", shell=True)""",
        patched_code="""# PATCHED: Argument list with shell=False
import subprocess, ipaddress
host = request.args.get('host', '')
try:
    ipaddress.ip_address(host)  # Validate IP
    res = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, check=True, shell=False)
except Exception:
    abort(400)""",
        explanation="Gunakan list argumen ['cmd', 'arg'] dan shell=False agar OS tidak memanggil shell (/bin/sh).",
    ),

    # 7. SSTI - Flask / Jinja2
    PatchSnippet(
        title="Server-Side Template Injection in Flask / Jinja2",
        category="SSTI",
        language="Python",
        vulnerable_code="""# VULNERABLE: render_template_string with user input
template = f"Hello {request.args.get('name')}!"
return render_template_string(template)""",
        patched_code="""# PATCHED: render_template with context variable
name = request.args.get('name', 'Guest')
return render_template("hello.html", name=name)
# Di dalam hello.html: <h1>Hello {{ name }}</h1>""",
        explanation="Jangan pernah mem-format string template dengan input user. Selalu masukkan sebagai parameter context.",
    ),

    # 8. Insecure Deserialization - PHP
    PatchSnippet(
        title="Insecure Deserialization in PHP (unserialize)",
        category="DESER",
        language="PHP",
        vulnerable_code="""// VULNERABLE: unserialize on user input
$data = unserialize(base64_decode($_COOKIE['session']));""",
        patched_code="""// PATCHED: JSON encode/decode
$data = json_decode(base64_decode($_COOKIE['session'] ?? ''), true);
if (!is_array($data)) {
    $data = [];
}""",
        explanation="Ganti fungsi unserialize() dengan json_decode() yang aman dari object injection / POP chains.",
    ),

    # 9. Type Juggling & Loose Comparison - PHP
    PatchSnippet(
        title="Type Juggling / Loose Comparison in PHP (== and strcmp)",
        category="AUTH",
        language="PHP",
        vulnerable_code="""// VULNERABLE: Loose comparison & strcmp bypass
if ($_POST['token'] == "0e123456789") { ... }
if (strcmp($_POST['password'], $secret_pass) == 0) { ... }""",
        patched_code="""// PATCHED: Strict comparison === & hash_equals()
$input_token = (string)($_POST['token'] ?? '');
if (hash_equals($secret_token, $input_token)) { ... }

$input_pass = (string)($_POST['password'] ?? '');
if (is_string($input_pass) && $input_pass === $secret_pass) { ... }""",
        explanation="Gunakan hash_equals() atau pastikan string casting dengan strict comparison === untuk mencegah bypass magic hash (0e...) dan strcmp array input.",
    ),

    # 10. Insecure File Upload - PHP
    PatchSnippet(
        title="Insecure File Upload in PHP (Webshell upload bypass)",
        category="UPLOAD",
        language="PHP",
        vulnerable_code="""// VULNERABLE: No extension whitelist or renaming
$target = "uploads/" . $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], $target);""",
        patched_code="""// PATCHED: Whitelist extension + MIME check + Random Hash Name
$allowed_exts = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'txt'];
$ext = strtolower(pathinfo($_FILES['file']['name'] ?? '', PATHINFO_EXTENSION));
if (!in_array($ext, $allowed_exts, true)) {
    die("Format file dilarang!");
}
$safe_name = bin2hex(random_bytes(16)) . "." . $ext;
move_uploaded_file($_FILES['file']['tmp_name'], "uploads/" . $safe_name);""",
        explanation="Validasi ekstensi dengan whitelist ketat dan ganti nama file menjadi random hex hash agar attacker tidak bisa menebak atau mengeksekusi webshell.",
    ),

    # 11. SSRF - PHP / Python
    PatchSnippet(
        title="Server-Side Request Forgery (SSRF) Filter",
        category="SSRF",
        language="PHP",
        vulnerable_code="""// VULNERABLE: Direct file_get_contents / curl to user URL
$url = $_GET['url'];
$content = file_get_contents($url);""",
        patched_code="""// PATCHED: Scheme validation + Private IP filtering
$url = (string)($_GET['url'] ?? '');
$parsed = parse_url($url);
if (!in_array(strtolower($parsed['scheme'] ?? ''), ['http', 'https'], true)) die("Invalid scheme");
$ip = gethostbyname($parsed['host'] ?? '');
if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) || $ip === '127.0.0.1') {
    die("Akses jaringan internal dilarang!");
}
$content = file_get_contents($url);""",
        explanation="Validasi skema protokol (hanya http/https) dan resolusikan hostname ke IP untuk memblokir IP private/loopback/cloud metadata.",
    ),

    # 12. Insecure Deserialization - Python Pickle
    PatchSnippet(
        title="Python Pickle Deserialization to JSON",
        category="DESER",
        language="Python",
        vulnerable_code="""# VULNERABLE: pickle.loads on base64 user cookie
cookie = request.cookies.get('session')
user_data = pickle.loads(base64.b64decode(cookie))""",
        patched_code="""# PATCHED: Safe json.loads with fallback
import json, base64
cookie = request.cookies.get('session', '')
try:
    user_data = json.loads(base64.b64decode(cookie).decode('utf-8'))
except Exception:
    user_data = {}""",
        explanation="Ganti fungsi pickle.loads() dengan json.loads(). Pickle di Python memungkinkan eksekusi kode biner arbitrary (__reduce__).",
    ),

    # 13. SQL Injection - Node.js (PostgreSQL / MySQL)
    PatchSnippet(
        title="SQL Injection in Node.js / Express",
        category="SQLi",
        language="Node.js",
        vulnerable_code="""// VULNERABLE: Template literal in database query
const userId = req.query.id;
const query = `SELECT * FROM users WHERE id = ${userId}`;
db.query(query, (err, result) => { ... });""",
        patched_code="""// PATCHED: Parameterized Query ($1 placeholder)
const userId = parseInt(req.query.id, 10) || 0;
const query = "SELECT * FROM users WHERE id = $1";
db.query(query, [userId], (err, result) => { ... });""",
        explanation="Gunakan parameterized query placeholder ($1 atau ?) dengan array nilai parameter terpisah.",
    ),

    # 14. Command Injection - Node.js
    PatchSnippet(
        title="Command Injection in Node.js (child_process)",
        category="RCE",
        language="Node.js",
        vulnerable_code="""// VULNERABLE: child_process.exec with concatenated user input
const { exec } = require('child_process');
exec(`ping -c 1 ${req.query.ip}`, (error, stdout) => { ... });""",
        patched_code="""// PATCHED: child_process.spawn with argument array
const { spawn } = require('child_process');
const net = require('net');
const ip = req.query.ip || '';
if (!net.isIP(ip)) { return res.status(400).send('Invalid IP'); }
const child = spawn('ping', ['-c', '1', ip]);""",
        explanation="Gunakan child_process.spawn() dengan array argumen terpisah agar input tidak diparsing melalui shell interpreter.",
    ),

    # 15. XML External Entity (XXE) - PHP
    PatchSnippet(
        title="XML External Entity (XXE) in PHP",
        category="XXE",
        language="PHP",
        vulnerable_code="""// VULNERABLE: XML parser with entity resolution enabled
$xmlData = file_get_contents('php://input');
$doc = simplexml_load_string($xmlData);""",
        patched_code="""// PATCHED: Disable external entity loader
libxml_disable_entity_loader(true);
$xmlData = file_get_contents('php://input');
$doc = simplexml_load_string($xmlData, 'SimpleXMLElement', LIBXML_NOENT | LIBXML_DTDLOAD);
if (!$doc) { die("Invalid XML"); }""",
        explanation="Panggil libxml_disable_entity_loader(true) untuk mencegah entity SYSTEM memanggil file:///flag atau URI internal.",
    ),

    # 16. Insecure Direct Object Reference (IDOR) - Flask / Python
    PatchSnippet(
        title="IDOR / Broken Object-Level Authorization (Python/Flask)",
        category="AUTH",
        language="Python",
        vulnerable_code="""# VULNERABLE: Direct access to document by ID without ownership check
@app.route('/doc/<int:doc_id>')
def view_doc(doc_id):
    doc = Document.query.get(doc_id)
    return jsonify(doc.content)""",
        patched_code="""# PATCHED: Enforce session user ownership check
@app.route('/doc/<int:doc_id>')
def view_doc(doc_id):
    user_id = session.get('user_id')
    if not user_id: abort(401)
    doc = Document.query.filter_by(id=doc_id, owner_id=user_id).first_or_404()
    return jsonify(doc.content)""",
        explanation="Selalu filter data berdasarkan owner_id dari session login pengguna yang valid.",
    ),

    # 17. NoSQL Injection - Node.js / MongoDB
    PatchSnippet(
        title="NoSQL Injection in Node.js (MongoDB / Mongoose)",
        category="NOSQLI",
        language="Node.js",
        vulnerable_code="""// VULNERABLE: Direct object input from req.body
const { username, password } = req.body;
db.users.findOne({ username: username, password: password });""",
        patched_code="""// PATCHED: Type cast to strict strings (anti $ne operator)
const username = String(req.body.username || '');
const password = String(req.body.password || '');
if (!username || !password) return res.status(400).send('Bad Request');
db.users.findOne({ username: username, password: password });""",
        explanation="Konversi nilai menjadi String() murni agar payload operator objek seperti {$ne: ''} tidak bisa mengubah logika query MongoDB.",
    ),

    # 18. Hardcoded Flask Secret Key
    PatchSnippet(
        title="Hardcoded Secret Key in Flask",
        category="AUTH",
        language="Python",
        vulnerable_code="""# VULNERABLE: Hardcoded weak secret key
app.secret_key = "secret123" # Attacker can forge session cookies""",
        patched_code="""# PATCHED: Random secret key from OS entropy or env
import os, secrets
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)""",
        explanation="Gunakan secrets.token_hex(32) yang di-generate dinamis agar penyerang tidak bisa memalsukan cookie session.",
    ),
]


def show_all_patch_guides(category_filter: str = ""):
    """Print beautifully formatted patch guides."""
    print_banner("Emergency Code Patching Guides", "Before & After Quick Reference")
    filtered = [s for s in SNIPPETS if not category_filter or s.category.lower() == category_filter.lower()]

    for idx, s in enumerate(filtered, 1):
        safe_print(colorize(f"\n[{idx}] {s.title} ({s.language})", Colors.BOLD + Colors.BRIGHT_YELLOW))
        safe_print(colorize("-" * 75, Colors.DIM))

        safe_print(colorize("❌ BEFORE (VULNERABLE):", Colors.BRIGHT_RED))
        for line in s.vulnerable_code.strip().splitlines():
            safe_print(f"   {colorize(line, Colors.BRIGHT_RED)}")

        safe_print(colorize("\n✅ AFTER (PATCHED):", Colors.BRIGHT_GREEN))
        for line in s.patched_code.strip().splitlines():
            safe_print(f"   {colorize(line, Colors.BRIGHT_GREEN)}")

        safe_print(f"\n💡 {colorize('Penjelasan:', Colors.CYAN)} {s.explanation}\n")
    return 0


if __name__ == "__main__":
    import sys
    category = sys.argv[1] if len(sys.argv) > 1 else ""
    show_all_patch_guides(category)
