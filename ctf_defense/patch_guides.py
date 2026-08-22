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
from .colors import Colors, colorize, print_banner, safe_print


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
