# Defensive Patch Patterns

## PHP — SQL

```php
// Hindari
$q = "SELECT * FROM users WHERE id = " . $_GET['id'];

// PDO
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
$stmt->execute(['id' => (int) $_GET['id']]);

// mysqli
$stmt = $mysqli->prepare('SELECT * FROM users WHERE id = ?');
$id = (int) $_GET['id'];
$stmt->bind_param('i', $id);
$stmt->execute();
```

## PHP — output dan file

```php
echo htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

$allowed = ['home.php', 'help.php'];
$page = $_GET['page'] ?? 'home.php';
if (!in_array($page, $allowed, true)) { http_response_code(404); exit; }
include __DIR__ . '/pages/' . $page;
```

## Python — SQL dan command

```python
cursor.execute('SELECT * FROM users WHERE id = ?', (int(user_id),))
subprocess.run(['ping', '-c', '1', host], check=False, shell=False)
```

Validasi host dengan allowlist sesuai kebutuhan aplikasi. Jangan memakai `shell=True` untuk input user.

## Flask — template dan file

```python
return render_template('result.html', value=user_value)

# Hindari: render_template_string(user_value)
```

Untuk file download, gunakan allowlist atau validasi `realpath` agar hasilnya tetap di direktori yang diizinkan.

## Node/Express

```javascript
db.query('SELECT * FROM users WHERE id = $1', [Number(req.query.id)]);
spawn('ping', ['-c', '1', host], { shell: false });
element.textContent = value;
```

## Patch discipline

- Pertahankan nama route dan response checker.
- Jangan mengubah schema database tanpa backup.
- Hindari rewrite besar.
- Setelah patch, cek syntax/runtime sebelum temuan berikutnya.
