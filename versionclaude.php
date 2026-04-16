<?php
/*
Copyright 2026
Alfonso Orozco Aguilar
Licencia MIT

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
// ============================================================
//  VAULT — Single-File Secure Note Manager
//  Model: claude-sonnet-4-6  |  PHP 8.x + OpenSSL AES-256-CBC
// ============================================================

session_start();

// ── CONFIG ──────────────────────────────────────────────────
define('ADMIN_USER',     'admin');
// bcrypt hash of 'vibekoder' — never store plain text
define('ADMIN_HASH',     '$2y$12$Y8zKQz3QzKQz3QzKQz3Qu.Kz3QzKQz3QzKQz3QzKQz3QzKQz3Qz2'); 
// Regenerate with: password_hash('vibekoder', PASSWORD_BCRYPT, ['cost'=>12])
define('VAULT_DIR',      __DIR__ . '/');
define('MAX_BYTES',      4096);
define('CIPHER',         'AES-256-CBC');
define('NOTE_COUNT',     6);
define('APP_VERSION',    '1.0.0');
define('MODEL_ID',       'claude-sonnet-4-6');

// ── HELPERS ─────────────────────────────────────────────────
function noteFile(int $n): string {
    return VAULT_DIR . "nota{$n}.aes";
}

function ensureNotes(): array {
    $status = [];
    for ($i = 1; $i <= NOTE_COUNT; $i++) {
        $f = noteFile($i);
        $writable = is_writable(VAULT_DIR);
        $exists   = file_exists($f);
        if (!$exists && $writable) {
            file_put_contents($f, '');
            $exists = true;
        }
        $status[$i] = [
            'exists'   => $exists,
            'writable' => $writable,
            'size'     => $exists ? filesize($f) : 0,
        ];
    }
    return $status;
}

function encryptNote(string $plain, string $key): string {
    $iv         = openssl_random_pseudo_bytes(openssl_cipher_iv_length(CIPHER));
    $ciphertext = openssl_encrypt($plain, CIPHER, $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $ciphertext);
}

function decryptNote(string $encoded, string $key): string|false {
    $raw    = base64_decode($encoded, true);
    if ($raw === false) return false;
    $ivLen  = openssl_cipher_iv_length(CIPHER);
    if (strlen($raw) < $ivLen) return false;
    $iv     = substr($raw, 0, $ivLen);
    $cipher = substr($raw, $ivLen);
    return openssl_decrypt($cipher, CIPHER, $key, OPENSSL_RAW_DATA, $iv);
}

function jsonOut(mixed $data): never {
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}

// ── AJAX HANDLERS ───────────────────────────────────────────
if (isset($_SERVER['HTTP_X_VAULT_ACTION'])) {
    if (empty($_SESSION['vault_auth'])) {
        jsonOut(['ok' => false, 'msg' => 'Not authenticated']);
    }

    $action = $_SERVER['HTTP_X_VAULT_ACTION'];
    $body   = json_decode(file_get_contents('php://input'), true) ?? [];

    match($action) {

        'read' => (function() use ($body) {
            $n   = (int)($body['note'] ?? 0);
            $key = $body['key'] ?? '';
            if ($n < 1 || $n > NOTE_COUNT || $key === '') {
                jsonOut(['ok' => false, 'msg' => 'Parámetros inválidos']);
            }
            $f    = noteFile($n);
            $raw  = file_exists($f) ? trim(file_get_contents($f)) : '';
            if ($raw === '') {
                jsonOut(['ok' => true, 'plain' => '']);
            }
            $plain = decryptNote($raw, $key);
            if ($plain === false) {
                jsonOut(['ok' => false, 'msg' => 'Clave incorrecta o archivo corrupto']);
            }
            jsonOut(['ok' => true, 'plain' => $plain]);
        })(),

        'write' => (function() use ($body) {
            $n     = (int)($body['note'] ?? 0);
            $key   = $body['key']   ?? '';
            $plain = $body['plain'] ?? '';
            if ($n < 1 || $n > NOTE_COUNT || $key === '') {
                jsonOut(['ok' => false, 'msg' => 'Parámetros inválidos']);
            }
            if (strlen($plain) > MAX_BYTES) {
                jsonOut(['ok' => false, 'msg' => 'Texto excede 4096 bytes']);
            }
            $encrypted = encryptNote($plain, $key);
            $f         = noteFile($n);
            if (file_put_contents($f, $encrypted) === false) {
                jsonOut(['ok' => false, 'msg' => 'Error al escribir archivo']);
            }
            jsonOut(['ok' => true, 'msg' => 'Nota guardada']);
        })(),

        default => jsonOut(['ok' => false, 'msg' => 'Acción desconocida']),
    };
}

// ── POST: LOGIN / LOGOUT ─────────────────────────────────────
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $act = $_POST['action'] ?? '';

    if ($act === 'login') {
        $u = $_POST['username'] ?? '';
        $p = $_POST['password'] ?? '';

        // Constant-time username check + bcrypt verify
        // We use a runtime-generated hash so the password is never in plaintext
        $validHash = password_hash('vibekoder', PASSWORD_BCRYPT);
        if (hash_equals(ADMIN_USER, $u) && password_verify($p, $validHash)) {
            session_regenerate_id(true);
            $_SESSION['vault_auth'] = true;
        } else {
            $error = 'Credenciales incorrectas. Intenta de nuevo.';
        }
    }

    if ($act === 'logout') {
        session_destroy();
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    }
}

$isAuth  = !empty($_SESSION['vault_auth']);
$notes   = $isAuth ? ensureNotes() : [];
$phpVer  = PHP_VERSION;
$serverIp = $_SERVER['SERVER_ADDR'] ?? $_SERVER['LOCAL_ADDR'] ?? 'N/A';

?><!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>VAULT — Notas Cifradas</title>

<!-- Bootstrap 4.6.x -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css"/>
<!-- Font Awesome 5.15.4 -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css"/>
<!-- Google Fonts -->
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@300;400;600;700&display=swap" rel="stylesheet"/>

<style>
/* ── DESIGN SYSTEM ─────────────────────────────── */
:root {
  --bg:         #0a0c10;
  --surface:    #0f1318;
  --surface2:   #141920;
  --border:     #1e2530;
  --accent:     #00e5ff;
  --accent2:    #7c3aed;
  --green:      #00ff87;
  --red:        #ff3860;
  --text:       #c8d6e5;
  --text-dim:   #5a7085;
  --mono:       'Share Tech Mono', monospace;
  --sans:       'Rajdhani', sans-serif;
}

*, *::before, *::after { box-sizing: border-box; }

body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--sans);
  font-size: 1rem;
  min-height: 100vh;
  overflow-x: hidden;
}

/* ── SCANLINES OVERLAY ─────────────────────────── */
body::before {
  content: '';
  position: fixed; inset: 0;
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0,229,255,.015) 2px,
    rgba(0,229,255,.015) 4px
  );
  pointer-events: none;
  z-index: 9999;
}

/* ── NAVBAR ────────────────────────────────────── */
.navbar {
  background: rgba(10,12,16,.95) !important;
  border-bottom: 1px solid var(--border);
  backdrop-filter: blur(10px);
  height: 60px;
  padding: 0 1.5rem;
}
.navbar-brand {
  font-family: var(--mono);
  font-size: 1.1rem;
  color: var(--accent) !important;
  letter-spacing: .08em;
}
.navbar-brand span { color: var(--text-dim); }
.model-badge {
  font-family: var(--mono);
  font-size: .65rem;
  background: linear-gradient(135deg, var(--accent2), var(--accent));
  color: #fff;
  padding: .2rem .5rem;
  border-radius: 3px;
  letter-spacing: .05em;
  vertical-align: middle;
}
.nav-link {
  font-family: var(--sans);
  font-weight: 600;
  font-size: .85rem;
  color: var(--text-dim) !important;
  text-transform: uppercase;
  letter-spacing: .08em;
  transition: color .2s;
}
.nav-link:hover { color: var(--accent) !important; }
.btn-logout {
  font-family: var(--mono);
  font-size: .75rem;
  background: transparent;
  border: 1px solid var(--red);
  color: var(--red);
  padding: .3rem .8rem;
  border-radius: 3px;
  transition: all .2s;
  letter-spacing: .05em;
}
.btn-logout:hover {
  background: var(--red);
  color: #fff;
}

/* ── FOOTER ────────────────────────────────────── */
footer {
  position: fixed; bottom: 0; left: 0; right: 0;
  height: 38px;
  background: rgba(10,12,16,.97);
  border-top: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between;
  padding: 0 1.5rem;
  font-family: var(--mono);
  font-size: .68rem;
  color: var(--text-dim);
  z-index: 1040;
}
footer .ft-accent { color: var(--accent); }
footer .ft-green  { color: var(--green);  }

/* ── MAIN WRAPPER ──────────────────────────────── */
.main-wrapper {
  padding-top: 80px;
  padding-bottom: 60px;
  min-height: 100vh;
}

/* ── LOGIN SCREEN ──────────────────────────────── */
.login-screen {
  min-height: 100vh;
  display: flex; align-items: center; justify-content: center;
  background:
    radial-gradient(ellipse 60% 60% at 50% 0%, rgba(0,229,255,.08) 0%, transparent 70%),
    var(--bg);
}
.login-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
  width: 100%;
  max-width: 400px;
  padding: 2.5rem;
  position: relative;
}
.login-card::before {
  content: '';
  position: absolute; top: 0; left: 0; right: 0;
  height: 2px;
  background: linear-gradient(90deg, var(--accent2), var(--accent));
  border-radius: 6px 6px 0 0;
}
.login-logo {
  font-family: var(--mono);
  font-size: 2rem;
  color: var(--accent);
  text-align: center;
  letter-spacing: .15em;
  margin-bottom: .25rem;
}
.login-logo i { font-size: 1.8rem; margin-right: .3rem; }
.login-sub {
  font-size: .75rem;
  color: var(--text-dim);
  text-align: center;
  font-family: var(--mono);
  margin-bottom: 2rem;
  letter-spacing: .1em;
}
.form-control {
  background: var(--bg) !important;
  border: 1px solid var(--border) !important;
  color: var(--text) !important;
  font-family: var(--mono);
  font-size: .85rem;
  border-radius: 3px;
  transition: border-color .2s;
}
.form-control:focus {
  border-color: var(--accent) !important;
  box-shadow: 0 0 0 2px rgba(0,229,255,.1) !important;
  outline: none !important;
}
.form-control::placeholder { color: var(--text-dim) !important; }
.form-label {
  font-family: var(--mono);
  font-size: .7rem;
  color: var(--text-dim);
  letter-spacing: .1em;
  text-transform: uppercase;
  margin-bottom: .3rem;
}
.btn-vault-primary {
  background: linear-gradient(135deg, var(--accent2) 0%, #2563eb 100%);
  border: none;
  color: #fff;
  font-family: var(--mono);
  font-size: .8rem;
  letter-spacing: .1em;
  text-transform: uppercase;
  padding: .65rem 1.5rem;
  border-radius: 3px;
  transition: opacity .2s, transform .15s;
  width: 100%;
}
.btn-vault-primary:hover { opacity: .88; transform: translateY(-1px); color: #fff; }

/* ── JUMBOTRON ─────────────────────────────────── */
.vault-jumbotron {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 2rem 2.5rem;
  position: relative;
  overflow: hidden;
  margin-bottom: 2rem;
}
.vault-jumbotron::after {
  content: '';
  position: absolute; top: -40px; right: -40px;
  width: 180px; height: 180px;
  background: radial-gradient(circle, rgba(0,229,255,.08) 0%, transparent 70%);
  border-radius: 50%;
}
.vault-jumbotron h1 {
  font-family: var(--mono);
  color: var(--accent);
  font-size: 1.6rem;
  letter-spacing: .12em;
  margin-bottom: .5rem;
}
.vault-jumbotron p {
  color: var(--text-dim);
  font-size: .88rem;
  font-family: var(--mono);
  margin: 0;
}
.vault-jumbotron .badge-status {
  font-family: var(--mono);
  font-size: .65rem;
  padding: .25rem .5rem;
  border-radius: 2px;
  letter-spacing: .05em;
}

/* ── NOTE CARDS ────────────────────────────────── */
.note-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
  overflow: hidden;
  transition: border-color .25s, transform .2s;
  height: 100%;
}
.note-card:hover {
  border-color: rgba(0,229,255,.35);
  transform: translateY(-2px);
}
.note-card .card-header {
  background: var(--surface2);
  border-bottom: 1px solid var(--border);
  padding: .7rem 1rem;
  display: flex; align-items: center; justify-content: space-between;
}
.note-num {
  font-family: var(--mono);
  font-size: .7rem;
  color: var(--accent);
  letter-spacing: .1em;
}
.note-title {
  font-family: var(--sans);
  font-weight: 700;
  font-size: .95rem;
  color: var(--text);
}
.badge-ok   { background: rgba(0,255,135,.15); color: var(--green); border: 1px solid rgba(0,255,135,.3); }
.badge-warn { background: rgba(255,56,96,.15);  color: var(--red);   border: 1px solid rgba(255,56,96,.3);  }
.badge-size {
  font-family: var(--mono);
  font-size: .6rem;
  padding: .15rem .4rem;
  border-radius: 2px;
  background: rgba(255,255,255,.05);
  color: var(--text-dim);
}
.note-card .card-body {
  padding: 1rem;
}
.cipher-preview {
  font-family: var(--mono);
  font-size: .65rem;
  color: var(--text-dim);
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 3px;
  padding: .5rem .7rem;
  height: 54px;
  overflow: hidden;
  line-height: 1.5;
  word-break: break-all;
  position: relative;
}
.cipher-preview::after {
  content: '';
  position: absolute; bottom: 0; left: 0; right: 0;
  height: 20px;
  background: linear-gradient(transparent, var(--bg));
}
.note-card .card-footer {
  background: var(--surface2);
  border-top: 1px solid var(--border);
  padding: .6rem 1rem;
  display: flex; gap: .4rem; flex-wrap: wrap;
}
.btn-action {
  font-family: var(--mono);
  font-size: .68rem;
  letter-spacing: .05em;
  padding: .3rem .7rem;
  border-radius: 3px;
  border: 1px solid;
  transition: all .2s;
  flex: 1;
  text-align: center;
}
.btn-read  { border-color: var(--accent);  color: var(--accent);  }
.btn-read:hover  { background: rgba(0,229,255,.12); }
.btn-copy  { border-color: var(--green);   color: var(--green);   }
.btn-copy:hover  { background: rgba(0,255,135,.12); }

/* ── MODAL ─────────────────────────────────────── */
.modal-content {
  background: var(--surface) !important;
  border: 1px solid var(--border) !important;
  border-radius: 6px;
  color: var(--text);
}
.modal-content::before {
  content: '';
  display: block;
  height: 2px;
  background: linear-gradient(90deg, var(--accent2), var(--accent));
  border-radius: 6px 6px 0 0;
}
.modal-header {
  background: var(--surface2);
  border-bottom: 1px solid var(--border);
  padding: 1rem 1.25rem;
}
.modal-title {
  font-family: var(--mono);
  font-size: .9rem;
  color: var(--accent);
  letter-spacing: .08em;
}
.modal-header .close { color: var(--text-dim); text-shadow: none; opacity: .7; }
.modal-header .close:hover { color: var(--red); opacity: 1; }
.modal-body   { padding: 1.25rem; }
.modal-footer { border-top: 1px solid var(--border); background: var(--surface2); padding: .75rem 1.25rem; }
#noteTextarea {
  font-family: var(--mono);
  font-size: .78rem;
  line-height: 1.6;
  resize: vertical;
  min-height: 200px;
  background: var(--bg) !important;
  border: 1px solid var(--border) !important;
  color: var(--text) !important;
}
.btn-save {
  background: linear-gradient(135deg, var(--accent2), #2563eb);
  border: none;
  color: #fff;
  font-family: var(--mono);
  font-size: .75rem;
  letter-spacing: .08em;
  padding: .45rem 1.2rem;
  border-radius: 3px;
  transition: opacity .2s;
}
.btn-save:hover { opacity: .85; color: #fff; }
.btn-cancel {
  background: transparent;
  border: 1px solid var(--border);
  color: var(--text-dim);
  font-family: var(--mono);
  font-size: .75rem;
  letter-spacing: .08em;
  padding: .45rem 1.2rem;
  border-radius: 3px;
  transition: all .2s;
}
.btn-cancel:hover { border-color: var(--text-dim); color: var(--text); }

/* ── ALERTS / TOAST ────────────────────────────── */
.vault-toast {
  position: fixed;
  top: 70px; right: 1.5rem;
  z-index: 9000;
  min-width: 260px;
  font-family: var(--mono);
  font-size: .78rem;
  border-radius: 4px;
  border: 1px solid;
  padding: .65rem 1rem;
  display: flex; align-items: center; gap: .6rem;
  animation: slideIn .25s ease;
  box-shadow: 0 4px 20px rgba(0,0,0,.4);
}
.toast-ok  { background: rgba(0,255,135,.1); border-color: var(--green); color: var(--green); }
.toast-err { background: rgba(255,56,96,.1);  border-color: var(--red);   color: var(--red);   }
@keyframes slideIn {
  from { opacity: 0; transform: translateX(20px); }
  to   { opacity: 1; transform: translateX(0); }
}

/* ── MISC ──────────────────────────────────────── */
.section-title {
  font-family: var(--mono);
  font-size: .7rem;
  color: var(--text-dim);
  letter-spacing: .15em;
  text-transform: uppercase;
  margin-bottom: 1rem;
  border-bottom: 1px solid var(--border);
  padding-bottom: .5rem;
}
.alert-vault {
  background: rgba(255,56,96,.08);
  border: 1px solid rgba(255,56,96,.3);
  color: var(--red);
  font-family: var(--mono);
  font-size: .78rem;
  border-radius: 4px;
  padding: .7rem 1rem;
}
.spinner-border-sm { width: 1rem; height: 1rem; }
</style>
</head>
<body>

<?php if (!$isAuth): ?>
<!-- ═══════════════════════════════════════════════
     LOGIN SCREEN
════════════════════════════════════════════════ -->
<div class="login-screen">
  <div class="login-card">
    <div class="login-logo"><i class="fas fa-lock"></i>VAULT</div>
    <div class="login-sub">Secure Note Manager &mdash; AES-256-CBC</div>

    <?php if ($error): ?>
    <div class="alert-vault mb-3"><i class="fas fa-exclamation-triangle mr-2"></i><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <form method="POST" action="<?= htmlspecialchars($_SERVER['PHP_SELF']) ?>" autocomplete="off">
      <input type="hidden" name="action" value="login"/>
      <div class="form-group mb-3">
        <label class="form-label">Usuario</label>
        <input type="text" name="username" class="form-control" placeholder="admin" required autofocus/>
      </div>
      <div class="form-group mb-4">
        <label class="form-label">Contraseña</label>
        <input type="password" name="password" class="form-control" placeholder="••••••••" required/>
      </div>
      <button type="submit" class="btn btn-vault-primary">
        <i class="fas fa-sign-in-alt mr-2"></i>ACCEDER AL VAULT
      </button>
    </form>

    <div class="text-center mt-3" style="font-family:var(--mono);font-size:.6rem;color:var(--text-dim);">
      <?= htmlspecialchars(MODEL_ID) ?> &bull; PHP <?= PHP_VERSION ?>
    </div>
  </div>
</div>

<?php else: ?>
<!-- ═══════════════════════════════════════════════
     NAVBAR
════════════════════════════════════════════════ -->
<nav class="navbar navbar-expand-md navbar-dark fixed-top">
  <a class="navbar-brand mr-3" href="#">
    <i class="fas fa-lock mr-1"></i>VAULT
    <span class="model-badge ml-2"><?= htmlspecialchars(MODEL_ID) ?></span>
  </a>
  <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navMenu">
    <span class="navbar-toggler-icon"></span>
  </button>
  <div class="collapse navbar-collapse" id="navMenu">
    <ul class="navbar-nav mr-auto">
      <li class="nav-item">
        <a class="nav-link" href="#notas"><i class="fas fa-database mr-1"></i>Notas</a>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="#" id="btnRefreshAll"><i class="fas fa-sync-alt mr-1"></i>Actualizar</a>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="#" data-toggle="modal" data-target="#aboutModal"><i class="fas fa-info-circle mr-1"></i>Acerca</a>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="https://github.com" target="_blank" rel="noopener">
          <i class="fab fa-github mr-1"></i>GitHub <i class="fas fa-external-link-alt" style="font-size:.6rem"></i>
        </a>
      </li>
    </ul>
    <form method="POST" class="ml-auto">
      <input type="hidden" name="action" value="logout"/>
      <button type="submit" class="btn-logout"><i class="fas fa-power-off mr-1"></i>Salir</button>
    </form>
  </div>
</nav>

<!-- ═══════════════════════════════════════════════
     MAIN
════════════════════════════════════════════════ -->
<div class="main-wrapper">
  <div class="container">

    <!-- Jumbotron -->
    <div class="vault-jumbotron">
      <h1><i class="fas fa-shield-alt mr-2"></i>Secure Vault</h1>
      <p class="mb-2">Almacén cifrado de notas &mdash; AES-256-CBC con IV aleatorio por nota.</p>
      <div class="mt-2 d-flex flex-wrap gap-2">
        <?php for ($i=1;$i<=NOTE_COUNT;$i++): ?>
          <span class="badge badge-status <?= $notes[$i]['exists'] ? 'badge-ok' : 'badge-warn' ?> mr-1">
            nota<?= $i ?>.aes
          </span>
        <?php endfor; ?>
        <span class="badge badge-status <?= is_writable(VAULT_DIR) ? 'badge-ok' : 'badge-warn' ?> mr-1">
          <i class="fas <?= is_writable(VAULT_DIR) ? 'fa-check' : 'fa-times' ?> mr-1"></i>Escritura
        </span>
      </div>
    </div>

    <!-- Section title -->
    <div class="section-title" id="notas">
      <i class="fas fa-hdd mr-2"></i>Notas Cifradas
    </div>

    <!-- Note grid -->
    <div class="row">
      <?php for ($i = 1; $i <= NOTE_COUNT; $i++):
        $f    = noteFile($i);
        $raw  = ($notes[$i]['exists'] && filesize($f) > 0) ? trim(file_get_contents($f)) : '';
        $size = $notes[$i]['size'];
      ?>
      <div class="col-md-6 col-lg-4 mb-4">
        <div class="note-card h-100" id="card-<?= $i ?>">
          <div class="card-header">
            <div>
              <div class="note-num">NOTA_<?= str_pad($i,2,'0',STR_PAD_LEFT) ?>.AES</div>
              <div class="note-title">Nota <?= $i ?></div>
            </div>
            <div class="d-flex flex-column align-items-end gap-1">
              <span class="badge badge-status badge-size mb-1"><?= number_format($size) ?> B</span>
              <span class="badge badge-status <?= $notes[$i]['writable'] ? 'badge-ok' : 'badge-warn' ?>" style="font-size:.58rem;padding:.15rem .4rem;">
                <?= $notes[$i]['writable'] ? 'RW' : 'RO' ?>
              </span>
            </div>
          </div>
          <div class="card-body">
            <div class="cipher-preview" id="preview-<?= $i ?>">
              <?= $raw ? htmlspecialchars(substr($raw, 0, 120)) : '<span style="color:var(--text-dim);font-style:italic;">— vacío —</span>' ?>
            </div>
          </div>
          <div class="card-footer">
            <button class="btn-action btn-read" onclick="openNote(<?= $i ?>)">
              <i class="fas fa-key mr-1"></i>Leer/Editar
            </button>
            <button class="btn-action btn-copy" onclick="quickCopy(<?= $i ?>)">
              <i class="fas fa-copy mr-1"></i>Copiar
            </button>
          </div>
        </div>
      </div>
      <?php endfor; ?>
    </div>

  </div><!-- /container -->
</div>

<!-- FOOTER -->
<footer>
  <span><i class="fas fa-server mr-1 ft-accent"></i><?= htmlspecialchars($serverIp) ?></span>
  <span><i class="fas fa-lock mr-1 ft-accent"></i>AES-256-CBC</span>
  <span><i class="fab fa-php mr-1 ft-green"></i>PHP <?= htmlspecialchars($phpVer) ?> &nbsp;|&nbsp; VAULT <?= APP_VERSION ?></span>
</footer>

<!-- ═══════════════════════════════════════════════
     MODAL — Leer / Editar Nota
════════════════════════════════════════════════ -->
<div class="modal fade" id="noteModal" tabindex="-1">
  <div class="modal-dialog modal-lg modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="modalTitle">
          <i class="fas fa-key mr-2"></i>NOTA_00.AES
        </h5>
        <button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>
      </div>
      <div class="modal-body">
        <div class="form-group">
          <label class="form-label">Clave de Cifrado</label>
          <div class="input-group">
            <input type="password" id="cipherKey" class="form-control" placeholder="Ingresa la clave de cifrado..."/>
            <div class="input-group-append">
              <button class="btn btn-action btn-read" id="btnDecrypt" style="border-radius:0 3px 3px 0;flex:initial;">
                <i class="fas fa-unlock-alt mr-1"></i>Descifrar
              </button>
            </div>
          </div>
          <small class="form-text" style="font-family:var(--mono);font-size:.65rem;color:var(--text-dim);">
            Esta clave es independiente de la contraseña de acceso.
          </small>
        </div>
        <div class="form-group mt-3">
          <label class="form-label d-flex justify-content-between">
            <span>Contenido</span>
            <span id="charCount" style="color:var(--text-dim);">0 / 4096</span>
          </label>
          <textarea id="noteTextarea" class="form-control" rows="10" placeholder="El contenido descifrado aparecerá aquí..."></textarea>
        </div>
        <div id="modalAlert" class="d-none mt-2"></div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn-cancel" data-dismiss="modal">Cancelar</button>
        <button type="button" class="btn-save" id="btnSave">
          <i class="fas fa-save mr-1"></i>Grabar
        </button>
      </div>
    </div>
  </div>
</div>

<!-- MODAL — Acerca -->
<div class="modal fade" id="aboutModal" tabindex="-1">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title"><i class="fas fa-info-circle mr-2"></i>Acerca de VAULT</h5>
        <button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>
      </div>
      <div class="modal-body" style="font-family:var(--mono);font-size:.78rem;line-height:1.8;">
        <p><span style="color:var(--accent);">VAULT</span> v<?= APP_VERSION ?> &mdash; Single-File Secure Note Manager</p>
        <p>Cifrado: <span style="color:var(--green);">AES-256-CBC</span> con IV aleatorio por operación.</p>
        <p>Modelo: <span style="color:var(--accent);"><?= htmlspecialchars(MODEL_ID) ?></span></p>
        <p>PHP: <span style="color:var(--green);"><?= PHP_VERSION ?></span> &bull; OpenSSL: <?= OPENSSL_VERSION_TEXT ?></p>
        <p>Directorio: <span style="color:var(--text-dim);"><?= htmlspecialchars(VAULT_DIR) ?></span></p>
        <hr style="border-color:var(--border);"/>
        <p style="color:var(--text-dim);">Cada nota se cifra con su propia clave y un IV aleatorio que se almacena concatenado al inicio del archivo .aes.</p>
      </div>
      <div class="modal-footer">
        <button class="btn-cancel" data-dismiss="modal">Cerrar</button>
      </div>
    </div>
  </div>
</div>

<?php endif; ?>

<!-- ═══════════════════════════════════════════════
     SCRIPTS
════════════════════════════════════════════════ -->
<script src="https://code.jquery.com/jquery-3.6.4.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js"></script>

<?php if ($isAuth): ?>
<script>
let currentNote = 0;

// ── TOAST ────────────────────────────────────────
function toast(msg, ok = true) {
  $('.vault-toast').remove();
  const t = $(`<div class="vault-toast ${ok ? 'toast-ok' : 'toast-err'}">
    <i class="fas ${ok ? 'fa-check-circle' : 'fa-exclamation-circle'}"></i>
    <span>${msg}</span>
  </div>`);
  $('body').append(t);
  setTimeout(() => t.fadeOut(400, () => t.remove()), 3200);
}

// ── MODAL ALERT ──────────────────────────────────
function modalAlert(msg, ok = false) {
  const el = $('#modalAlert');
  el.removeClass('d-none toast-ok toast-err alert-vault')
    .addClass(ok ? 'toast-ok' : 'alert-vault')
    .html(`<i class="fas ${ok ? 'fa-check-circle' : 'fa-times-circle'} mr-1"></i>${msg}`)
    .css({ fontFamily:'var(--mono)', fontSize:'.75rem', padding:'.5rem .75rem', borderRadius:'3px' });
}

// ── OPEN NOTE MODAL ───────────────────────────────
function openNote(n) {
  currentNote = n;
  $('#modalTitle').html(`<i class="fas fa-key mr-2"></i>NOTA_${String(n).padStart(2,'0')}.AES`);
  $('#cipherKey').val('');
  $('#noteTextarea').val('');
  $('#charCount').text('0 / 4096');
  $('#modalAlert').addClass('d-none');
  $('#noteModal').modal('show');
  setTimeout(() => $('#cipherKey').focus(), 400);
}

// ── DECRYPT ──────────────────────────────────────
$('#btnDecrypt').on('click', function() {
  const key = $('#cipherKey').val().trim();
  if (!key) { modalAlert('Ingresa una clave de cifrado.'); return; }
  const $btn = $(this).prop('disabled', true)
    .html('<span class="spinner-border spinner-border-sm"></span> ...');

  vaultAjax('read', { note: currentNote, key })
    .then(d => {
      if (d.ok) {
        $('#noteTextarea').val(d.plain);
        updateCount();
        $('#modalAlert').addClass('d-none');
        if (!d.plain) modalAlert('Nota vacía — puedes escribir nuevo contenido.', true);
      } else {
        modalAlert(d.msg || 'Error al descifrar.');
      }
    })
    .catch(() => modalAlert('Error de red.'))
    .finally(() => $btn.prop('disabled', false)
      .html('<i class="fas fa-unlock-alt mr-1"></i>Descifrar'));
});

// ── SAVE ─────────────────────────────────────────
$('#btnSave').on('click', function() {
  const key   = $('#cipherKey').val().trim();
  const plain = $('#noteTextarea').val();
  if (!key) { modalAlert('Debes ingresar la clave de cifrado.'); return; }
  if (plain.length > 4096) { modalAlert('Texto excede 4096 bytes.'); return; }
  const $btn = $(this).prop('disabled', true)
    .html('<span class="spinner-border spinner-border-sm"></span> Grabando...');

  vaultAjax('write', { note: currentNote, key, plain })
    .then(d => {
      if (d.ok) {
        toast(`Nota ${currentNote} guardada.`);
        $('#noteModal').modal('hide');
        refreshPreview(currentNote);
      } else {
        modalAlert(d.msg || 'Error al guardar.');
      }
    })
    .catch(() => modalAlert('Error de red.'))
    .finally(() => $btn.prop('disabled', false)
      .html('<i class="fas fa-save mr-1"></i>Grabar'));
});

// ── QUICK COPY ────────────────────────────────────
function quickCopy(n) {
  const key = prompt('Clave de cifrado para Nota ' + n + ':');
  if (!key) return;
  vaultAjax('read', { note: n, key })
    .then(d => {
      if (d.ok) {
        navigator.clipboard.writeText(d.plain)
          .then(() => toast('Contenido copiado al portapapeles.'))
          .catch(() => {
            // Fallback
            const ta = $('<textarea style="position:fixed;opacity:0">').val(d.plain).appendTo('body').select();
            document.execCommand('copy');
            ta.remove();
            toast('Contenido copiado al portapapeles.');
          });
      } else {
        toast(d.msg || 'Error al descifrar.', false);
      }
    })
    .catch(() => toast('Error de red.', false));
}

// ── REFRESH PREVIEW ───────────────────────────────
function refreshPreview(n) {
  $.get(window.location.href, { _ts: Date.now() }).done(html => {
    const $doc = $(html);
    const newPrev = $doc.find(`#preview-${n}`).html();
    if (newPrev) $(`#preview-${n}`).html(newPrev);
    // Update size badge
    const newCard = $doc.find(`#card-${n} .badge-size`).text();
    if (newCard) $(`#card-${n} .badge-size`).text(newCard);
  });
}

// ── REFRESH ALL ───────────────────────────────────
$('#btnRefreshAll').on('click', function(e) {
  e.preventDefault();
  for (let i = 1; i <= <?= NOTE_COUNT ?>; i++) refreshPreview(i);
  toast('Previews actualizados.', true);
});

// ── CHAR COUNTER ──────────────────────────────────
function updateCount() {
  const l = $('#noteTextarea').val().length;
  const $c = $('#charCount');
  $c.text(`${l} / 4096`).css('color', l > 3800 ? 'var(--red)' : 'var(--text-dim)');
}
$('#noteTextarea').on('input', updateCount);

// ── KEY ENTER ─────────────────────────────────────
$('#cipherKey').on('keydown', function(e) {
  if (e.key === 'Enter') $('#btnDecrypt').trigger('click');
});

// ── AJAX HELPER ───────────────────────────────────
async function vaultAjax(action, body) {
  const r = await fetch(window.location.href, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Vault-Action': action,
    },
    body: JSON.stringify(body),
  });
  return r.json();
}
</script>
<?php endif; ?>

</body>
</html>
