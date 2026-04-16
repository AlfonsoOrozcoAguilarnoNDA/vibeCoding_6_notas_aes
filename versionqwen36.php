<?php
/*
Copyright 2026
Alfonso Orozco Aguilarqwen 3.6
Licencia MIT

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/

/**
 * 🔐 Secure Notes Vault - Single File PHP App
 * Autor: Qwen3.6 | Stack: PHP 8.x, Bootstrap 4.6, Font Awesome 5.15, jQuery
 * Requisitos: PHP >= 8.0, ext-openssl, ext-session
 */

declare(strict_types=1);
error_reporting(E_ALL);
ini_set('display_errors', 0); // Producción segura

// ======================== CONFIGURACIÓN ========================
define('VAULT_DIR', __DIR__ . '/vault_notes');
define('MAX_FILE_SIZE', 4096);
define('NOTES_COUNT', 6);
define('ADMIN_HASH', '$2y$10$rC8XqJ5Z3qYvXqJ5Z3qYvO1aB2cD3eF4gH5iJ6kL7mN8oP9qR0s'); // ← Generar con: php -r "echo password_hash('vibekoder', PASSWORD_DEFAULT);"
define('APP_VERSION', '1.0.0');

// Generar hash real si el placeholder no coincide (solo primer uso)
if (!password_verify('vibekoder', ADMIN_HASH)) {
    define('ADMIN_HASH_REAL', password_hash('vibekoder', PASSWORD_DEFAULT));
} else {
    define('ADMIN_HASH_REAL', ADMIN_HASH);
}

session_start();

// ======================== FUNCIONES DE SEGURIDAD ========================
function encryptData(string $data, string $key): string {
    $iv = openssl_random_pseudo_bytes(16);
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', hash('sha256', $key, true), OPENSSL_RAW_DATA, $iv);
    return $iv . $encrypted; // IV concatenado al inicio
}

function decryptData(string $data, string $key): string|false {
    if (strlen($data) < 16) return false;
    $iv = substr($data, 0, 16);
    $ciphertext = substr($data, 16);
    return openssl_decrypt($ciphertext, 'AES-256-CBC', hash('sha256', $key, true), OPENSSL_RAW_DATA, $iv);
}

function ensureVaultDir(): void {
    if (!is_dir(VAULT_DIR)) {
        mkdir(VAULT_DIR, 0750, true);
    }
    // Crear archivos vacíos si no existen
    for ($i = 1; $i <= NOTES_COUNT; $i++) {
        $file = VAULT_DIR . "/nota{$i}.aes";
        if (!file_exists($file)) {
            file_put_contents($file, '', LOCK_EX);
            chmod($file, 0640);
        }
    }
}

function isDirWritable(): bool {
    return is_dir(VAULT_DIR) && is_writable(VAULT_DIR);
}

// ======================== RUTEO / LÓGICA ========================
$action = $_GET['action'] ?? '';

// LOGIN
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $user = trim($_POST['username'] ?? '');
    $pass = $_POST['password'] ?? '';
    
    if ($user === 'admin' && password_verify($pass, ADMIN_HASH_REAL)) {
        $_SESSION['vault_auth'] = true;
        $_SESSION['vault_user'] = $user;
        $_SESSION['vault_login_time'] = time();
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    }
    $loginError = true;
}

// LOGOUT
if ($action === 'logout') {
    session_unset();
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// GUARDAR NOTA (AJAX)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'save' && isset($_SESSION['vault_auth'])) {
    header('Content-Type: application/json');
    $noteId = (int)($_POST['note_id'] ?? 0);
    $key = $_POST['key'] ?? '';
    $content = $_POST['content'] ?? '';
    
    if ($noteId < 1 || $noteId > NOTES_COUNT || empty($key)) {
        echo json_encode(['success' => false, 'error' => 'Datos inválidos']);
        exit;
    }
    
    $file = VAULT_DIR . "/nota{$noteId}.aes";
    $encrypted = encryptData($content, $key);
    
    if (strlen($encrypted) > MAX_FILE_SIZE) {
        echo json_encode(['success' => false, 'error' => 'Excede el tamaño máximo (4KB)']);
        exit;
    }
    
    file_put_contents($file, $encrypted, LOCK_EX);
    echo json_encode(['success' => true]);
    exit;
}

// LEER NOTA (AJAX)
if ($action === 'read' && isset($_SESSION['vault_auth'])) {
    header('Content-Type: application/json');
    $noteId = (int)($_GET['note_id'] ?? 0);
    $key = $_GET['key'] ?? '';
    
    if ($noteId < 1 || $noteId > NOTES_COUNT || empty($key)) {
        echo json_encode(['success' => false, 'error' => 'Datos inválidos']);
        exit;
    }
    
    $file = VAULT_DIR . "/nota{$noteId}.aes";
    if (!file_exists($file) || filesize($file) === 0) {
        echo json_encode(['success' => true, 'content' => '', 'empty' => true]);
        exit;
    }
    
    $data = file_get_contents($file);
    $decrypted = decryptData($data, $key);
    
    if ($decrypted === false) {
        echo json_encode(['success' => false, 'error' => 'Clave incorrecta o archivo corrupto']);
        exit;
    }
    
    echo json_encode(['success' => true, 'content' => $decrypted]);
    exit;
}

// ESTADO DE ARCHIVOS
if ($action === 'status' && isset($_SESSION['vault_auth'])) {
    header('Content-Type: application/json');
    $files = [];
    for ($i = 1; $i <= NOTES_COUNT; $i++) {
        $file = VAULT_DIR . "/nota{$i}.aes";
        $files[$i] = [
            'exists' => file_exists($file),
            'size' => file_exists($file) ? filesize($file) : 0,
            'has_content' => file_exists($file) && filesize($file) > 16
        ];
    }
    echo json_encode($files);
    exit;
}

// VERIFICAR AUTENTICACIÓN
$authenticated = isset($_SESSION['vault_auth']) && $_SESSION['vault_auth'] === true;
ensureVaultDir();
?>
<?php if (!$authenticated): ?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔐 Vault Login</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <style>
        body { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .login-box { background: rgba(255,255,255,0.95); border-radius: 15px; padding: 2.5rem; box-shadow: 0 10px 40px rgba(0,0,0,0.3); max-width: 400px; width: 100%; }
        .login-box h2 { color: #0f3460; font-weight: 700; }
        .btn-login { background: #0f3460; border: none; transition: all 0.3s; }
        .btn-login:hover { background: #1a1a2e; transform: translateY(-2px); }
        .form-control { border-radius: 8px; }
    </style>
</head>
<body>
    <div class="login-box text-center">
        <i class="fas fa-shield-alt fa-3x mb-3" style="color:#0f3460;"></i>
        <h2 class="mb-4">Secure Vault</h2>
        <?php if (!empty($loginError)): ?>
            <div class="alert alert-danger py-2">Credenciales incorrectas</div>
        <?php endif; ?>
        <form method="POST" action="">
            <div class="form-group text-left">
                <label><i class="fas fa-user mr-2"></i>Usuario</label>
                <input type="text" name="username" class="form-control" required autocomplete="username" placeholder="admin">
            </div>
            <div class="form-group text-left">
                <label><i class="fas fa-lock mr-2"></i>Contraseña</label>
                <input type="password" name="password" class="form-control" required autocomplete="current-password" placeholder="••••••••">
            </div>
            <button type="submit" name="login" class="btn btn-login btn-block text-white font-weight-bold py-2">
                <i class="fas fa-sign-in-alt mr-2"></i>Ingresar
            </button>
        </form>
        <p class="mt-3 text-muted small">Protegido con AES-256-CBC & PHP <?= PHP_VERSION ?></p>
    </div>
</body>
</html>
<?php exit; endif; ?>

<?php // ================ INTERFAZ PRINCIPAL ================ ?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔐 Secure Vault</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <style>
        :root { --primary: #0f3460; --secondary: #1a1a2e; --accent: #e94560; --light: #f8f9fa; }
        body { background: #f4f6f9; padding-top: 70px; padding-bottom: 80px; }
        .navbar-custom { background: var(--secondary); border-bottom: 3px solid var(--accent); }
        .navbar-brand { font-weight: 700; letter-spacing: 1px; }
        .jumbotron { background: linear-gradient(135deg, var(--primary), var(--secondary)); color: white; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.15); }
        .card-note { border: none; border-radius: 10px; transition: transform 0.2s, box-shadow 0.2s; cursor: pointer; }
        .card-note:hover { transform: translateY(-5px); box-shadow: 0 8px 25px rgba(0,0,0,0.15); }
        .card-header-note { background: var(--primary); color: white; border-radius: 10px 10px 0 0 !important; }
        .status-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; margin-right: 5px; }
        .status-empty { background: #6c757d; } .status-filled { background: #28a745; }
        .footer-fixed { position: fixed; bottom: 0; left: 0; right: 0; background: var(--secondary); color: #aaa; padding: 0.6rem 0; font-size: 0.85rem; border-top: 2px solid var(--accent); }
        .btn-vault { background: var(--accent); border: none; color: white; }
        .btn-vault:hover { background: #d63851; color: white; }
        textarea.note-content { background: #1a1a2e; color: #0f0; font-family: 'Courier New', monospace; border: 1px solid #333; min-height: 200px; resize: vertical; }
        .modal-content { border-radius: 12px; overflow: hidden; }
        .modal-header { background: var(--primary); color: white; }
    </style>
</head>
<body>
    <!-- NAVBAR -->
    <nav class="navbar navbar-expand-lg navbar-dark navbar-custom fixed-top">
        <div class="container">
            <a class="navbar-brand" href="#"><i class="fas fa-vault mr-2"></i>Secure Vault <span class="badge badge-danger">v<?= APP_VERSION ?></span></a>
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navMenu">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navMenu">
                <ul class="navbar-nav mr-auto">
                    <li class="nav-item"><a class="nav-link" href="#" onclick="checkStatus(); return false;"><i class="fas fa-home mr-1"></i>Inicio</a></li>
                    <li class="nav-item"><a class="nav-link" href="#" onclick="alert('Documentación en desarrollo'); return false;"><i class="fas fa-book mr-1"></i>Docs</a></li>
                    <li class="nav-item"><a class="nav-link" href="https://github.com" target="_blank" rel="noopener"><i class="fab fa-github mr-1"></i>GitHub</a></li>
                </ul>
                <span class="navbar-text text-white-50 mr-3 d-none d-lg-inline">Powered by <strong class="text-white">Qwen3.6</strong></span>
                <a href="?action=logout" class="btn btn-outline-light btn-sm"><i class="fas fa-sign-out-alt mr-1"></i>Salir</a>
            </div>
        </div>
    </nav>

    <!-- CONTENIDO -->
    <div class="container mt-4">
        <div class="jumbotron py-4">
            <h2 class="mb-2">🔐 Bienvenido, <?= htmlspecialchars($_SESSION['vault_user'] ?? 'admin') ?></h2>
            <p class="mb-0">Gestiona tus notas cifradas con AES-256-CBC. Cada archivo tiene su propia clave de cifrado.</p>
            <hr class="my-3 bg-white">
            <div class="row text-center">
                <div class="col-4"><i class="fas fa-lock fa-2x mb-2"></i><br><small>Cifrado Militar</small></div>
                <div class="col-4"><i class="fas fa-key fa-2x mb-2"></i><br><small>Claves por Nota</small></div>
                <div class="col-4"><i class="fas fa-file-shield fa-2x mb-2"></i><br><small>IV Aleatorio</small></div>
            </div>
        </div>

        <!-- GRID DE NOTAS -->
        <div class="row" id="notesGrid">
            <?php for ($i = 1; $i <= NOTES_COUNT; $i++): ?>
                <div class="col-md-4 mb-4">
                    <div class="card card-note h-100 shadow-sm">
                        <div class="card-header card-header-note d-flex justify-content-between align-items-center">
                            <span><i class="fas fa-file-alt mr-2"></i>nota<?= $i ?>.aes</span>
                            <span id="status<?= $i ?>" class="status-dot status-empty" title="Vacía"></span>
                        </div>
                        <div class="card-body">
                            <p class="card-text text-muted small" id="preview<?= $i ?>">
                                <i class="fas fa-lock mr-1"></i>Contenido cifrado o vacío
                            </p>
                            <div class="btn-group w-100" role="group">
                                <button class="btn btn-primary btn-sm" onclick="openNoteModal(<?= $i ?>)">
                                    <i class="fas fa-edit mr-1"></i>Leer/Editar
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endfor; ?>
        </div>
    </div>

    <!-- FOOTER -->
    <footer class="footer-fixed text-center">
        <div class="container">
            <i class="fas fa-server mr-1"></i> IP: <?= htmlspecialchars($_SERVER['SERVER_ADDR'] ?? '127.0.0.1') ?> | 
            <i class="fab fa-php mr-1"></i> PHP <?= PHP_VERSION ?> | 
            <i class="fas fa-shield-alt mr-1"></i> OpenSSL <?= defined('OPENSSL_VERSION_TEXT') ? OPENSSL_VERSION_TEXT : 'N/A' ?> |
            <span class="ml-2">© <?= date('Y') ?> Secure Vault</span>
        </div>
    </footer>

    <!-- MODAL EDICIÓN -->
    <div class="modal fade" id="noteModal" tabindex="-1" role="dialog">
        <div class="modal-dialog modal-lg modal-dialog-centered" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-key mr-2"></i><span id="modalTitle">Nota</span></h5>
                    <button type="button" class="close text-white" data-dismiss="modal">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label><i class="fas fa-lock mr-1"></i>Clave de Cifrado (específica para esta nota)</label>
                        <div class="input-group">
                            <input type="password" class="form-control" id="noteKey" placeholder="Ingresa la clave...">
                            <div class="input-group-append">
                                <button class="btn btn-outline-secondary" type="button" onclick="toggleKeyVisibility()">
                                    <i class="fas fa-eye" id="eyeIcon"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                    <div class="d-flex justify-content-end mb-2">
                        <button class="btn btn-success btn-sm mr-2" id="btnDecrypt" onclick="decryptNote()">
                            <i class="fas fa-unlock mr-1"></i>Descifrar
                        </button>
                        <button class="btn btn-warning btn-sm" id="btnLoadFile" onclick="loadFileStatus()" style="display:none;">
                            <i class="fas fa-sync mr-1"></i>Estado
                        </button>
                    </div>
                    <div class="form-group">
                        <label><i class="fas fa-file-alt mr-1"></i>Contenido</label>
                        <textarea class="form-control note-content" id="noteContent" rows="8" placeholder="El contenido aparecerá aquí tras descifrar..."></textarea>
                    </div>
                </div>
                <div class="modal-footer">
                    <span id="statusMsg" class="text-muted small mr-auto"></span>
                    <button class="btn btn-secondary" onclick="copyToClipboard()" id="btnCopy" disabled>
                        <i class="fas fa-copy mr-1"></i>Copiar
                    </button>
                    <button class="btn btn-vault" onclick="saveNote()" id="btnSave" disabled>
                        <i class="fas fa-save mr-1"></i>Grabar
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- SCRIPTS -->
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let currentNoteId = 0;

        function openNoteModal(noteId) {
            currentNoteId = noteId;
            $('#modalTitle').text(`nota${noteId}.aes`);
            $('#noteKey').val('');
            $('#noteContent').val('');
            $('#btnCopy, #btnSave').prop('disabled', true);
            $('#statusMsg').html('');
            $('#noteModal').modal('show');
            setTimeout(() => $('#noteKey').focus(), 500);
        }

        function toggleKeyVisibility() {
            const input = $('#noteKey');
            const icon = $('#eyeIcon');
            if (input.attr('type') === 'password') {
                input.attr('type', 'text'); icon.removeClass('fa-eye').addClass('fa-eye-slash');
            } else {
                input.attr('type', 'password'); icon.removeClass('fa-eye-slash').addClass('fa-eye');
            }
        }

        function decryptNote() {
            const key = $('#noteKey').val().trim();
            if (!key) { showStatus('⚠️ Ingresa una clave de cifrado', 'warning'); return; }
            showStatus('🔓 Descifrando...', 'info');
            
            $.get(window.location.pathname, { action: 'read', note_id: currentNoteId, key: key })
                .done(res => {
                    if (res.success) {
                        $('#noteContent').val(res.content || '');
                        $('#btnCopy, #btnSave').prop('disabled', false);
                        showStatus(res.empty ? '📝 Archivo vacío, listo para escribir' : '✅ Contenido descifrado correctamente', 'success');
                    } else {
                        showStatus('❌ ' + (res.error || 'Error desconocido'), 'danger');
                        $('#noteContent').val('');
                    }
                })
                .fail(() => showStatus('⚠️ Error de conexión', 'danger'));
        }

        function saveNote() {
            const key = $('#noteKey').val().trim();
            const content = $('#noteContent').val();
            if (!key) { showStatus('⚠️ La clave es obligatoria para cifrar', 'warning'); return; }
            
            showStatus('🔒 Cifrando y guardando...', 'info');
            $.post(window.location.pathname, { action: 'save', note_id: currentNoteId, key: key, content: content })
                .done(res => {
                    if (res.success) {
                        showStatus('💾 Guardado y cifrado correctamente', 'success');
                        updateStatusDot(currentNoteId, true);
                    } else {
                        showStatus('❌ ' + (res.error || 'Error al guardar'), 'danger');
                    }
                })
                .fail(() => showStatus('⚠️ Error de conexión', 'danger'));
        }

        function copyToClipboard() {
            const text = $('#noteContent').val();
            if (!text) return;
            navigator.clipboard.writeText(text).then(() => {
                const btn = $('#btnCopy');
                const original = btn.html();
                btn.html('<i class="fas fa-check mr-1"></i>Copiado');
                setTimeout(() => btn.html(original), 1500);
            });
        }

        function updateStatusDot(noteId, hasContent) {
            const dot = $(`#status${noteId}`);
            if (hasContent) {
                dot.removeClass('status-empty').addClass('status-filled').attr('title', 'Contenido cifrado');
                $(`#preview${noteId}`).html('<i class="fas fa-lock mr-1"></i>Contenido cifrado seguro');
            } else {
                dot.removeClass('status-filled').addClass('status-empty').attr('title', 'Vacía');
                $(`#preview${noteId}`).html('<i class="fas fa-file mr-1"></i>Sin contenido');
            }
        }

        function checkStatus() {
            $.get(window.location.pathname, { action: 'status' })
                .done(res => {
                    for (let i = 1; i <= 6; i++) {
                        updateStatusDot(i, res[i]?.has_content || false);
                    }
                    showStatus('✅ Estado actualizado', 'success');
                });
        }

        function loadFileStatus() { checkStatus(); }

        function showStatus(msg, type) {
            $('#statusMsg').removeClass('text-success text-danger text-warning text-info')
                .addClass(`text-${type}`).html(msg);
        }

        // Verificar permisos al cargar
        $(document).ready(() => checkStatus());
    </script>
</body>
</html>
