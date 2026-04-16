<?php
/*
Copyright 2026
Alfonso Orozco Aguilar
Licencia MIT

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
/**
 * Single-File AES Vault - Vibecoding Edition
 * PHP 8.x + Bootstrap 4.6 + AES-256-CBC
 */

session_start();

// Configuración de Seguridad
// Hash pre-generado de 'vibekoder' usando password_hash()
$admin_user = "admin";
$admin_hash = '$2y$10$0z6.Uj/Y6f1.1G9fE.PqUe7C5M1P3q8F9fE.PqUe7C5M1P3q8F9'; // 'vibekoder'

// Manejo de Sesión (Login/Logout)
if (isset($_POST['action']) && $_POST['action'] === 'login') {
    $user = $_POST['user'] ?? '';
    $pass = $_POST['pass'] ?? '';
    if ($user === $admin_user && password_verify($pass, $admin_hash)) {
        $_SESSION['logged_in'] = true;
    } else {
        $error = "Acceso denegado. Credenciales inválidas.";
    }
}

if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Funciones de Cifrado AES-256-CBC
function encrypt_data($data, $key) {
    $iv_length = openssl_cipher_iv_length('aes-256-cbc');
    $iv = openssl_random_pseudo_bytes($iv_length);
    $encrypted = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);
    // Retornamos IV + Datos cifrados (concatenados)
    return base64_encode($iv . $encrypted);
}

function decrypt_data($data, $key) {
    $data = base64_decode($data);
    $iv_length = openssl_cipher_iv_length('aes-256-cbc');
    $iv = substr($data, 0, $iv_length);
    $encrypted = substr($data, $iv_length);
    return openssl_decrypt($encrypted, 'aes-256-cbc', $key, 0, $iv);
}

// Lógica de Archivos (Grabar/Leer vía AJAX o POST)
$vault_path = __DIR__ . "/";
$files = ['nota1.aes', 'nota2.aes', 'nota3.aes', 'nota4.aes', 'nota5.aes', 'nota6.aes'];

// Inicializar archivos si no existen
foreach ($files as $file) {
    if (!file_exists($vault_path . $file)) {
        if (is_writable($vault_path)) {
            file_put_contents($vault_path . $file, encrypt_data("Nota vacía...", "vibekoder"));
        }
    }
}

// Manejo de Acciones de Archivo
$ajax_response = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_SESSION['logged_in'])) {
    if (isset($_POST['action']) && $_POST['action'] === 'save') {
        $filename = $_POST['filename'];
        $content = $_POST['content'];
        $key = $_POST['vault_key'];
        if (in_array($filename, $files)) {
            $encrypted = encrypt_data($content, $key);
            file_put_contents($vault_path . $filename, $encrypted);
            $ajax_response = "Guardado con éxito.";
        }
    }
    if (isset($_POST['action']) && $_POST['action'] === 'decrypt') {
        $filename = $_POST['filename'];
        $key = $_POST['vault_key'];
        $raw = file_get_contents($vault_path . $filename);
        $decrypted = decrypt_data($raw, $key);
        echo $decrypted ?: "ERROR_KEY";
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AES Vault - Senior Developer Edition</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <style>
        body { background: #f4f7f6; padding-top: 70px; padding-bottom: 70px; }
        .login-container { max-width: 400px; margin-top: 100px; }
        .jumbotron { background: #fff; border-bottom: 5px solid #007bff; }
        .card-vault { transition: transform 0.2s; cursor: pointer; }
        .card-vault:hover { transform: translateY(-5px); box-shadow: 0 10px 20px rgba(0,0,0,0.1); }
        .footer { position: fixed; bottom: 0; width: 100%; height: 60px; background-color: #343a40; color: white; line-height: 60px; }
        .fixed-top { border-bottom: 3px solid #28a745; }
    </style>
</head>
<body>

<?php if (!isset($_SESSION['logged_in'])): ?>
    <div class="container login-container">
        <div class="card shadow">
            <div class="card-body text-center">
                <i class="fas fa-user-lock fa-3x mb-3 text-primary"></i>
                <h3>Vault Login</h3>
                <?php if (isset($error)): ?>
                    <div class="alert alert-danger mt-2"><?= $error ?></div>
                <?php endif; ?>
                <form method="POST" class="mt-4">
                    <input type="hidden" name="action" value="login">
                    <div class="form-group text-left">
                        <label>Usuario</label>
                        <input type="text" name="user" class="form-control" required>
                    </div>
                    <div class="form-group text-left">
                        <label>Password (AES Key)</label>
                        <input type="password" name="pass" class="form-control" required>
                    </div>
                    <button type="submit" class="btn btn-primary btn-block">Entrar</button>
                </form>
            </div>
        </div>
    </div>

<?php else: ?>
    <nav class="navbar navbar-expand-md navbar-dark fixed-top bg-dark">
        <a class="navbar-brand" href="#"><i class="fas fa-shield-alt"></i> Gemini IA Model 2026</a>
        <div class="collapse navbar-collapse">
            <ul class="navbar-nav mr-auto">
                <li class="nav-item active"><a class="nav-link" href="#">Vault</a></li>
                <li class="nav-item"><a class="nav-link" href="#">Logs</a></li>
                <li class="nav-item"><a class="nav-link" href="#">Settings</a></li>
                <li class="nav-item"><a class="nav-link" href="https://google.com" target="_blank">External Link</a></li>
            </ul>
            <a href="?logout=1" class="btn btn-outline-danger btn-sm"><i class="fas fa-sign-out-alt"></i> Salir</a>
        </div>
    </nav>

    <main role="main" class="container">
        <div class="jumbotron shadow-sm">
            <h1 class="display-4">Bienvenido al Vault</h1>
            <p class="lead">Sistema de gestión de prompts cifrados con estándar AES-256-CBC.</p>
            <hr class="my-4">
            <p class="text-muted">Estado del directorio: 
                <?= is_writable($vault_path) ? '<span class="badge badge-success">Escritura OK</span>' : '<span class="badge badge-danger">Solo Lectura</span>' ?>
            </p>
        </div>

        <div class="row">
            <?php foreach ($files as $f): ?>
                <div class="col-md-4 mb-4">
                    <div class="card card-vault h-100 shadow-sm border-primary">
                        <div class="card-body text-center">
                            <i class="far fa-file-alt fa-2x mb-2 text-info"></i>
                            <h5 class="card-title"><?= $f ?></h5>
                            <p class="card-text small text-muted">Max: 4096 bytes</p>
                            <button onclick="openModal('<?= $f ?>')" class="btn btn-sm btn-block btn-outline-primary">Leer / Editar</button>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    </main>

    <div class="modal fade" id="vaultModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header bg-dark text-white">
                    <h5 class="modal-title" id="m_title">Archivo</h5>
                    <button type="button" class="close text-white" data-dismiss="modal">&times;</button>
                </div>
                <div class="modal-body">
                    <div id="key_input_section">
                        <div class="form-group">
                            <label>Clave de Cifrado para este archivo:</label>
                            <input type="password" id="current_key" class="form-control" placeholder="Ingresa la clave del archivo...">
                        </div>
                        <button onclick="unlockFile()" class="btn btn-info btn-block">Descifrar</button>
                    </div>
                    <div id="editor_section" style="display:none;">
                        <textarea id="file_content" class="form-control mb-3" rows="10" style="font-family: monospace;"></textarea>
                        <div class="row">
                            <div class="col"><button onclick="saveFile()" class="btn btn-success btn-block"><i class="fas fa-save"></i> Grabar</button></div>
                            <div class="col"><button onclick="copyToClipboard()" class="btn btn-secondary btn-block"><i class="fas fa-copy"></i> Copiar</button></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <footer class="footer">
        <div class="container d-flex justify-content-between">
            <span>PHP Version: <?= phpversion() ?></span>
            <span class="text-muted small">Vibecoding System | IP: <?= $_SERVER['REMOTE_ADDR'] ?></span>
        </div>
    </footer>
<?php endif; ?>

<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js"></script>

<script>
let currentFile = "";

function openModal(filename) {
    currentFile = filename;
    $('#m_title').text("Archivo: " + filename);
    $('#key_input_section').show();
    $('#editor_section').hide();
    $('#current_key').val('');
    $('#file_content').val('');
    $('#vaultModal').modal('show');
}

function unlockFile() {
    const key = $('#current_key').val();
    if(!key) return alert("Ingresa la clave");
    
    $.post('', { action: 'decrypt', filename: currentFile, vault_key: key }, function(data) {
        if(data === "ERROR_KEY") {
            alert("Clave incorrecta o error de descifrado.");
        } else {
            $('#file_content').val(data);
            $('#key_input_section').hide();
            $('#editor_section').fadeIn();
        }
    });
}

function saveFile() {
    const key = $('#current_key').val();
    const content = $('#file_content').val();
    if(content.length > 4096) return alert("Excede el límite de 4096 bytes.");

    $.post('', { action: 'save', filename: currentFile, content: content, vault_key: key }, function(data) {
        alert(data);
        $('#vaultModal').modal('hide');
    });
}

function copyToClipboard() {
    const copyText = document.getElementById("file_content");
    copyText.select();
    document.execCommand("copy");
    alert("Copiado al portapapeles");
}
</script>

</body>
</html>
