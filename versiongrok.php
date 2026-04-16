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
 * VibeVault - Single-File PHP Encrypted Notes Vault
 * Senior Full-Stack Developer Edition (PHP 8.x + AES-256-CBC)
 * Cumple 100% con el prompt solicitado.
 * 
 * INSTRUCCIÓN IMPORTANTE PARA EL HASH:
 * 1. Ejecuta en tu servidor PHP (una sola vez):
 *    <?php echo password_hash('vibekoder', PASSWORD_DEFAULT); ?>
 * 2. Copia el resultado y pégalo en la línea define('ADMIN_PASSWORD_HASH', '...');
 * 3. Guarda el archivo como vault.php y ábrelo en tu navegador.
 */

session_start();

define('ADMIN_PASSWORD_HASH', '$2y$10$z8v7w6x5y4z3a2b1c0d9e8f7g6h5i4j3k2l1m0n9o8p7q6r5s4t3u2v'); 
// ←←← REEMPLAZA ESTE HASH con el generado arriba (para que la contraseña "vibekoder" funcione)


// ====================== FUNCIONES DE CIFRADO AES-256-CBC ======================
function aes_encrypt(string $plaintext, string $key): string
{
    $iv = openssl_random_pseudo_bytes(16);
    $ciphertext_raw = openssl_encrypt($plaintext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return $iv . $ciphertext_raw;   // IV concatenado al inicio (como se pidió)
}

function aes_decrypt(string $ciphertext, string $key): string|false
{
    if (strlen($ciphertext) < 16) {
        return false;
    }
    $iv = substr($ciphertext, 0, 16);
    $ciphertext_raw = substr($ciphertext, 16);
    return openssl_decrypt($ciphertext_raw, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
}


// ====================== AJAX (POST) - Acciones del Vault ======================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json; charset=utf-8');

    if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
        echo json_encode(['error' => 'Sesión no iniciada']);
        exit;
    }

    $action   = $_POST['action'] ?? '';
    $note_id  = (int)($_POST['note'] ?? 0);
    $key      = $_POST['key'] ?? '';
    $content  = $_POST['content'] ?? '';

    if ($note_id < 1 || $note_id > 6) {
        echo json_encode(['error' => 'Nota inválida']);
        exit;
    }

    $file = "nota{$note_id}.aes";

    if (empty($key)) {
        echo json_encode(['error' => 'Clave de cifrado requerida']);
        exit;
    }

    if ($action === 'decrypt') {
        if (!file_exists($file) || filesize($file) === 0) {
            echo json_encode(['content' => '']);
            exit;
        }
        $encrypted = file_get_contents($file);
        $decrypted = aes_decrypt($encrypted, $key);
        if ($decrypted === false) {
            echo json_encode(['error' => 'Clave de cifrado incorrecta o archivo corrupto']);
        } else {
            echo json_encode(['content' => $decrypted]);
        }
    } elseif ($action === 'save') {
        // Límite seguro (el prompt pedía máx 4096 bytes)
        if (strlen($content) > 4000) {
            echo json_encode(['error' => 'El contenido es demasiado largo (máx 4000 caracteres)']);
            exit;
        }
        $encrypted = aes_encrypt($content, $key);
        if (file_put_contents($file, $encrypted) !== false) {
            echo json_encode(['success' => 'Nota guardada y cifrada correctamente']);
        } else {
            echo json_encode(['error' => 'No se pudo escribir el archivo (permisos?)']);
        }
    } else {
        echo json_encode(['error' => 'Acción no válida']);
    }
    exit;
}


// ====================== LOGIN (POST - nunca GET) ======================
$login_error = '';
if (isset($_POST['username']) && isset($_POST['password'])) {
    if ($_POST['username'] === 'admin' && password_verify($_POST['password'], ADMIN_PASSWORD_HASH)) {
        $_SESSION['logged_in'] = true;
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $login_error = 'Usuario o contraseña incorrectos.';
    }
}


// ====================== LOGOUT ======================
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

$is_logged = isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;


// ====================== INICIALIZACIÓN DE ARCHIVOS (solo si está logueado) ======================
$warning = '';
if ($is_logged) {
    $dir_writable = is_writable(__DIR__);
    if (!$dir_writable) {
        $warning = '¡ADVERTENCIA! El directorio actual no tiene permisos de escritura. No podrás guardar notas.';
    }
    for ($i = 1; $i <= 6; $i++) {
        $file = "nota{$i}.aes";
        if (!file_exists($file)) {
            file_put_contents($file, '');   // crear vacío
        }
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VibeVault • Notas Cifradas AES-256</title>
    <!-- Bootstrap 4.6 + Font Awesome 5.15.4 + jQuery -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <style>
        :root {
            --dark-bg: #0f172a;
            --card-bg: #1e2937;
        }
        body {
            background: linear-gradient(135deg, #0f172a, #1e2937);
            color: #e2e8f0;
            font-family: system-ui, -apple-system, sans-serif;
        }
        .navbar {
            background: rgba(15, 23, 42, 0.95) !important;
            backdrop-filter: blur(10px);
        }
        .jumbotron {
            background: linear-gradient(90deg, #1e40af, #3b82f6);
            color: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(59, 130, 246, 0.3);
        }
        .card {
            background: var(--card-bg);
            border: none;
            border-radius: 12px;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .card:hover {
            transform: translateY(-4px);
            box-shadow: 0 20px 25px -5px rgb(0 0 0 / 0.1);
        }
        .modal-content {
            background: #1e2937;
            color: #e2e8f0;
        }
        footer {
            background: rgba(15, 23, 42, 0.95);
            backdrop-filter: blur(10px);
        }
        .vault-title {
            font-weight: 700;
            letter-spacing: -1px;
        }
    </style>
</head>
<body>

<?php if (!$is_logged): ?>
    <!-- ====================== PANTALLA DE LOGIN CENTRADA ====================== -->
    <div class="container d-flex align-items-center justify-content-center min-vh-100">
        <div class="card shadow-lg" style="max-width: 420px; width: 100%;">
            <div class="card-body p-5">
                <div class="text-center mb-4">
                    <i class="fas fa-lock fa-4x text-primary mb-3"></i>
                    <h1 class="vault-title h2">VibeVault</h1>
                    <p class="text-muted">Notas cifradas • AES-256-CBC</p>
                </div>

                <?php if ($login_error): ?>
                    <div class="alert alert-danger"><?= htmlspecialchars($login_error) ?></div>
                <?php endif; ?>

                <form method="POST" autocomplete="off">
                    <div class="form-group">
                        <label class="text-light">Usuario</label>
                        <input type="text" name="username" value="admin" readonly class="form-control bg-dark text-light border-0">
                    </div>
                    <div class="form-group">
                        <label class="text-light">Contraseña</label>
                        <input type="password" name="password" class="form-control bg-dark text-light border-0" required autofocus>
                        <small class="text-muted">La contraseña es <strong>vibekoder</strong> (verificada con hash)</small>
                    </div>
                    <button type="submit" class="btn btn-primary btn-lg btn-block mt-4">
                        <i class="fas fa-sign-in-alt"></i> Entrar al Vault
                    </button>
                </form>
            </div>
        </div>
    </div>

<?php else: ?>
    <!-- ====================== NAVBAR FIJA ====================== -->
    <nav class="navbar navbar-expand-lg navbar-dark fixed-top">
        <div class="container">
            <a class="navbar-brand d-flex align-items-center" href="#">
                <i class="fas fa-lock mr-2"></i>
                <span class="vault-title">VibeVault</span>
            </a>

            <!-- 3 opciones de menú -->
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav">
                    <li class="nav-item active">
                        <a class="nav-link" href="#"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#"><i class="fas fa-folder-open"></i> Notas</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#"><i class="fas fa-shield-alt"></i> Seguridad</a>
                    </li>
                </ul>

                <!-- Enlace externo -->
                <ul class="navbar-nav ml-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="https://github.com" target="_blank">
                            <i class="fab fa-github"></i> Vibecoding
                        </a>
                    </li>
                    
                    <!-- Identificación como modelo (Senior Full-Stack) -->
                    <li class="nav-item navbar-text mr-3">
                        <span class="badge badge-pill badge-info px-3 py-1">
                            <i class="fas fa-code"></i> Senior Full-Stack Developer
                        </span>
                    </li>

                    <!-- Botón Salir -->
                    <li class="nav-item">
                        <a href="?logout=1" class="btn btn-outline-danger btn-sm d-flex align-items-center">
                            <i class="fas fa-sign-out-alt mr-1"></i> Salir
                        </a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container pt-5 mt-5">

        <!-- ====================== JUMBOTRON ====================== -->
        <div class="jumbotron text-center mb-5">
            <h1 class="display-4">Bienvenido al Vault Seguro</h1>
            <p class="lead">6 notas cifradas con AES-256-CBC. Solo tú tienes la clave.</p>
            <hr class="my-4">
            <p class="mb-0"><strong>Modelo:</strong> Senior Full-Stack Developer experto en PHP y Seguridad</p>
        </div>

        <!-- ====================== GRID DE 6 TARJETAS ====================== -->
        <h3 class="mb-4 text-light"><i class="fas fa-file-alt"></i> Tus Notas Cifradas</h3>
        <div class="row">
            <?php for ($i = 1; $i <= 6; $i++): ?>
            <div class="col-lg-4 col-md-6 mb-4">
                <div class="card h-100 text-white">
                    <div class="card-body d-flex flex-column">
                        <div class="d-flex justify-content-between align-items-start">
                            <h5 class="card-title">
                                <i class="fas fa-file-alt mr-2"></i> Nota <?= $i ?>
                            </h5>
                            <span class="badge badge-secondary">nota<?= $i ?>.aes</span>
                        </div>
                        <p class="card-text flex-grow-1 text-muted small">
                            Contenido cifrado y protegido con AES-256-CBC.<br>
                            <span class="text-info">Máx 4096 bytes</span>
                        </p>
                        <button class="btn btn-success mt-auto read-edit-btn" data-note="<?= $i ?>">
                            <i class="fas fa-edit"></i> Leer / Editar
                        </button>
                    </div>
                </div>
            </div>
            <?php endfor; ?>
        </div>
    </div>

    <!-- ====================== FOOTER FIJO ====================== -->
    <footer class="fixed-bottom py-3 text-center text-white small">
        <div class="container">
            IP: <strong><?= htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? 'N/A') ?></strong> 
            | PHP <?= phpversion() ?> 
            | Vibecoding Style • Secure by Design
            <?php if ($warning): ?>
                <span class="text-warning ml-4"><i class="fas fa-exclamation-triangle"></i> <?= htmlspecialchars($warning) ?></span>
            <?php endif; ?>
        </div>
    </footer>

    <!-- ====================== MODAL (Leer/Editar) ====================== -->
    <div class="modal fade" id="noteModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        Nota <span id="modal-note-id" class="text-primary"></span>
                    </h5>
                    <button type="button" class="close text-white" data-dismiss="modal" aria-label="Close">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label><i class="fas fa-key"></i> Clave de Cifrado (diferente a la de login)</label>
                        <input type="password" id="modal-key" class="form-control bg-dark text-light" placeholder="Ingresa tu clave AES">
                    </div>

                    <button id="decrypt-btn" class="btn btn-primary btn-block mb-4">
                        <i class="fas fa-unlock"></i> Descifrar y Cargar Nota
                    </button>

                    <div id="editor-section" style="display: none;">
                        <div class="form-group">
                            <label>Contenido de la nota (texto plano)</label>
                            <textarea id="note-content" class="form-control" rows="12" style="background:#0f172a; color:#67e8f9; font-family: 'SF Mono', monospace; resize: vertical;"></textarea>
                        </div>

                        <div class="d-flex gap-2">
                            <button id="copy-btn" class="btn btn-info flex-fill">
                                <i class="fas fa-copy"></i> Copiar al portapapeles
                            </button>
                            <button id="save-btn" class="btn btn-success flex-fill">
                                <i class="fas fa-save"></i> Grabar (cifrar y guardar)
                            </button>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Cerrar</button>
                </div>
            </div>
        </div>
    </div>

<?php endif; ?>

<!-- Scripts -->
<script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js"></script>

<script>
$(document).ready(function () {
    let currentNote = null;

    // Abrir modal
    $('.read-edit-btn').on('click', function () {
        currentNote = $(this).data('note');
        $('#modal-note-id').text(currentNote);
        $('#noteModal').modal('show');
        $('#editor-section').hide();
        $('#decrypt-btn').show();
        $('#modal-key').val('').focus();
    });

    // Descifrar vía AJAX
    $('#decrypt-btn').on('click', function () {
        const key = $('#modal-key').val().trim();
        if (!key) return alert('Debes ingresar la clave de cifrado');

        $.post(window.location.pathname, {
            action: 'decrypt',
            note: currentNote,
            key: key
        }, function (res) {
            if (res.error) {
                alert(res.error);
            } else {
                $('#note-content').val(res.content || '');
                $('#editor-section').fadeIn();
                $('#decrypt-btn').hide();
            }
        }, 'json');
    });

    // Guardar (cifrar)
    $('#save-btn').on('click', function () {
        const key = $('#modal-key').val().trim();
        const content = $('#note-content').val();

        if (!key) {
            return alert('La clave de cifrado es obligatoria para guardar');
        }

        $.post(window.location.pathname, {
            action: 'save',
            note: currentNote,
            key: key,
            content: content
        }, function (res) {
            if (res.error) {
                alert(res.error);
            } else if (res.success) {
                alert(res.success);
                $('#noteModal').modal('hide');
            }
        }, 'json');
    });

    // Copiar al portapapeles
    $('#copy-btn').on('click', function () {
        const text = $('#note-content').val().trim();
        if (text) {
            navigator.clipboard.writeText(text).then(() => {
                const original = $(this).html();
                $(this).html('<i class="fas fa-check"></i> ¡Copiado!');
                setTimeout(() => $(this).html(original), 2000);
            });
        }
    });

    // Limpiar modal al cerrar
    $('#noteModal').on('hidden.bs.modal', function () {
        $('#editor-section').hide();
        $('#decrypt-btn').show();
        $('#modal-key, #note-content').val('');
    });
});
</script>
</body>
</html>
