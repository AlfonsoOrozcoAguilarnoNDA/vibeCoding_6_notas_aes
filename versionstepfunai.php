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
 * Single-File Encrypted Notes Vault
 * Developed by Step 3.5 Flash (StepFun)
 * Date: <?= date('Y-m-d') ?>
 * IP: <?= $_SERVER['REMOTE_ADDR'] ?? 'N/A' ?>
 * PHP Version: <?= phpversion() ?>
 */

session_start();

// ==================== CONFIGURATION ====================
define('VAULT_DIR', __DIR__ . '/vault/');
define('MAX_NOTES', 6);
define('MAX_FILE_SIZE', 4096);
define('LOGIN_HASH', '$2y$10$YourHashHere'); // Generate with: echo password_hash('vibekoder', PASSWORD_DEFAULT);

// ==================== SECURITY HELPERS ====================
function encryptData($data, $key) {
    $iv = random_bytes(16);
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return $iv . $encrypted;
}

function decryptData($encryptedData, $key) {
    if (strlen($encryptedData) < 16) return false;
    $iv = substr($encryptedData, 0, 16);
    $ciphertext = substr($encryptedData, 16);
    return openssl_decrypt($ciphertext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
}

function sanitize($data) {
    return htmlspecialchars(strip_tags(trim($data)), ENT_QUOTES, 'UTF-8');
}

// ==================== SESSION & LOGIN ====================
$isLoggedIn = isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $username = sanitize($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    
    if ($username === 'admin' && password_verify($password, LOGIN_HASH)) {
        $_SESSION['logged_in'] = true;
        $isLoggedIn = true;
    } else {
        $loginError = "Credenciales inválidas";
    }
}

if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ' . strtok($_SERVER["REQUEST_URI"], '?'));
    exit;
}

// ==================== VAULT MANAGEMENT ====================
if (!is_dir(VAULT_DIR)) {
    mkdir(VAULT_DIR, 0700, true);
}

// Initialize note files if they don't exist
for ($i = 1; $i <= MAX_NOTES; $i++) {
    $file = VAULT_DIR . "nota{$i}.aes";
    if (!file_exists($file)) {
        $emptyIv = random_bytes(16);
        file_put_contents($file, $emptyIv);
    }
}

// ==================== NOTE OPERATIONS ====================
$notes = [];
for ($i = 1; $i <= MAX_NOTES; $i++) {
    $file = VAULT_DIR . "nota{$i}.aes";
    $size = filesize($file);
    $writable = is_writable(VAULT_DIR);
    $notes[] = [
        'id' => $i,
        'filename' => "nota{$i}.aes",
        'size' => $size,
        'writable' => $writable,
        'content' => '',
        'encrypted' => true
    ];
}

// Handle AJAX operations
if ($isLoggedIn && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');
    $response = ['success' => false, 'message' => ''];
    
    $noteId = intval($_POST['note_id'] ?? 0);
    $encryptionKey = $_POST['encryption_key'] ?? '';
    
    if ($noteId < 1 || $noteId > MAX_NOTES) {
        $response['message'] = 'ID de nota inválido';
        echo json_encode($response);
        exit;
    }
    
    $file = VAULT_DIR . "nota{$noteId}.aes";
    
    switch ($_POST['action']) {
        case 'decrypt':
            if (empty($encryptionKey)) {
                $response['message'] = 'La clave de cifrado es requerida';
                break;
            }
            $encryptedData = file_get_contents($file);
            $decrypted = decryptData($encryptedData, $encryptionKey);
            if ($decrypted === false) {
                $response['message'] = 'Error al descifrar. Verifica la clave.';
            } else {
                $response['success'] = true;
                $response['data'] = $decrypted;
            }
            break;
            
        case 'encrypt':
            if (empty($encryptionKey)) {
                $response['message'] = 'La clave de cifrado es requerida';
                break;
            }
            $content = $_POST['content'] ?? '';
            $encrypted = encryptData($content, $encryptionKey);
            if (file_put_contents($file, $encrypted) !== false) {
                $response['success'] = true;
                $response['message'] = 'Nota guardada exitosamente';
            } else {
                $response['message'] = 'Error al guardar la nota';
            }
            break;
    }
    
    echo json_encode($response);
    exit;
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vault de Notas Cifradas</title>
    <!-- Bootstrap 4.6 -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome 5.15.4 -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #34495e;
            --accent-color: #3498db;
            --bg-light: #ecf0f1;
        }
        
        body {
            padding-top: 70px;
            padding-bottom: 60px;
            background-color: var(--bg-light);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .navbar {
            background-color: var(--primary-color) !important;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .navbar-brand {
            font-weight: 600;
            color: white !important;
        }
        
        .footer {
            position: fixed;
            bottom: 0;
            width: 100%;
            height: 60px;
            line-height: 60px;
            background-color: var(--primary-color);
            color: white;
            text-align: center;
            z-index: 1030;
        }
        
        .jumbotron {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            color: white;
            border-radius: 15px;
            margin-bottom: 30px;
            padding: 2rem 1rem;
        }
        
        .note-card {
            transition: transform 0.3s, box-shadow 0.3s;
            border: none;
            border-radius: 10px;
            overflow: hidden;
        }
        
        .note-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
        }
        
        .card-header {
            background-color: var(--accent-color);
            color: white;
            font-weight: 600;
        }
        
        .btn-primary {
            background-color: var(--accent-color);
            border-color: var(--accent-color);
        }
        
        .btn-primary:hover {
            background-color: #2980b9;
            border-color: #2980b9;
        }
        
        .modal-content {
            border-radius: 10px;
        }
        
        .encrypted-badge {
            background-color: #e74c3c;
            color: white;
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.8rem;
        }
        
        .writable-badge {
            background-color: #27ae60;
            color: white;
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.8rem;
        }
        
        .copy-btn {
            cursor: pointer;
        }
    </style>
</head>
<body>
    <?php if (!$isLoggedIn): ?>
        <!-- LOGIN FORM -->
        <div class="container">
            <div class="row justify-content-center align-items-center min-vh-100">
                <div class="col-md-6 col-lg-4">
                    <div class="card shadow">
                        <div class="card-header text-center py-4">
                            <h4 class="mb-0"><i class="fas fa-lock mr-2"></i>Vault de Notas</h4>
                        </div>
                        <div class="card-body p-4">
                            <?php if (isset($loginError)): ?>
                                <div class="alert alert-danger"><?= $loginError ?></div>
                            <?php endif; ?>
                            
                            <form method="POST">
                                <div class="form-group">
                                    <label><i class="fas fa-user mr-2"></i>Usuario</label>
                                    <input type="text" name="username" class="form-control" required autofocus>
                                </div>
                                <div class="form-group">
                                    <label><i class="fas fa-key mr-2"></i>Contraseña</label>
                                    <input type="password" name="password" class="form-control" required>
                                </div>
                                <button type="submit" name="login" class="btn btn-primary btn-block">
                                    <i class="fas fa-sign-in-alt mr-2"></i>Acceder
                                </button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    <?php else: ?>
        <!-- MAIN APPLICATION -->
        <nav class="navbar navbar-expand-lg navbar-dark fixed-top">
            <div class="container">
                <a class="navbar-brand" href="#">
                    <i class="fas fa-shield-alt mr-2"></i>Vault de Notas
                </a>
                <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav">
                    <span class="navbar-toggler-icon"></span>
                </button>
                <div class="collapse navbar-collapse" id="navbarNav">
                    <ul class="navbar-nav mr-auto">
                        <li class="nav-item active">
                            <a class="nav-link" href="#"><i class="fas fa-home mr-1"></i> Inicio</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#"><i class="fas fa-info-circle mr-1"></i> Acerca de</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="https://stepfun.com" target="_blank">
                                <i class="fas fa-external-link-alt mr-1"></i> StepFun
                            </a>
                        </li>
                    </ul>
                    <a href="?logout=1" class="btn btn-outline-light btn-sm">
                        <i class="fas fa-sign-out-alt mr-1"></i> Salir
                    </a>
                </div>
            </div>
        </nav>

        <div class="container mt-4">
            <div class="jumbotron text-center">
                <h1 class="display-4"><i class="fas fa-lock mr-3"></i>Bienvenido al Vault</h1>
                <p class="lead">Sistema seguro de notas cifradas con AES-256-CBC</p>
                <hr class="my-4 bg-light">
                <p>Cada nota está protegida con una clave única. Asegúrate de recordar tus claves.</p>
            </div>

            <div class="row">
                <?php foreach ($notes as $note): ?>
                <div class="col-md-4 col-lg-2 mb-4">
                    <div class="card note-card h-100">
                        <div class="card-header text-center py-3">
                            <h6 class="mb-0"><?= $note['filename'] ?></h6>
                        </div>
                        <div class="card-body text-center">
                            <div class="mb-3">
                                <i class="fas fa-file-alt fa-3x text-muted"></i>
                            </div>
                            <div class="mb-2">
                                <span class="encrypted-badge">
                                    <i class="fas fa-lock mr-1"></i> Cifrado
                                </span>
                            </div>
                            <div class="mb-3">
                                <small class="text-muted">
                                    <?= $note['writable'] ? 
                                        '<span class="writable-badge"><i class="fas fa-check mr-1"></i> Escritura OK</span>' : 
                                        '<span class="encrypted-badge"><i class="fas fa-exclamation-triangle mr-1"></i> Sin permisos</span>' ?>
                                </small>
                            </div>
                            <div class="mb-3">
                                <small class="text-muted">Tamaño: <?= $note['size'] ?> bytes</small>
                            </div>
                            <button class="btn btn-primary btn-sm btn-block mb-2" 
                                    onclick="openNoteModal(<?= $note['id'] ?>)">
                                <i class="fas fa-edit mr-1"></i> Leer/Editar
                            </button>
                            <button class="btn btn-success btn-sm btn-block" 
                                    onclick="copyNoteText(<?= $note['id'] ?>)">
                                <i class="fas fa-copy mr-1"></i> Copiar
                            </button>
                        </div>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- NOTE MODAL -->
        <div class="modal fade" id="noteModal" tabindex="-1" role="dialog">
            <div class="modal-dialog modal-lg" role="document">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">
                            <i class="fas fa-edit mr-2"></i>Editar Nota
                        </h5>
                        <button type="button" class="close" data-dismiss="modal">
                            <span>&times;</span>
                        </button>
                    </div>
                    <div class="modal-body">
                        <form id="noteForm">
                            <input type="hidden" id="noteId" name="note_id">
                            <div class="form-group">
                                <label><i class="fas fa-key mr-2"></i>Clave de Cifrado</label>
                                <input type="password" id="encryptionKey" class="form-control" required>
                                <small class="form-text text-muted">
                                    Esta clave es diferente a la de login. Guárdala segura.
                                </small>
                            </div>
                            <div class="form-group">
                                <label><i class="fas fa-file-alt mr-2"></i>Contenido de la Nota</label>
                                <textarea id="noteContent" class="form-control" rows="10" 
                                          placeholder="Escribe tu nota aquí..."></textarea>
                            </div>
                        </form>
                        <div id="alertArea"></div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-dismiss="modal">
                            <i class="fas fa-times mr-1"></i> Cancelar
                        </button>
                        <button type="button" class="btn btn-primary" onclick="saveNote()">
                            <i class="fas fa-save mr-1"></i> Grabar
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- FOOTER -->
        <footer class="footer">
            <div class="container">
                <span class="text-white-50">
                    <i class="fas fa-microchip mr-2"></i>
                    Modelo: Step 3.5 Flash (StepFun) | 
                    IP: <?= $_SERVER['REMOTE_ADDR'] ?? 'N/A' ?> | 
                    PHP: <?= phpversion() ?>
                </span>
            </div>
        </footer>
    <?php endif; ?>

    <!-- SCRIPTS -->
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
    // ==================== JAVASCRIPT FUNCTIONS ====================
    let currentNoteId = null;

    function openNoteModal(noteId) {
        currentNoteId = noteId;
        $('#noteId').val(noteId);
        $('#encryptionKey').val('');
        $('#noteContent').val('');
        $('#alertArea').empty();
        $('#noteModal').modal('show');
        
        // Try to decrypt with empty key to show placeholder
        decryptNote(noteId, '');
    }

    function decryptNote(noteId, key) {
        if (!key) {
            $('#noteContent').val('=== CONTENIDO CIFRADO ===\n\nIngresa la clave de cifrado para ver/editar esta nota.');
            return;
        }
        
        $.ajax({
            url: window.location.href.split('?')[0],
            type: 'POST',
            data: {
                action: 'decrypt',
                note_id: noteId,
                encryption_key: key
            },
            success: function(response) {
                if (response.success) {
                    $('#noteContent').val(response.data);
                } else {
                    $('#noteContent').val('=== ERROR ===\n\n' + response.message);
                }
            },
            error: function() {
                $('#noteContent').val('=== ERROR ===\n\nNo se pudo conectar con el servidor.');
            }
        });
    }

    function saveNote() {
        const noteId = $('#noteId').val();
        const key = $('#encryptionKey').val();
        const content = $('#noteContent').val();
        
        if (!key) {
            showAlert('La clave de cifrado es requerida', 'danger');
            return;
        }
        
        $.ajax({
            url: window.location.href.split('?')[0],
            type: 'POST',
            data: {
                action: 'encrypt',
                note_id: noteId,
                encryption_key: key,
                content: content
            },
            success: function(response) {
                if (response.success) {
                    showAlert('Nota guardada exitosamente', 'success');
                    setTimeout(() => $('#noteModal').modal('hide'), 1500);
                } else {
                    showAlert(response.message, 'danger');
                }
            },
            error: function() {
                showAlert('Error al conectar con el servidor', 'danger');
            }
        });
    }

    function copyNoteText(noteId) {
        // First decrypt to get the content
        const key = prompt('Ingresa la clave de cifrado para copiar el contenido:');
        if (!key) return;
        
        $.ajax({
            url: window.location.href.split('?')[0],
            type: 'POST',
            data: {
                action: 'decrypt',
                note_id: noteId,
                encryption_key: key
            },
            success: function(response) {
                if (response.success) {
                    navigator.clipboard.writeText(response.data).then(() => {
                        showAlert('Contenido copiado al portapapeles', 'success');
                    }).catch(() => {
                        // Fallback for older browsers
                        const textarea = document.createElement('textarea');
                        textarea.value = response.data;
                        document.body.appendChild(textarea);
                        textarea.select();
                        document.execCommand('copy');
                        document.body.removeChild(textarea);
                        showAlert('Contenido copiado al portapapeles', 'success');
                    });
                } else {
                    showAlert('No se pudo copiar: ' + response.message, 'danger');
                }
            }
        });
    }

    function showAlert(message, type) {
        const alertHtml = `
            <div class="alert alert-${type} alert-dismissible fade show" role="alert">
                ${message}
                <button type="button" class="close" data-dismiss="alert">
                    <span>&times;</span>
                </button>
            </div>
        `;
        $('#alertArea').html(alertHtml);
    }

    // Listen for encryption key changes to auto-decrypt
    $(document).ready(function() {
        $('#encryptionKey').on('input', function() {
            if (currentNoteId && $(this).val().length > 0) {
                decryptNote(currentNoteId, $(this).val());
            }
        });
    });
    </script>
</body>
</html>
