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
 * Secure Notes Vault - Single File PHP Application
 * PHP 8.x | Bootstrap 4.6.x | Font Awesome 5.15.4 | jQuery
 * 
 * Security: AES-256-CBC with IV per file
 */

// --- Configuration ---
$ADMIN_PASSWORD_HASH = '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi'; // hash of 'vibekoder'
$NOTES_DIR = __DIR__ . '/notes/';
$MAX_FILE_SIZE = 4096;
$SESSION_NAME = 'SecureVaultSession';

// --- Session Management ---
if (session_status() === PHP_SESSION_NONE) {
    session_name($SESSION_NAME);
    session_start();
}

// --- Helper Functions ---
function isLoggedIn(): bool {
    return isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true;
}

function redirect(string $url): void {
    header("Location: $url");
    exit;
}

function sanitize(string $data): string {
    return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
}

function getPhpVersion(): string {
    return PHP_VERSION;
}

function getUserIp(): string {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
    return filter_var($ip, FILTER_VALIDATE_IP) ?: 'Unknown';
}

// --- Encryption Functions ---
function encryptData(string $data, string $key): string {
    $iv = random_bytes(16); // AES-256-CBC requires 16 bytes IV
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $encrypted);
}

function decryptData(string $data, string $key): ?string {
    $raw = base64_decode($data);
    if ($raw === false || strlen($raw) < 17) return null;
    
    $iv = substr($raw, 0, 16);
    $encrypted = substr($raw, 16);
    
    $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return $decrypted !== false ? $decrypted : null;
}

// --- File Management ---
function ensureNotesDirectory(): bool {
    global $NOTES_DIR;
    if (!is_dir($NOTES_DIR)) {
        return @mkdir($NOTES_DIR, 0755, true);
    }
    return is_writable($NOTES_DIR);
}

function getNoteFiles(): array {
    global $NOTES_DIR;
    $files = [];
    for ($i = 1; $i <= 6; $i++) {
        $filename = "nota$i.aes";
        $filepath = $NOTES_DIR . $filename;
        $files[] = [
            'id' => $i,
            'filename' => $filename,
            'filepath' => $filepath,
            'exists' => file_exists($filepath),
            'size' => file_exists($filepath) ? filesize($filepath) : 0
        ];
    }
    return $files;
}

function createEmptyNote(string $filepath): bool {
    if (!file_exists($filepath)) {
        return @file_put_contents($filepath, '') !== false;
    }
    return true;
}

function readNote(string $filepath): string {
    if (!file_exists($filepath)) return '';
    $content = @file_get_contents($filepath);
    return $content !== false ? $content : '';
}

function writeNote(string $filepath, string $content): bool {
    global $MAX_FILE_SIZE;
    if (strlen($content) > $MAX_FILE_SIZE) return false;
    return @file_put_contents($filepath, $content) !== false;
}

// --- Handle Requests ---
$error = '';
$success = '';

// Login Handler
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'login') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    if ($username === 'admin' && password_verify($password, $ADMIN_PASSWORD_HASH)) {
        $_SESSION['authenticated'] = true;
        redirect($_SERVER['PHP_SELF']);
    } else {
        $error = 'Credenciales incorrectas';
    }
}

// Logout Handler
if (isset($_GET['logout'])) {
    session_destroy();
    redirect($_SERVER['PHP_SELF']);
}

// AJAX API Handler
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_SERVER['HTTP_X_REQUESTED_WITH']) && 
    strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
    
    header('Content-Type: application/json');
    
    if (!isLoggedIn()) {
        echo json_encode(['success' => false, 'error' => 'No autenticado']);
        exit;
    }
    
    $action = $_POST['api_action'] ?? '';
    $noteId = intval($_POST['note_id'] ?? 0);
    $cryptoKey = $_POST['crypto_key'] ?? '';
    $content = $_POST['content'] ?? '';
    
    if ($noteId < 1 || $noteId > 6) {
        echo json_encode(['success' => false, 'error' => 'ID de nota inválido']);
        exit;
    }
    
    $filepath = $NOTES_DIR . "nota$noteId.aes";
    
    switch ($action) {
        case 'decrypt':
            if (empty($cryptoKey)) {
                echo json_encode(['success' => false, 'error' => 'Clave de cifrado requerida']);
                exit;
            }
            $encrypted = readNote($filepath);
            if (empty($encrypted)) {
                echo json_encode(['success' => true, 'content' => '', 'empty' => true]);
                exit;
            }
            $decrypted = decryptData($encrypted, $cryptoKey);
            if ($decrypted === null) {
                echo json_encode(['success' => false, 'error' => 'Clave incorrecta o archivo corrupto']);
            } else {
                echo json_encode(['success' => true, 'content' => $decrypted]);
            }
            break;
            
        case 'encrypt':
            if (empty($cryptoKey)) {
                echo json_encode(['success' => false, 'error' => 'Clave de cifrado requerida']);
                exit;
            }
            $encrypted = encryptData($content, $cryptoKey);
            if (writeNote($filepath, $encrypted)) {
                echo json_encode(['success' => true, 'message' => 'Nota guardada correctamente']);
            } else {
                echo json_encode(['success' => false, 'error' => 'Error al guardar el archivo']);
            }
            break;
            
        default:
            echo json_encode(['success' => false, 'error' => 'Acción no válida']);
    }
    exit;
}

// Initialize notes directory and files if logged in
if (isLoggedIn()) {
    ensureNotesDirectory();
    $notes = getNoteFiles();
    foreach ($notes as $note) {
        if (!$note['exists']) {
            createEmptyNote($note['filepath']);
        }
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Notes Vault</title>
    
    <!-- Bootstrap 4.6.2 CSS -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css" integrity="sha384-xOolHFLEh07PJGoPkLv1IbcEPTNtaed2xpHsD9ESMhqIYd0nLMwNLD69Npy4HI+N" crossorigin="anonymous">
    
    <!-- Font Awesome 5.15.4 -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css" integrity="sha512-1ycn6IcaQQ40/MKBW2W4Rhis/DbILU74C1vSrLJxCq57o941Ym01SwNsOMqvEBFlcgUa6xLiPY/NS5R+E6ztJQ==" crossorigin="anonymous" referrerpolicy="no-referrer" />
    
    <style>
        :root {
            --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --dark-bg: #1a1a2e;
            --card-bg: #16213e;
            --accent: #e94560;
        }
        
        body {
            background: var(--dark-bg);
            min-height: 100vh;
            color: #fff;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            padding-top: 70px;
            padding-bottom: 60px;
        }
        
        .navbar {
            background: rgba(22, 33, 62, 0.95) !important;
            backdrop-filter: blur(10px);
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        
        .navbar-brand {
            font-weight: 700;
            background: var(--primary-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .jumbotron {
            background: var(--primary-gradient);
            border-radius: 20px;
            margin-top: 20px;
            box-shadow: 0 10px 40px rgba(102, 126, 234, 0.3);
        }
        
        .card {
            background: var(--card-bg);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 15px;
            transition: all 0.3s ease;
            height: 100%;
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(233, 69, 96, 0.2);
            border-color: var(--accent);
        }
        
        .card-header {
            background: rgba(233, 69, 96, 0.1);
            border-bottom: 1px solid rgba(233, 69, 96, 0.2);
            border-radius: 15px 15px 0 0 !important;
            font-weight: 600;
        }
        
        .encrypted-preview {
            font-family: 'Courier New', monospace;
            font-size: 0.75rem;
            color: #6c757d;
            word-break: break-all;
            max-height: 80px;
            overflow: hidden;
        }
        
        .btn-custom {
            background: var(--primary-gradient);
            border: none;
            border-radius: 25px;
            padding: 8px 20px;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .btn-custom:hover {
            transform: scale(1.05);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
        }
        
        .btn-outline-custom {
            border: 2px solid var(--accent);
            color: var(--accent);
            border-radius: 25px;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .btn-outline-custom:hover {
            background: var(--accent);
            color: white;
        }
        
        .login-container {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: var(--primary-gradient);
        }
        
        .login-card {
            background: var(--card-bg);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            width: 100%;
            max-width: 400px;
        }
        
        .form-control {
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            color: white;
            border-radius: 10px;
        }
        
        .form-control:focus {
            background: rgba(255,255,255,0.1);
            border-color: var(--accent);
            color: white;
            box-shadow: 0 0 0 0.2rem rgba(233, 69, 96, 0.25);
        }
        
        .footer {
            background: rgba(22, 33, 62, 0.95);
            border-top: 1px solid rgba(255,255,255,0.1);
            font-size: 0.85rem;
        }
        
        .modal-content {
            background: var(--card-bg);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 20px;
        }
        
        .modal-header {
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        
        .modal-footer {
            border-top: 1px solid rgba(255,255,255,0.1);
        }
        
        .badge-custom {
            background: var(--accent);
            font-size: 0.7rem;
            padding: 5px 10px;
            border-radius: 10px;
        }
        
        .status-indicator {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 5px;
        }
        
        .status-ok { background: #28a745; }
        .status-warning { background: #ffc107; }
        .status-error { background: #dc3545; }
    </style>
</head>
<body>

<?php if (!isLoggedIn()): ?>
    <!-- Login Screen -->
    <div class="login-container">
        <div class="login-card">
            <div class="text-center mb-4">
                <i class="fas fa-shield-alt fa-4x mb-3" style="color: var(--accent);"></i>
                <h2 class="font-weight-bold">Secure Vault</h2>
                <p class="text-muted">Autenticación requerida</p>
            </div>
            
            <?php if ($error): ?>
                <div class="alert alert-danger alert-dismissible fade show" role="alert">
                    <i class="fas fa-exclamation-circle mr-2"></i><?php echo sanitize($error); ?>
                    <button type="button" class="close" data-dismiss="alert">
                        <span>&times;</span>
                    </button>
                </div>
            <?php endif; ?>
            
            <form method="POST" action="">
                <input type="hidden" name="action" value="login">
                
                <div class="form-group">
                    <label><i class="fas fa-user mr-2"></i>Usuario</label>
                    <input type="text" name="username" class="form-control" placeholder="admin" required autofocus>
                </div>
                
                <div class="form-group">
                    <label><i class="fas fa-lock mr-2"></i>Contraseña</label>
                    <input type="password" name="password" class="form-control" placeholder="••••••••" required>
                </div>
                
                <button type="submit" class="btn btn-custom btn-block mt-4">
                    <i class="fas fa-sign-in-alt mr-2"></i>Acceder
                </button>
            </form>
            
            <div class="text-center mt-3 text-muted small">
                <i class="fas fa-code mr-1"></i>Powered by PHP <?php echo getPhpVersion(); ?>
            </div>
        </div>
    </div>

<?php else: ?>
    <!-- Main Application -->
    
    <!-- Fixed Navbar -->
    <nav class="navbar navbar-expand-lg navbar-dark fixed-top">
        <div class="container">
            <a class="navbar-brand" href="#">
                <i class="fas fa-shield-alt mr-2"></i>Secure Vault
            </a>
            
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav mr-auto">
                    <li class="nav-item active">
                        <a class="nav-link" href="#"><i class="fas fa-home mr-1"></i>Inicio</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#" data-toggle="modal" data-target="#aboutModal">
                            <i class="fas fa-info-circle mr-1"></i>Acerca de
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="https://www.php.net/manual/es/book.openssl.php" target="_blank">
                            <i class="fas fa-external-link-alt mr-1"></i>OpenSSL Docs
                        </a>
                    </li>
                </ul>
                
                <span class="navbar-text mr-3">
                    <span class="badge badge-custom">
                        <i class="fas fa-robot mr-1"></i>Kimi K2.5
                    </span>
                </span>
                
                <a href="?logout=1" class="btn btn-outline-danger btn-sm">
                    <i class="fas fa-sign-out-alt mr-1"></i>Salir
                </a>
            </div>
        </div>
    </nav>
    
    <!-- Main Content -->
    <div class="container">
        <!-- Jumbotron -->
        <div class="jumbotron text-center">
            <h1 class="display-4 font-weight-bold mb-3">
                <i class="fas fa-lock mr-3"></i>Bienvenido al Vault
            </h1>
            <p class="lead">
                Sistema de notas cifradas con <strong>AES-256-CBC</strong>. 
                Tus datos se almacenan de forma segura y solo tú puedes descifrarlos con tu clave privada.
            </p>
            <hr class="my-4" style="border-color: rgba(255,255,255,0.3);">
            <div class="row text-center">
                <div class="col-md-4">
                    <i class="fas fa-key fa-2x mb-2"></i>
                    <p class="mb-0">Cifrado Fuerte</p>
                </div>
                <div class="col-md-4">
                    <i class="fas fa-user-shield fa-2x mb-2"></i>
                    <p class="mb-0">IV Único por Archivo</p>
                </div>
                <div class="col-md-4">
                    <i class="fas fa-server fa-2x mb-2"></i>
                    <p class="mb-0">Almacenamiento Local</p>
                </div>
            </div>
        </div>
        
        <!-- Notes Grid -->
        <div class="row">
            <?php 
            $notes = getNoteFiles();
            $isWritable = ensureNotesDirectory();
            
            foreach ($notes as $note): 
                $content = readNote($note['filepath']);
                $isEmpty = empty($content);
            ?>
                <div class="col-md-4 mb-4">
                    <div class="card">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <span>
                                <i class="fas fa-file-alt mr-2"></i><?php echo sanitize($note['filename']); ?>
                            </span>
                            <span class="status-indicator <?php echo $isEmpty ? 'status-warning' : 'status-ok'; ?>"></span>
                        </div>
                        <div class="card-body">
                            <p class="text-muted small mb-2">
                                <i class="fas fa-hdd mr-1"></i>
                                <?php echo $isEmpty ? 'Vacío' : number_format($note['size']) . ' bytes'; ?>
                            </p>
                            
                            <div class="encrypted-preview mb-3 p-2 bg-dark rounded">
                                <?php if ($isEmpty): ?>
                                    <em class="text-muted">Sin contenido cifrado...</em>
                                <?php else: ?>
                                    <?php echo sanitize(substr($content, 0, 100)) . '...'; ?>
                                <?php endif; ?>
                            </div>
                            
                            <div class="d-flex justify-content-between">
                                <button class="btn btn-custom btn-sm" onclick="openNoteModal(<?php echo $note['id']; ?>)">
                                    <i class="fas fa-eye mr-1"></i>Leer/Editar
                                </button>
                                
                                <button class="btn btn-outline-secondary btn-sm" onclick="copyNote(<?php echo $note['id']; ?>)" id="copy-btn-<?php echo $note['id']; ?>">
                                    <i class="fas fa-copy mr-1"></i>Copiar
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
        
        <?php if (!$isWritable): ?>
            <div class="alert alert-danger mt-4">
                <i class="fas fa-exclamation-triangle mr-2"></i>
                <strong>Error:</strong> El directorio de notas no tiene permisos de escritura.
            </div>
        <?php endif; ?>
    </div>
    
    <!-- Fixed Footer -->
    <footer class="footer fixed-bottom py-3">
        <div class="container">
            <div class="row">
                <div class="col-md-6 text-center text-md-left">
                    <span class="text-muted">
                        <i class="fas fa-code mr-1"></i>
                        PHP <?php echo getPhpVersion(); ?> | 
                        <i class="fas fa-network-wired mr-1 ml-2"></i>
                        IP: <?php echo sanitize(getUserIp()); ?>
                    </span>
                </div>
                <div class="col-md-6 text-center text-md-right">
                    <span class="text-muted">
                        <i class="fas fa-shield-alt mr-1"></i>
                        Secure Vault v1.0 | 
                        <span class="badge badge-success ml-1">AES-256-CBC</span>
                    </span>
                </div>
            </div>
        </div>
    </footer>
    
    <!-- Note Modal -->
    <div class="modal fade" id="noteModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-edit mr-2"></i>
                        <span id="modalNoteTitle">Nota</span>
                    </h5>
                    <button type="button" class="close text-white" data-dismiss="modal">
                        <span>&times;</span>
                    </button>
                </div>
                <div class="modal-body">
                    <input type="hidden" id="currentNoteId">
                    
                    <!-- Crypto Key Input -->
                    <div class="form-group">
                        <label class="font-weight-bold">
                            <i class="fas fa-key mr-2"></i>Clave de Cifrado
                        </label>
                        <div class="input-group">
                            <input type="password" class="form-control" id="cryptoKey" placeholder="Ingresa la clave para descifrar/encriptar...">
                            <div class="input-group-append">
                                <button class="btn btn-outline-secondary" type="button" onclick="toggleKeyVisibility()">
                                    <i class="fas fa-eye" id="eyeIcon"></i>
                                </button>
                            </div>
                        </div>
                        <small class="form-text text-muted">
                            Esta clave se usa para cifrar/descifrar el contenido. No se almacena en el servidor.
                        </small>
                    </div>
                    
                    <hr class="border-secondary">
                    
                    <!-- Content Textarea -->
                    <div class="form-group">
                        <label class="font-weight-bold">
                            <i class="fas fa-align-left mr-2"></i>Contenido
                        </label>
                        <textarea class="form-control" id="noteContent" rows="10" placeholder="El contenido descifrado aparecerá aquí..."></textarea>
                    </div>
                    
                    <!-- Alerts -->
                    <div id="modalAlert" class="alert d-none" role="alert"></div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">
                        <i class="fas fa-times mr-1"></i>Cerrar
                    </button>
                    <button type="button" class="btn btn-info" onclick="decryptNote()">
                        <i class="fas fa-unlock mr-1"></i>Descifrar
                    </button>
                    <button type="button" class="btn btn-custom" onclick="encryptAndSave()">
                        <i class="fas fa-save mr-1"></i>Grabar
                    </button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- About Modal -->
    <div class="modal fade" id="aboutModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-info-circle mr-2"></i>Acerca de Secure Vault
                    </h5>
                    <button type="button" class="close text-white" data-dismiss="modal">
                        <span>&times;</span>
                    </button>
                </div>
                <div class="modal-body">
                    <h6 class="font-weight-bold">Especificaciones Técnicas:</h6>
                    <ul class="list-unstyled">
                        <li><i class="fas fa-check text-success mr-2"></i>PHP <?php echo getPhpVersion(); ?></li>
                        <li><i class="fas fa-check text-success mr-2"></i>AES-256-CBC Encryption</li>
                        <li><i class="fas fa-check text-success mr-2"></i>IV (Initialization Vector) único por archivo</li>
                        <li><i class="fas fa-check text-success mr-2"></i>Base64 encoding para almacenamiento</li>
                        <li><i class="fas fa-check text-success mr-2"></i>Password hashing con bcrypt</li>
                    </ul>
                    <hr class="border-secondary">
                    <p class="text-muted small mb-0">
                        Desarrollado con <i class="fas fa-heart text-danger mx-1"></i> por Kimi K2.5
                    </p>
                </div>
            </div>
        </div>
    </div>

<?php endif; ?>

<!-- jQuery 3.6.0 -->
<script src="https://code.jquery.com/jquery-3.6.0.min.js" integrity="sha256-/xUj+3OJU5yExlq6GSYGSHk7tPXikynS7ogEvDej/m4=" crossorigin="anonymous"></script>

<!-- Bootstrap 4.6.2 Bundle -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-Fy6S3B9q64WdZWQUiU+q4/2Lc9npb8tCaSX9FK7E8HnRr0Jz8D6OP9dO5Vg3Q9ct" crossorigin="anonymous"></script>

<?php if (isLoggedIn()): ?>
<script>
let currentDecryptedContent = '';

function openNoteModal(noteId) {
    $('#currentNoteId').val(noteId);
    $('#modalNoteTitle').text('Nota #' + noteId);
    $('#noteContent').val('').attr('readonly', true).attr('placeholder', 'Presiona "Descifrar" para ver el contenido...');
    $('#cryptoKey').val('');
    $('#modalAlert').addClass('d-none').removeClass('alert-success alert-danger');
    currentDecryptedContent = '';
    $('#noteModal').modal('show');
}

function toggleKeyVisibility() {
    const input = $('#cryptoKey');
    const icon = $('#eyeIcon');
    if (input.attr('type') === 'password') {
        input.attr('type', 'text');
        icon.removeClass('fa-eye').addClass('fa-eye-slash');
    } else {
        input.attr('type', 'password');
        icon.removeClass('fa-eye-slash').addClass('fa-eye');
    }
}

function showModalAlert(message, type) {
    const alert = $('#modalAlert');
    alert.removeClass('d-none alert-success alert-danger').addClass('alert-' + type).text(message);
}

function decryptNote() {
    const noteId = $('#currentNoteId').val();
    const cryptoKey = $('#cryptoKey').val().trim();
    
    if (!cryptoKey) {
        showModalAlert('Por favor ingresa la clave de cifrado', 'danger');
        return;
    }
    
    $.ajax({
        url: '',
        type: 'POST',
        data: {
            api_action: 'decrypt',
            note_id: noteId,
            crypto_key: cryptoKey
        },
        headers: {'X-Requested-With': 'XMLHttpRequest'},
        success: function(response) {
            if (response.success) {
                $('#noteContent').val(response.content).attr('readonly', false);
                currentDecryptedContent = response.content;
                showModalAlert('Contenido descifrado correctamente', 'success');
            } else {
                $('#noteContent').val('').attr('readonly', true);
                showModalAlert(response.error || 'Error al descifrar', 'danger');
            }
        },
        error: function() {
            showModalAlert('Error de conexión', 'danger');
        }
    });
}

function encryptAndSave() {
    const noteId = $('#currentNoteId').val();
    const cryptoKey = $('#cryptoKey').val().trim();
    const content = $('#noteContent').val();
    
    if (!cryptoKey) {
        showModalAlert('Por favor ingresa la clave de cifrado', 'danger');
        return;
    }
    
    $.ajax({
        url: '',
        type: 'POST',
        data: {
            api_action: 'encrypt',
            note_id: noteId,
            crypto_key: cryptoKey,
            content: content
        },
        headers: {'X-Requested-With': 'XMLHttpRequest'},
        success: function(response) {
            if (response.success) {
                showModalAlert('Nota guardada y cifrada correctamente', 'success');
                setTimeout(() => location.reload(), 1000);
            } else {
                showModalAlert(response.error || 'Error al guardar', 'danger');
            }
        },
        error: function() {
            showModalAlert('Error de conexión', 'danger');
        }
    });
}

function copyNote(noteId) {
    // Try to get from cache or prompt for key
    const cryptoKey = prompt('Para copiar, ingresa la clave de cifrado de la Nota #' + noteId + ':');
    
    if (!cryptoKey) return;
    
    $.ajax({
        url: '',
        type: 'POST',
        data: {
            api_action: 'decrypt',
            note_id: noteId,
            crypto_key: cryptoKey
        },
        headers: {'X-Requested-With': 'XMLHttpRequest'},
        success: function(response) {
            if (response.success) {
                navigator.clipboard.writeText(response.content).then(function() {
                    const btn = $('#copy-btn-' + noteId);
                    const originalHtml = btn.html();
                    btn.html('<i class="fas fa-check mr-1"></i>Copiado').removeClass('btn-outline-secondary').addClass('btn-success');
                    setTimeout(() => {
                        btn.html(originalHtml).removeClass('btn-success').addClass('btn-outline-secondary');
                    }, 2000);
                });
            } else {
                alert('Clave incorrecta');
            }
        }
    });
}
</script>
<?php endif; ?>

</body>
</html>
