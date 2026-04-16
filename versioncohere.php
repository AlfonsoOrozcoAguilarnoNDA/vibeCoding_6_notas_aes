<?php
/*
Copyright 2026
Alfonso Orozco Aguilar
Licencia MIT

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
session_start();

// Configuración inicial
$requiredFiles = ['nota1.aes', 'nota2.aes', 'nota3.aes', 'nota4.aes', 'nota5.aes', 'nota6.aes'];
$dataDir = __DIR__;
$passwordHash = '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi'; // Hash de 'vibekoder'

// Funciones de cifrado y descifrado
function encryptData($data, $key) {
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
    $encrypted = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);
    return base64_encode($iv . $encrypted);
}

function decryptData($data, $key) {
    $data = base64_decode($data);
    $iv = substr($data, 0, openssl_cipher_iv_length('aes-256-cbc'));
    $encrypted = substr($data, openssl_cipher_iv_length('aes-256-cbc'));
    return openssl_decrypt($encrypted, 'aes-256-cbc', $key, 0, $iv);
}

// Verificar y crear archivos si no existen
foreach ($requiredFiles as $file) {
    $filePath = "$dataDir/$file";
    if (!file_exists($filePath)) {
        file_put_contents($filePath, '');
    }
}

// Verificar permisos de escritura
if (!is_writable($dataDir)) {
    die('<div class="alert alert-danger">El directorio no tiene permisos de escritura.</div>');
}

// Procesar login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username']) && isset($_POST['password'])) {
    if ($_POST['username'] === 'admin' && password_verify($_POST['password'], $passwordHash)) {
        $_SESSION['logged_in'] = true;
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit();
    } else {
        $loginError = 'Credenciales incorrectas.';
    }
}

// Cerrar sesión
if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit();
}

// Verificar si el usuario está logueado
if (!isset($_SESSION['logged_in'])) {
    echo '
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Login - Vault</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.6.0/css/bootstrap.min.css">
        <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">Login</div>
                        <div class="card-body">
                            ' . (isset($loginError) ? '<div class="alert alert-danger">' . $loginError . '</div>' : '') . '
                            <form method="POST">
                                <div class="form-group">
                                    <label for="username">Usuario</label>
                                    <input type="text" class="form-control" id="username" name="username" required>
                                </div>
                                <div class="form-group">
                                    <label for="password">Contraseña</label>
                                    <input type="password" class="form-control" id="password" name="password" required>
                                </div>
                                <button type="submit" class="btn btn-primary">Ingresar</button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>';
    exit();
}

?><!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Vault - Vibecoding</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.6.0/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.6.0/js/bootstrap.bundle.min.js"></script>
    <style>
        body { padding-top: 56px; }
        .navbar, .footer { position: fixed; width: 100%; }
        .footer { bottom: 0; }
        .card { cursor: pointer; }
    </style>
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark fixed-top">
        <a class="navbar-brand" href="#">Vault <small>(Command Model)</small></a>
        <div class="collapse navbar-collapse">
            <ul class="navbar-nav mr-auto">
                <li class="nav-item"><a class="nav-link" href="#">Inicio</a></li>
                <li class="nav-item"><a class="nav-link" href="#">Acerca de</a></li>
                <li class="nav-item"><a class="nav-link" href="https://vibecoding.com" target="_blank">Vibecoding</a></li>
            </ul>
            <a href="?logout" class="btn btn-outline-danger">Salir</a>
        </div>
    </nav>

    <!-- Contenido Principal -->
    <div class="container mt-5">
        <div class="jumbotron text-center">
            <h1 class="display-4">Bienvenido al Vault</h1>
            <p class="lead">Gestiona tus notas cifradas de manera segura.</p>
        </div>

        <div class="row">
            <?php foreach ($requiredFiles as $index => $file): ?>
            <?php $noteNumber = $index + 1; ?>
            <div class="col-md-4 mb-4">
                <div class="card h-100" data-toggle="modal" data-target="#noteModal<?=$noteNumber?>">
                    <div class="card-body">
                        <h5 class="card-title">Nota <?=$noteNumber?></h5>
                        <p class="card-text"><?php 
                            $content = file_get_contents("$dataDir/$file");
                            echo strlen($content) ? 'Contenido cifrado' : 'Vacía';
                        ?></p>
                    </div>
                </div>
            </div>

            <!-- Modal para cada nota -->
            <div class="modal fade" id="noteModal<?=$noteNumber?>" tabindex="-1">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">Nota <?=$noteNumber?></h5>
                            <button type="button" class="close" data-dismiss="modal">&times;</button>
                        </div>
                        <div class="modal-body">
                            <form id="noteForm<?=$noteNumber?>">
                                <div class="form-group">
                                    <label for="encryptionKey<?=$noteNumber?>">Clave de Cifrado</label>
                                    <input type="password" class="form-control" id="encryptionKey<?=$noteNumber?>" required>
                                </div>
                                <div class="form-group">
                                    <label for="noteContent<?=$noteNumber?>">Contenido</label>
                                    <textarea class="form-control" id="noteContent<?=$noteNumber?>" rows="10" readonly></textarea>
                                </div>
                                <button type="button" class="btn btn-primary" onclick="toggleEdit(<?=$noteNumber?>)">
                                    <i id="editIcon<?=$noteNumber?>" class="fas fa-lock"></i> Leer/Editar
                                </button>
                                <button type="submit" class="btn btn-success" disabled>Grabar</button>
                                <button type="button" class="btn btn-secondary" onclick="copyToClipboard(<?=$noteNumber?>)">
                                    <i class="fas fa-copy"></i> Copiar
                                </button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
            <script>
            $(document).ready(function() {
                $('#noteModal<?=$noteNumber?>').on('shown.bs.modal', function() {
                    $('#encryptionKey<?=$noteNumber?>').focus();
                });

                $('#noteForm<?=$noteNumber?>').submit(function(e) {
                    e.preventDefault();
                    const key = $('#encryptionKey<?=$noteNumber?>').val();
                    const content = $('#noteContent<?=$noteNumber?>').val();
                    $.ajax({
                        url: '<?=$_SERVER['PHP_SELF']?>',
                        method: 'POST',
                        data: {
                            action: 'save',
                            file: '<?=$file?>',
                            key: key,
                            content: content
                        },
                        success: function() {
                            alert('Nota guardada exitosamente');
                            location.reload();
                        }
                    });
                });
            });

            function loadNote<?=$noteNumber?>() {
                const key = $('#encryptionKey<?=$noteNumber?>').val();
                if (key.length < 8) return;
                
                $.ajax({
                    url: '<?=$_SERVER['PHP_SELF']?>',
                    method: 'POST',
                    data: {
                        action: 'load',
                        file: '<?=$file?>',
                        key: key
                    },
                    success: function(response) {
                        $('#noteContent<?=$noteNumber?>').val(response).prop('readonly', false);
                        $('#editIcon<?=$noteNumber?>').removeClass('fa-lock').addClass('fa-edit');
                        $('#noteForm<?=$noteNumber?> button[type="submit"]').prop('disabled', false);
                    },
                    error: function() {
                        alert('Clave incorrecta o error al descifrar');
                    }
                });
            }

            function toggleEdit(noteNumber) {
                const textarea = $('#noteContent' + noteNumber);
                const icon = $('#editIcon' + noteNumber);
                if (textarea.prop('readonly')) {
                    loadNote(noteNumber);
                } else {
                    textarea.prop('readonly', true);
                    icon.removeClass('fa-edit').addClass('fa-lock');
                }
            }

            function copyToClipboard(noteNumber) {
                const content = $('#noteContent' + noteNumber).val();
                navigator.clipboard.writeText(content).then(() => {
                    alert('Contenido copiado al portapapeles');
                });
            }
            </script>
            <?php endforeach; ?>
        </div>
    </div>

    <!-- Footer -->
    <footer class="footer bg-dark text-white text-center py-3">
        <small>Command Model | IP: <?= $_SERVER['SERVER_ADDR'] ?> | PHP: <?= phpversion() ?></small>
    </footer>
</body>
</html>

<?php
// Procesar acciones AJAX
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    if (!isset($_SESSION['logged_in'])) {
        http_response_code(403);
        exit();
    }

    $file = $_POST['file'];
    $key = $_POST['key'];
    $filePath = "$dataDir/$file";

    if ($_POST['action'] === 'load') {
        $content = file_get_contents($filePath);
        if ($content) {
            echo decryptData($content, $key) ?: '';
        }
    } elseif ($_POST['action'] === 'save') {
        $content = $_POST['content'];
        if (strlen($content) > 4096) {
            http_response_code(400);
            exit('Contenido excede el límite de 4096 bytes');
        }
        file_put_contents($filePath, encryptData($content, $key));
    }
}
?>
