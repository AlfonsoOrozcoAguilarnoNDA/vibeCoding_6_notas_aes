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

// -------------------------------
// 1. CONFIGURACIÓN Y CONSTANTES
// -------------------------------
define('NOTAS_DIR', __DIR__);
define('HASH_ADMIN', password_hash('vibekoder', PASSWORD_DEFAULT)); // Hash pre-generado de 'vibekoder'
define('MAX_SIZE', 4096);

// Lista de archivos .aes
$archivos = [
    'nota1.aes', 'nota2.aes', 'nota3.aes',
    'nota4.aes', 'nota5.aes', 'nota6.aes'
];

// -------------------------------
// 2. FUNCIONES DE CIFRADO AES-256-CBC
// -------------------------------
function cifrarAES($texto, $clave) {
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
    $cifrado = openssl_encrypt($texto, 'aes-256-cbc', $clave, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $cifrado);
}

function descifrarAES($dataBase64, $clave) {
    $data = base64_decode($dataBase64);
    $ivLength = openssl_cipher_iv_length('aes-256-cbc');
    $iv = substr($data, 0, $ivLength);
    $cifrado = substr($data, $ivLength);
    return openssl_decrypt($cifrado, 'aes-256-cbc', $clave, OPENSSL_RAW_DATA, $iv);
}

// -------------------------------
// 3. VERIFICAR Y CREAR ARCHIVOS VACÍOS
// -------------------------------
function verificarYcrearArchivos($archivos) {
    $dirWritable = is_writable(NOTAS_DIR);
    foreach ($archivos as $archivo) {
        $ruta = NOTAS_DIR . '/' . $archivo;
        if (!file_exists($ruta)) {
            // Crear archivo vacío (cifrado con IV falso? Mejor vacío pero con estructura)
            // Inicialmente guardamos un string vacío cifrado con una clave dummy
            // Para evitar errores, guardamos un texto vacío cifrado con clave temporal
            $emptyData = cifrarAES('', 'temp_key_initial');
            file_put_contents($ruta, $emptyData);
        } else {
            // Verificar tamaño máximo
            if (filesize($ruta) > MAX_SIZE) {
                // Truncar si excede (no debería ocurrir)
                $contenido = file_get_contents($ruta);
                file_put_contents($ruta, substr($contenido, 0, MAX_SIZE));
            }
        }
    }
    return $dirWritable;
}

// -------------------------------
// 4. LOGOUT
// -------------------------------
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// -------------------------------
// 5. LOGIN POST
// -------------------------------
$loginError = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username']) && isset($_POST['password'])) {
    $user = $_POST['username'];
    $pass = $_POST['password'];
    if ($user === 'admin' && password_verify($pass, HASH_ADMIN)) {
        $_SESSION['loggedin'] = true;
        // Regenerar ID de sesión por seguridad
        session_regenerate_id(true);
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $loginError = 'Usuario o contraseña incorrectos.';
    }
}

// Si no está logueado, mostrar pantalla de login
if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    ?>
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <title>Vault - Login</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
        <style>
            body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
            .card-login { border-radius: 1rem; box-shadow: 0 10px 25px rgba(0,0,0,0.1); border: none; }
            .card-login .card-header { background: transparent; border-bottom: none; text-align: center; font-size: 1.8rem; font-weight: bold; color: #4a5568; padding-top: 2rem; }
            .btn-login { background: linear-gradient(to right, #667eea, #764ba2); border: none; border-radius: 50px; padding: 10px 20px; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-5">
                    <div class="card card-login">
                        <div class="card-header">
                            <i class="fas fa-lock"></i> Secure Vault
                        </div>
                        <div class="card-body">
                            <?php if ($loginError): ?>
                                <div class="alert alert-danger"><?php echo htmlspecialchars($loginError); ?></div>
                            <?php endif; ?>
                            <form method="POST" action="">
                                <div class="form-group">
                                    <label><i class="fas fa-user"></i> Usuario</label>
                                    <input type="text" name="username" class="form-control" required autofocus placeholder="admin">
                                </div>
                                <div class="form-group">
                                    <label><i class="fas fa-key"></i> Contraseña</label>
                                    <input type="password" name="password" class="form-control" required placeholder="********">
                                </div>
                                <button type="submit" class="btn btn-primary btn-block btn-login"><i class="fas fa-sign-in-alt"></i> Acceder</button>
                            </form>
                            <hr>
                            <small class="text-muted">Acceso solo para administradores</small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// -------------------------------
// 6. VERIFICAR DIRECTORIO Y ARCHIVOS (USUARIO LOGUEADO)
// -------------------------------
$writable = verificarYcrearArchivos($archivos);

// -------------------------------
// 7. PROCESAR PETICIONES AJAX (Leer/Grabar Nota)
// -------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
    header('Content-Type: application/json');
    $action = $_POST['action'] ?? '';
    $index = $_POST['index'] ?? null;
    $clave = $_POST['clave'] ?? '';
    $contenidoNuevo = $_POST['contenido'] ?? '';

    if ($index !== null && is_numeric($index) && $index >= 0 && $index < count($archivos)) {
        $archivo = $archivos[$index];
        $ruta = NOTAS_DIR . '/' . $archivo;

        if ($action === 'leer') {
            if (empty($clave)) {
                echo json_encode(['success' => false, 'error' => 'Clave requerida']);
                exit;
            }
            $dataBase64 = file_get_contents($ruta);
            $textoDescifrado = descifrarAES($dataBase64, $clave);
            if ($textoDescifrado === false) {
                echo json_encode(['success' => false, 'error' => 'Clave incorrecta o datos corruptos']);
            } else {
                echo json_encode(['success' => true, 'contenido' => $textoDescifrado]);
            }
        } 
        elseif ($action === 'grabar') {
            if (empty($clave)) {
                echo json_encode(['success' => false, 'error' => 'Clave requerida para cifrar']);
                exit;
            }
            if (strlen($contenidoNuevo) > MAX_SIZE) {
                echo json_encode(['success' => false, 'error' => 'El contenido excede el tamaño máximo de 4096 bytes']);
                exit;
            }
            $cifrado = cifrarAES($contenidoNuevo, $clave);
            if (file_put_contents($ruta, $cifrado) !== false) {
                echo json_encode(['success' => true]);
            } else {
                echo json_encode(['success' => false, 'error' => 'Error al guardar archivo']);
            }
        }
        else {
            echo json_encode(['success' => false, 'error' => 'Acción no válida']);
        }
    } else {
        echo json_encode(['success' => false, 'error' => 'Índice de nota inválido']);
    }
    exit;
}

// -------------------------------
// 8. MOSTRAR INTERFAZ PRINCIPAL
// -------------------------------
$ipCliente = $_SERVER['REMOTE_ADDR'] ?? 'Desconocida';
$phpVersion = phpversion();
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>Vault - Notas Cifradas AES-256</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js"></script>
    <style>
        body {
            padding-top: 70px;
            padding-bottom: 60px;
            background: #f8f9fc;
            font-family: 'Segoe UI', Roboto, sans-serif;
        }
        .navbar-brand i {
            margin-right: 8px;
        }
        .footer {
            position: fixed;
            bottom: 0;
            width: 100%;
            background-color: #2c3e50;
            color: #ecf0f1;
            text-align: center;
            padding: 10px 0;
            font-size: 0.85rem;
            z-index: 1000;
        }
        .jumbotron {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem 1rem;
            border-radius: 1rem;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        .card-vault {
            border-radius: 15px;
            transition: transform 0.2s, box-shadow 0.2s;
            border: none;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
        }
        .card-vault:hover {
            transform: translateY(-5px);
            box-shadow: 0 12px 25px rgba(0,0,0,0.12);
        }
        .card-header-vault {
            background: #4e73df;
            color: white;
            border-radius: 15px 15px 0 0 !important;
            font-weight: bold;
        }
        .btn-sm-custom {
            border-radius: 20px;
            padding: 5px 12px;
            margin: 2px;
        }
        .preview-cifrado {
            font-family: monospace;
            font-size: 0.8rem;
            background: #f1f3f5;
            padding: 8px;
            border-radius: 8px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        textarea.modal-textarea {
            font-family: monospace;
            font-size: 0.9rem;
        }
        .navbar-nav .nav-link i {
            margin-right: 5px;
        }
        .badge-version {
            background-color: #1abc9c;
        }
    </style>
</head>
<body>

<!-- NAVBAR FIJA -->
<nav class="navbar navbar-expand-lg navbar-dark bg-dark fixed-top">
    <a class="navbar-brand" href="#"><i class="fas fa-dragon"></i> Vault Cifrado</a>
    <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav mr-auto">
            <li class="nav-item active"><a class="nav-link" href="#"><i class="fas fa-home"></i> Inicio</a></li>
            <li class="nav-item"><a class="nav-link" href="#" id="infoBtn"><i class="fas fa-info-circle"></i> Acerca</a></li>
            <li class="nav-item"><a class="nav-link" href="#" id="ayudaBtn"><i class="fas fa-question-circle"></i> Ayuda</a></li>
            <li class="nav-item"><a class="nav-link" href="https://github.com" target="_blank"><i class="fab fa-github"></i> GitHub</a></li>
        </ul>
        <span class="navbar-text mr-3">
            <i class="fas fa-microchip"></i> Modelo: GPT-4 (IA)
        </span>
        <a href="?logout=1" class="btn btn-outline-danger btn-sm"><i class="fas fa-sign-out-alt"></i> Salir</a>
    </div>
</nav>

<div class="container">
    <!-- JUMBOTRON -->
    <div class="jumbotron">
        <h1 class="display-4"><i class="fas fa-shield-alt"></i> Secure Vault</h1>
        <p class="lead">Almacenamiento de notas cifradas con AES-256-CBC. Cada nota está protegida con una clave independiente.</p>
        <hr class="my-4" style="background: rgba(255,255,255,0.3);">
        <p><i class="fas fa-check-circle"></i> Archivos verificados y listos. Permisos de escritura: <?php echo $writable ? '<span class="badge badge-success">OK</span>' : '<span class="badge badge-danger">Problemas</span>'; ?></p>
    </div>

    <!-- GRID DE 6 CARDS -->
    <div class="row">
        <?php for ($i = 0; $i < count($archivos); $i++): 
            $nombreArchivo = $archivos[$i];
            $rutaCompleta = NOTAS_DIR . '/' . $nombreArchivo;
            $tamano = file_exists($rutaCompleta) ? filesize($rutaCompleta) : 0;
            $preview = (file_exists($rutaCompleta) && $tamano > 0) ? substr(basename(file_get_contents($rutaCompleta)), 0, 30) . '...' : '[Vacío]';
        ?>
            <div class="col-md-4 col-lg-4 mb-4">
                <div class="card card-vault h-100">
                    <div class="card-header card-header-vault">
                        <i class="fas fa-file-alt"></i> <?php echo htmlspecialchars($nombreArchivo); ?>
                        <span class="badge badge-light float-right"><?php echo $tamano; ?> bytes</span>
                    </div>
                    <div class="card-body">
                        <div class="preview-cifrado mb-3">
                            <small><i class="fas fa-lock"></i> Cifrado: </small> 
                            <span id="preview-<?php echo $i; ?>"><?php echo htmlspecialchars($preview); ?></span>
                        </div>
                        <div class="btn-group d-flex" role="group">
                            <button class="btn btn-primary btn-sm-custom btn-leer" data-index="<?php echo $i; ?>" data-toggle="modal" data-target="#modalNota"><i class="fas fa-edit"></i> Leer/Editar</button>
                            <button class="btn btn-success btn-sm-custom btn-copiar" data-index="<?php echo $i; ?>" disabled><i class="fas fa-copy"></i> Copiar</button>
                        </div>
                    </div>
                </div>
            </div>
        <?php endfor; ?>
    </div>
</div>

<!-- MODAL PARA LEER/EDITAR NOTA -->
<div class="modal fade" id="modalNota" tabindex="-1" role="dialog" aria-labelledby="modalNotaLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header bg-primary text-white">
                <h5 class="modal-title" id="modalNotaLabel"><i class="fas fa-pen-alt"></i> Nota: <span id="modalNombreNota"></span></h5>
                <button type="button" class="close text-white" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label><i class="fas fa-key"></i> Clave de cifrado (AES-256)</label>
                    <input type="password" class="form-control" id="modalClave" placeholder="Introduce la clave para descifrar / guardar">
                </div>
                <div class="form-group">
                    <label><i class="fas fa-file-signature"></i> Contenido de la nota (máx 4096 bytes)</label>
                    <textarea class="form-control modal-textarea" id="modalContenido" rows="8" maxlength="4096" placeholder="El texto se mostrará aquí tras descifrar..."></textarea>
                </div>
                <div id="modalError" class="alert alert-danger d-none"></div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-dismiss="modal"><i class="fas fa-times"></i> Cerrar</button>
                <button type="button" class="btn btn-info" id="btnDescifrarModal"><i class="fas fa-unlock-alt"></i> Descifrar / Cargar</button>
                <button type="button" class="btn btn-warning" id="btnCopiarModal"><i class="fas fa-copy"></i> Copiar texto</button>
                <button type="button" class="btn btn-success" id="btnGuardarModal"><i class="fas fa-save"></i> Grabar (Cifrar)</button>
            </div>
        </div>
    </div>
</div>

<!-- FOOTER FIJO -->
<div class="footer">
    <i class="fas fa-server"></i> IP: <?php echo htmlspecialchars($ipCliente); ?> | <i class="fab fa-php"></i> PHP v<?php echo $phpVersion; ?> | <i class="fas fa-lock"></i> AES-256-CBC | Secure Vault &copy; 2025
</div>

<script>
$(document).ready(function(){
    let currentIndex = null;

    // Al abrir modal: almacenar índice y resetear campos
    $('.btn-leer').on('click', function(){
        currentIndex = $(this).data('index');
        let nombreArchivo = $('.card-vault').eq(currentIndex).find('.card-header').text().trim();
        $('#modalNombreNota').text(nombreArchivo);
        $('#modalClave').val('');
        $('#modalContenido').val('');
        $('#modalError').addClass('d-none');
        $('#btnCopiarModal').prop('disabled', false);
    });

    // Descifrar / Leer
    $('#btnDescifrarModal').on('click', function(){
        let clave = $('#modalClave').val();
        if(!clave){
            showError('Debes ingresar la clave de cifrado.');
            return;
        }
        $.ajax({
            url: window.location.href,
            type: 'POST',
            data: {
                action: 'leer',
                index: currentIndex,
                clave: clave
            },
            dataType: 'json',
            success: function(resp){
                if(resp.success){
                    $('#modalContenido').val(resp.contenido);
                    $('#modalError').addClass('d-none');
                    // Habilitar botón copiar para el modal
                } else {
                    showError(resp.error || 'Error al descifrar. Clave incorrecta o archivo corrupto.');
                }
            },
            error: function(){
                showError('Error de conexión.');
            }
        });
    });

    // Guardar (Cifrar y escribir)
    $('#btnGuardarModal').on('click', function(){
        let clave = $('#modalClave').val();
        let contenido = $('#modalContenido').val();
        if(!clave){
            showError('La clave es necesaria para cifrar.');
            return;
        }
        if(contenido.length > 4096){
            showError('El contenido supera los 4096 bytes.');
            return;
        }
        $.ajax({
            url: window.location.href,
            type: 'POST',
            data: {
                action: 'grabar',
                index: currentIndex,
                clave: clave,
                contenido: contenido
            },
            dataType: 'json',
            success: function(resp){
                if(resp.success){
                    $('#modalError').addClass('d-none');
                    alert('Nota guardada exitosamente.');
                    // Actualizar preview con un placeholder (no podemos mostrar el cifrado real)
                    $('#preview-'+currentIndex).text('[Actualizado y cifrado]');
                } else {
                    showError(resp.error || 'Error al guardar.');
                }
            },
            error: function(){
                showError('Error al guardar en el servidor.');
            }
        });
    });

    // Copiar contenido del textarea del modal
    $('#btnCopiarModal').on('click', function(){
        let textarea = $('#modalContenido');
        if(textarea.val()){
            textarea.select();
            document.execCommand('copy');
            alert('Texto copiado al portapapeles.');
        } else {
            alert('No hay texto para copiar.');
        }
    });

    // Función para mostrar errores en modal
    function showError(msg){
        $('#modalError').removeClass('d-none').text(msg);
    }

    // Info y ayuda modales (básicos)
    $('#infoBtn').on('click', function(e){
        e.preventDefault();
        alert('🔐 Vault Seguro\nCifrado AES-256-CBC con IV.\nCada nota se guarda en archivo .aes.\nLa clave de cifrado es independiente al login.');
    });
    $('#ayudaBtn').on('click', function(e){
        e.preventDefault();
        alert('📘 Ayuda:\n1. Ingresa la clave de cifrado para descifrar.\n2. Edita el texto en el área.\n3. Presiona "Grabar" para cifrar y guardar.\n4. Copia el texto descifrado con el botón copiar.');
    });
});
</script>
</body>
</html>
<?php
// Fin del archivo único
?>
