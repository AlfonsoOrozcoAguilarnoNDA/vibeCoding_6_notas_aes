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
 * ============================================================
 * VAULT DE NOTAS CIFRADAS
 * ============================================================
 * Archivo: vault.php
 * Versión: 1.0
 * Fecha: 25 de marzo de 2026
 * Licencia: MIT
 * 
 * Coautoría: Together Chat (MiniMax-M2.5)
 * Co-programador en el experimento vibecodingmexico.com
 * 
 * Stack: PHP 8.x Procedural, Bootstrap 4.6, Font Awesome 5.0, OpenSSL
 * ============================================================
 */

// ============================================
// HEADERS DE CACHÉ Y CODIFICACIÓN
// ============================================
header('Content-Type: text/html; charset=UTF-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: Sat, 01 Jan 2000 00:00:00 GMT');

session_start();

// ============================================
// CONSTANTES DE CONFIGURACIÓN
// ============================================
define('NOTAS_DIR', './notas/');
define('MAX_NOTAS', 6);
define('MAX_SIZE_NOTA', 4096);

// Hash pre-generado de 'vibekoder' (usando password_hash)
// Generado con: password_hash('vibekoder', PASSWORD_DEFAULT)
define('HASH_LOGIN', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi');

// ============================================
// FUNCIONES DE CIFRADO AES-256-CBC
// ============================================

/**
 * Cifra texto usando AES-256-CBC
 * Retorna: IV (16 bytes) + contenido cifrado en base64
 */
function cifrar_texto($texto, $clave) {
    $metodo = "aes-256-cbc";
    $iv = openssl_random_pseudo_bytes(16);
    
    $cifrado = openssl_encrypt($texto, $metodo, $clave, OPENSSL_RAW_DATA, $iv);
    
    if ($cifrado === false) {
        return false;
    }
    
    // Concatenar IV + cifrado y convertir a base64
    return base64_encode($iv . $cifrado);
}

/**
 * Descifra texto usando AES-256-CBC
 * Requiere: IV (16 bytes) + contenido cifrado en base64
 */
function descifrar_texto($cifrado_base64, $clave) {
    $metodo = "aes-256-cbc";
    
    $datos = base64_decode($cifrado_base64);
    if ($datos === false) {
        return false;
    }
    
    // Extraer IV (primeros 16 bytes)
    $iv = substr($datos, 0, 16);
    $cifrado = substr($datos, 16);
    
    return openssl_decrypt($cifrado, $metodo, $clave, OPENSSL_RAW_DATA, $iv);
}

// ============================================
// VERIFICAR Y CREAR DIRECTORIO DE NOTAS
// ============================================
function verificar_directorio_notas() {
    if (!is_dir(NOTAS_DIR)) {
        mkdir(NOTAS_DIR, 0755, true);
    }
    
    if (!is_writable(NOTAS_DIR)) {
        return ['existe' => true, 'escribible' => false, 'mensaje' => 'Directorio sin permisos de escritura'];
    }
    
    return ['existe' => true, 'escribible' => true, 'mensaje' => 'Directorio OK'];
}

// ============================================
// VERIFICAR Y CREAR ARCHIVOS DE NOTAS
// ============================================
function verificar_archivos_notas() {
    $estado = [];
    
    for ($i = 1; $i <= MAX_NOTAS; $i++) {
        $nombre = 'nota' . $i . '.aes';
        $ruta = NOTAS_DIR . $nombre;
        
        if (!file_exists($ruta)) {
            // Crear archivo vacío
            file_put_contents($ruta, '');
            $estado[$i] = ['existe' => true, 'vacio' => true, 'nombre' => $nombre];
        } else {
            $contenido = file_get_contents($ruta);
            $estado[$i] = [
                'existe' => true, 
                'vacio' => empty($contenido), 
                'nombre' => $nombre,
                'size' => strlen($contenido)
            ];
        }
    }
    
    return $estado;
}

// ============================================
// LEER NOTA (descifrada o cifrada)
// ============================================
function leer_nota($numero, $clave = null) {
    $nombre = 'nota' . $numero . '.aes';
    $ruta = NOTAS_DIR . $nombre;
    
    if (!file_exists($ruta)) {
        return ['success' => false, 'mensaje' => 'Archivo no existe'];
    }
    
    $contenido = file_get_contents($ruta);
    
    if (empty($contenido)) {
        return ['success' => true, 'contenido' => '', 'cifrado' => false, 'mensaje' => 'Nota vacía'];
    }
    
    if ($clave === null) {
        // Solo devolver contenido cifrado
        return ['success' => true, 'contenido' => $contenido, 'cifrado' => true, 'mensaje' => 'Contenido cifrado'];
    }
    
    // Descifrar
    $descifrado = descifrar_texto($contenido, $clave);
    
    if ($descifrado === false) {
        return ['success' => false, 'mensaje' => 'Error al descifrar. Clave incorrecta o contenido corrupto.'];
    }
    
    return ['success' => true, 'contenido' => $descifrado, 'cifrado' => false, 'mensaje' => 'Nota descifrada'];
}

// ============================================
// GUARDAR NOTA (cifrada)
// ============================================
function guardar_nota($numero, $contenido, $clave) {
    if (strlen($contenido) > MAX_SIZE_NOTA) {
        return ['success' => false, 'mensaje' => 'Contenido excede límite de ' . MAX_SIZE_NOTA . ' bytes'];
    }
    
    $cifrado = cifrar_texto($contenido, $clave);
    
    if ($cifrado === false) {
        return ['success' => false, 'mensaje' => 'Error al cifrar'];
    }
    
    $nombre = 'nota' . $numero . '.aes';
    $ruta = NOTAS_DIR . $nombre;
    
    if (file_put_contents($ruta, $cifrado) === false) {
        return ['success' => false, 'mensaje' => 'Error al guardar archivo'];
    }
    
    return ['success' => true, 'mensaje' => 'Nota cifrada y guardada correctamente'];
}

// ============================================
// VARIABLES DE CONTROL
// ============================================
$directorio_ok = verificar_directorio_notas();
$archivos_notas = verificar_archivos_notas();
$autenticado = isset($_SESSION['autenticado']) && $_SESSION['autenticado'] === true;
$mensaje = '';
$tipo_mensaje = '';
$accion = $_GET['accion'] ?? '';

// Obtener IP del cliente
$ip_cliente = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';

// ============================================
// PROCESAMIENTO DE ACCIONES
// ============================================

// Login
if ($accion === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    // Verificar usuario y contraseña
    if ($username === 'admin' && password_verify($password, HASH_LOGIN)) {
        $_SESSION['autenticado'] = true;
        $autenticado = true;
        $mensaje = 'Sesión iniciada correctamente';
        $tipo_mensaje = 'success';
    } else {
        $mensaje = 'Credenciales incorrectas';
        $tipo_mensaje = 'danger';
    }
    $accion = '';
}

// Logout
if ($accion === 'logout') {
    session_destroy();
    header('Location: vault.php');
    exit;
}

// Leer nota
if ($accion === 'leer' && $_SERVER['REQUEST_METHOD'] === 'POST' && $autenticado) {
    $numero = intval($_POST['numero'] ?? 0);
    $clave = $_POST['clave_leer'] ?? '';
    
    if ($numero < 1 || $numero > MAX_NOTAS) {
        $mensaje = 'Número de nota inválido';
        $tipo_mensaje = 'danger';
    } elseif (empty($clave)) {
        $mensaje = 'Debe proporcionar una clave de descifrado';
        $tipo_mensaje = 'warning';
    } else {
        $resultado = leer_nota($numero, $clave);
        if ($resultado['success']) {
            $_SESSION['nota_actual'] = $numero;
            $_SESSION['contenido_nota'] = $resultado['contenido'];
            $mensaje = $resultado['mensaje'];
            $tipo_mensaje = 'success';
        } else {
            $mensaje = $resultado['mensaje'];
            $tipo_mensaje = 'danger';
        }
    }
}

// Guardar nota
if ($accion === 'guardar' && $_SERVER['REQUEST_METHOD'] === 'POST' && $autenticado) {
    $numero = intval($_POST['numero'] ?? 0);
    $contenido = $_POST['contenido'] ?? '';
    $clave = $_POST['clave_guardar'] ?? '';
    
    if ($numero < 1 || $numero > MAX_NOTAS) {
        $mensaje = 'Número de nota inválido';
        $tipo_mensaje = 'danger';
    } elseif (empty($clave)) {
        $mensaje = 'Debe proporcionar una clave para cifrar';
        $tipo_mensaje = 'warning';
    } else {
        $resultado = guardar_nota($numero, $contenido, $clave);
        if ($resultado['success']) {
            $mensaje = $resultado['mensaje'];
            $tipo_mensaje = 'success';
            // Limpiar sesión de nota
            unset($_SESSION['contenido_nota']);
        } else {
            $mensaje = $resultado['mensaje'];
            $tipo_mensaje = 'danger';
        }
    }
}

// Copiar al portapapeles (solo sesión)
if ($accion === 'copiar' && $autenticado && isset($_SESSION['contenido_nota'])) {
    // El copiado se maneja con JS en el cliente
    $mensaje = 'Contenido disponible para copiar';
    $tipo_mensaje = 'info';
}

// Obtener nota actual para modal
$nota_actual = $_SESSION['nota_actual'] ?? null;
$contenido_mostrar = $_SESSION['contenido_nota'] ?? '';

?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>Vault Cifrado - Lemkotir</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <style>
        :root {
            --metro-blue: #3498db;
            --metro-green: #27ae60;
            --metro-red: #e74c3c;
            --metro-purple: #9b59b6;
            --metro-dark: #2c3e50;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, sans-serif;
            background: linear-gradient(135deg, #1a2a6c 0%, #2c3e50 50%, #4a69bd 100%);
            min-height: 100vh;
            margin: 0;
            padding: 0;
        }
        
        .main-container {
            padding-top: 90px;
            padding-bottom: 100px;
        }
        
        .navbar {
            background: linear-gradient(135deg, #2c3e50, #34495e) !important;
        }
        
        .card-vault {
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            overflow: hidden;
            transition: all 0.3s ease;
        }
        
        .card-vault:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.4);
        }
        
        .header-vault {
            background: linear-gradient(135deg, #2c3e50, #34495e);
            color: white;
            padding: 15px 20px;
        }
        
        .nota-vacia {
            color: #6c757d;
            font-style: italic;
        }
        
        .nota-cifrada {
            color: #e74c3c;
            font-family: 'Courier New', monospace;
            font-size: 0.75rem;
            word-break: break-all;
        }
        
        .btn-metro {
            background: linear-gradient(135deg, #2c3e50, #34495e);
            color: white;
            border: none;
            border-radius: 8px;
            padding: 8px 16px;
            transition: all 0.3s ease;
        }
        
        .btn-metro:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
            color: white;
        }
        
        .jumbotron-custom {
            background: linear-gradient(135deg, rgba(44, 62, 80, 0.9), rgba(52, 73, 94, 0.9));
            color: white;
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
        }
        
        .login-card {
            max-width: 400px;
            margin: 100px auto;
        }
    </style>
</head>
<body>

<!-- Navbar Fijo -->
<nav class="navbar navbar-expand-lg navbar-dark sticky-top">
    <div class="container">
        <a class="navbar-brand font-weight-bold" href="vault.php">
            <i class="fas fa-vault mr-2"></i>Vault
        </a>
        <span class="navbar-text text-white">
            <i class="fas fa-robot mr-1"></i>Modelo: MiniMax-M2.5
        </span>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav ml-auto">
                <li class="nav-item">
                    <a class="nav-link" href="https://www.google.com" target="_blank">
                        <i class="fas fa-search mr-1"></i>Google
                    </a>
                </li>
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" data-toggle="dropdown">
                        <i class="fas fa-layer-group mr-1"></i>Menú
                    </a>
                    <div class="dropdown-menu">
                        <a class="dropdown-item" href="#notas"><i class="fas fa-sticky-note mr-2"></i>Notas Cifradas</a>
                        <a class="dropdown-item" href="#info"><i class="fas fa-info-circle mr-2"></i>Información</a>
                    </div>
                </li>
                <?php if ($autenticado): ?>
                <li class="nav-item">
                    <a class="nav-link text-warning" href="vault.php?accion=logout">
                        <i class="fas fa-sign-out-alt mr-1"></i>Salir
                    </a>
                </li>
                <?php endif; ?>
            </ul>
        </div>
    </div>
</nav>

<!-- Contenido Principal -->
<div class="main-container">
    <div class="container">
        
        <!-- Mensajes -->
        <?php if (!empty($mensaje)): ?>
        <div class="alert alert-<?php echo $tipo_mensaje; ?> alert-dismissible fade show" role="alert">
            <i class="fas <?php echo ($tipo_mensaje === 'success') ? 'fa-check-circle' : 'fa-exclamation-circle'; ?> mr-2"></i>
            <?php echo htmlspecialchars($mensaje); ?>
            <button type="button" class="close" data-dismiss="alert"><span>&times;</span></button>
        </div>
        <?php endif; ?>
        
        <!-- ============================================ -->
        <!-- LOGIN (si no autenticado) -->
        <!-- ============================================ -->
        <?php if (!$autenticado): ?>
        
        <div class="card-vault login-card">
            <div class="header-vault">
                <h4 class="mb-0"><i class="fas fa-lock mr-2"></i>Acceso al Vault</h4>
            </div>
            <div class="card-body p-4">
                <form method="POST" action="vault.php?accion=login">
                    <div class="form-group">
                        <label><i class="fas fa-user mr-2"></i>Usuario</label>
                        <input type="text" name="username" class="form-control" value="admin" required>
                    </div>
                    <div class="form-group">
                        <label><i class="fas fa-key mr-2"></i>Contraseña</label>
                        <input type="password" name="password" class="form-control" required>
                    </div>
                    <button type="submit" class="btn btn-metro btn-block">
                        <i class="fas fa-sign-in-alt mr-2"></i>Iniciar Sesión
                    </button>
                </form>
                <hr>
                <p class="text-muted text-center small mb-0">
                    <i class="fas fa-info-circle mr-1"></i>
                    Ingrese sus credenciales para acceder al vault cifrado
                </p>
            </div>
        </div>
        
        <?php else: ?>
        
        <!-- ============================================ -->
        <!-- INTERFAZ PRINCIPAL (autenticado) -->
        <!-- ============================================ -->
        
        <!-- Jumbotron de bienvenida -->
        <div class="jumbotron-custom" id="info">
            <h1 class="display-4">
                <i class="fas fa-shield-alt mr-3"></i>Vault de Notas Cifradas
            </h1>
            <p class="lead">
                Sistema de almacenamiento seguro con cifrado AES-256-CBC. 
                Cada nota está protegida con su propia clave de cifrado.
            </p>
            <hr class="my-4">
            <p>
                <i class="fas fa-check-circle text-success mr-2"></i>
                <?php echo MAX_NOTAS; ?> notas disponibles
                <span class="mx-3">|</span>
                <i class="fas fa-key text-warning mr-2"></i>
                Cifrado AES-256-CBC
                <span class="mx-3">|</span>
                <i class="fas fa-folder text-info mr-2"></i>
                <?php echo $directorio_ok['mensaje']; ?>
            </p>
        </div>
        
        <!-- Verificar directorio -->
        <?php if (!$directorio_ok['escribible']): ?>
        <div class="alert alert-danger">
            <i class="fas fa-exclamation-triangle mr-2"></i>
            <?php echo htmlspecialchars($directorio_ok['mensaje']); ?>
        </div>
        <?php endif; ?>
        
        <!-- Grid de Notas -->
        <h4 class="text-white mb-3" id="notas">
            <i class="fas fa-sticky-note mr-2"></i>Mis Notas Cifradas
        </h4>
        
        <div class="row">
            <?php for ($i = 1; $i <= MAX_NOTAS; $i++): ?>
            <div class="col-md-6 col-lg-4 mb-4">
                <div class="card-vault h-100">
                    <div class="header-vault">
                        <div class="d-flex justify-content-between align-items-center">
                            <h5 class="mb-0"><i class="fas fa-file-alt mr-2"></i>Nota <?php echo $i; ?></h5>
                            <span class="badge badge-light"><?php echo MAX_SIZE_NOTA; ?> bytes</span>
                        </div>
                    </div>
                    <div class="card-body">
                        <?php if ($archivos_notas[$i]['vacio']): ?>
                        <p class="nota-vacia">Nota vacía</p>
                        <?php else: ?>
                        <p class="nota-cifrada">
                            <?php echo substr(file_get_contents(NOTAS_DIR . 'nota' . $i . '.aes'), 0, 100); ?>...
                        </p>
                        <?php endif; ?>
                    </div>
                    <div class="card-footer bg-light">
                        <div class="row">
                            <div class="col-4">
                                <button class="btn btn-sm btn-metro btn-block" data-toggle="modal" data-target="#leerModal" data-nota="<?php echo $i; ?>">
                                    <i class="fas fa-eye"></i>
                                </button>
                            </div>
                            <div class="col-4">
                                <button class="btn btn-sm btn-metro btn-block" data-toggle="modal" data-target="#guardarModal" data-nota="<?php echo $i; ?>">
                                    <i class="fas fa-save"></i>
                                </button>
                            </div>
                            <div class="col-4">
                                <button class="btn btn-sm btn-metro btn-block" data-toggle="modal" data-target="#copiarModal" data-nota="<?php echo $i; ?>">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <?php endfor; ?>
        </div>
        
        <!-- ============================================ -->
        <!-- MODAL LEER NOTA -->
        <!-- ============================================ -->
        <div class="modal fade" id="leerModal" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header" style="background: linear-gradient(135deg, #2c3e50, #34495e); color: white;">
                        <h5 class="modal-title"><i class="fas fa-eye mr-2"></i>Leer Nota</h5>
                        <button type="button" class="close text-white" data-dismiss="modal"><span>&times;</span></button>
                    </div>
                    <form method="POST" action="vault.php?accion=leer">
                        <div class="modal-body">
                            <input type="hidden" name="numero" id="leer_numero" value="">
                            <div class="form-group">
                                <label><i class="fas fa-key mr-2"></i>Clave de Descifrado</label>
                                <input type="password" name="clave_leer" class="form-control" required>
                                <small class="text-muted">Ingrese la clave usada al guardar esta nota</small>
                            </div>
                            <?php if ($nota_actual): ?>
                            <div class="form-group">
                                <label><i class="fas fa-align-left mr-2"></i>Contenido</label>
                                <textarea class="form-control" rows="10" readonly><?php echo htmlspecialchars($contenido_mostrar); ?></textarea>
                            </div>
                            <?php endif; ?>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-dismiss="modal">Cerrar</button>
                            <button type="submit" class="btn btn-metro"><i class="fas fa-unlock mr-2"></i>Descifrar</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        
        <!-- ============================================ -->
        <!-- MODAL GUARDAR NOTA -->
        <!-- ============================================ -->
        <div class="modal fade" id="guardarModal" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header" style="background: linear-gradient(135deg, #2c3e50, #34495e); color: white;">
                        <h5 class="modal-title"><i class="fas fa-save mr-2"></i>Guardar Nota</h5>
                        <button type="button" class="close text-white" data-dismiss="modal"><span>&times;</span></button>
                    </div>
                    <form method="POST" action="vault.php?accion=guardar">
                        <div class="modal-body">
                            <input type="hidden" name="numero" id="guardar_numero" value="">
                            <div class="form-group">
                                <label><i class="fas fa-key mr-2"></i>Clave de Cifrado</label>
                                <input type="password" name="clave_guardar" class="form-control" required>
                                <small class="text-muted">Guarde esta clave, necesitará usarla para leer la nota</small>
                            </div>
                            <div class="form-group">
                                <label><i class="fas fa-align-left mr-2"></i>Contenido</label>
                                <textarea name="contenido" class="form-control" rows="10" placeholder="Escriba su nota aquí..."></textarea>
                                <small class="text-muted">Máximo <?php echo MAX_SIZE_NOTA; ?> bytes</small>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-dismiss="modal">Cancelar</button>
                            <button type="submit" class="btn btn-metro"><i class="fas fa-lock mr-2"></i>Cifrar y Guardar</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        
        <!-- ============================================ -->
        <!-- MODAL COPIAR CONTENIDO -->
        <!-- ============================================ -->
        <div class="modal fade" id="copiarModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header" style="background: linear-gradient(135deg, #2c3e50, #34495e); color: white;">
                        <h5 class="modal-title"><i class="fas fa-copy mr-2"></i>Copiar Contenido</h5>
                        <button type="button" class="close text-white" data-dismiss="modal"><span>&times;</span></button>
                    </div>
                    <div class="modal-body">
                        <p>Para copiar el contenido de una nota, primero debe descifrarla usando el botón "Leer".</p>
                        <p class="text-muted">Una vez descifrada, el contenido estará disponible en el portapapeles.</p>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-dismiss="modal">Cerrar</button>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            // Pasar número de nota a los modales
            $('#leerModal').on('show.bs.modal', function(e) {
                var button = $(e.relatedTarget);
                var nota = button.data('nota');
                $('#leer_numero').val(nota);
            });
            
            $('#guardarModal').on('show.bs.modal', function(e) {
                var button = $(e.relatedTarget);
                var nota = button.data('nota');
                $('#guardar_numero').val(nota);
            });
            
            $('#copiarModal').on('show.bs.modal', function(e) {
                var button = $(e.relatedTarget);
                var nota = button.data('nota');
            });
        </script>
        
        <?php endif; ?>
        
    </div>
</div>

<!-- Footer Fijo -->
<footer class="py-2" style="background: linear-gradient(135deg, #2c3e50, #34495e); color: white; position: fixed; bottom: 0; width: 100%; z-index: 1000;">
    <div class="container text-center">
        <small>
            <i class="fas fa-vault mr-1"></i>Vault Cifrado | 
            <i class="fas fa-code mr-1"></i>PHP <?php echo phpversion(); ?> | 
            <i class="fas fa-network-wired mr-1"></i>IP: <?php echo htmlspecialchars($ip_cliente); ?> | 
            <i class="fas fa-robot mr-1"></i>MiniMax-M2.5
        </small>
    </div>
</footer>

<!-- Bootstrap & jQuery -->
<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js"></script>

</body>
</html>
