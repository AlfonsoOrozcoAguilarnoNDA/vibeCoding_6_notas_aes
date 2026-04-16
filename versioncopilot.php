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

// --- CONFIGURACIÓN LOGIN ---
$stored_hash = '$2y$10$YFqZkRk7u0YQvYkZkRk7uOQvYkZkRk7u0YQvYkZkRk7uOQvYkZkRk7u'; 
// Reemplaza con un hash real de 'vibekoder' generado con password_hash('vibekoder', PASSWORD_DEFAULT)

// --- FUNCIONES DE CIFRADO ---
function encrypt_note($plaintext, $key) {
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
    $ciphertext = openssl_encrypt($plaintext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    return $iv . $ciphertext;
}

function decrypt_note($data, $key) {
    $iv_length = openssl_cipher_iv_length('aes-256-cbc');
    $iv = substr($data, 0, $iv_length);
    $ciphertext = substr($data, $iv_length);
    return openssl_decrypt($ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
}

// --- LOGIN ---
if (isset($_POST['username'], $_POST['password'])) {
    if ($_POST['username'] === 'admin' && password_verify($_POST['password'], $stored_hash)) {
        $_SESSION['logged_in'] = true;
    } else {
        $error = "Credenciales inválidas";
    }
}

if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: ".$_SERVER['PHP_SELF']);
    exit;
}

// --- ARCHIVOS DE NOTAS ---
$notes = [];
for ($i=1; $i<=6; $i++) {
    $filename = "nota{$i}.aes";
    if (!file_exists($filename)) {
        file_put_contents($filename, "");
    }
    $notes[$i] = $filename;
}

// --- ACCIONES DE NOTAS ---
if (isset($_POST['action']) && $_SESSION['logged_in']) {
    $note_id = intval($_POST['note_id']);
    $filename = $notes[$note_id];
    $key = $_POST['note_key'];

    if ($_POST['action'] === 'read') {
        $data = file_get_contents($filename);
        $decrypted = $data ? decrypt_note($data, $key) : "";
        echo $decrypted !== false ? $decrypted : "";
        exit;
    }

    if ($_POST['action'] === 'save') {
        $plaintext = $_POST['content'];
        $encrypted = encrypt_note($plaintext, $key);
        file_put_contents($filename, $encrypted);
        echo "OK";
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Vault de Notas</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
</head>
<body class="bg-light">

<?php if (!isset($_SESSION['logged_in'])): ?>
<div class="container d-flex vh-100">
    <div class="row align-self-center w-100">
        <div class="col-md-4 offset-md-4">
            <div class="card shadow">
                <div class="card-body">
                    <h4 class="card-title text-center">Login</h4>
                    <?php if (isset($error)) echo "<div class='alert alert-danger'>$error</div>"; ?>
                    <form method="POST">
                        <div class="form-group">
                            <label>Usuario</label>
                            <input type="text" name="username" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label>Contraseña</label>
                            <input type="password" name="password" class="form-control" required>
                        </div>
                        <button type="submit" class="btn btn-primary btn-block">Entrar</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
<?php else: ?>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark fixed-top">
    <a class="navbar-brand" href="#">Vault (PHP Model)</a>
    <div class="ml-auto">
        <a href="https://example.com" class="nav-link d-inline">Enlace Externo</a>
        <a href="?logout=1" class="btn btn-danger btn-sm">Salir</a>
    </div>
</nav>

<div class="container mt-5 pt-5">
    <div class="jumbotron">
        <h1 class="display-4">Bienvenido al Vault</h1>
        <p class="lead">Tus notas cifradas con AES-256-CBC</p>
    </div>

    <div class="row">
        <?php foreach ($notes as $i=>$file): ?>
        <div class="col-md-4 mb-3">
            <div class="card shadow">
                <div class="card-body">
                    <h5 class="card-title">Nota <?php echo $i; ?></h5>
                    <p class="card-text text-muted">Archivo: <?php echo $file; ?></p>
                    <button class="btn btn-primary btn-sm" onclick="openModal(<?php echo $i; ?>)">Leer/Editar</button>
                </div>
            </div>
        </div>
        <?php endforeach; ?>
    </div>
</div>

<footer class="footer bg-dark text-white fixed-bottom text-center py-2">
    IP: <?php echo $_SERVER['REMOTE_ADDR']; ?> | PHP <?php echo PHP_VERSION; ?>
</footer>

<!-- Modal -->
<div class="modal fade" id="noteModal" tabindex="-1">
  <div class="modal-dialog modal-lg">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title">Editar Nota</h5>
        <button type="button" class="close" data-dismiss="modal">&times;</button>
      </div>
      <div class="modal-body">
        <input type="hidden" id="note_id">
        <div class="form-group">
            <label>Clave de Cifrado</label>
            <input type="password" id="note_key" class="form-control">
        </div>
        <div class="form-group">
            <label>Contenido</label>
            <textarea id="note_content" class="form-control" rows="10"></textarea>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" onclick="copyContent()">Copiar</button>
        <button class="btn btn-success" onclick="saveNote()">Grabar</button>
      </div>
    </div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js"></script>
<script>
function openModal(id){
    $('#note_id').val(id);
    $('#note_content').val('');
    $('#note_key').val('');
    $('#noteModal').modal('show');
}

function saveNote(){
    $.post('', {
        action:'save',
        note_id:$('#note_id').val(),
        note_key:$('#note_key').val(),
        content:$('#note_content').val()
    }, function(resp){
        alert('Guardado: '+resp);
        $('#noteModal').modal('hide');
    });
}

function copyContent(){
    $('#note_content').select();
    document.execCommand('copy');
    alert('Copiado al portapapeles');
}

$('#note_key').on('change', function(){
    $.post('', {
        action:'read',
        note_id:$('#note_id').val(),
        note_key:$('#note_key').val()
    }, function(resp){
        $('#note_content').val(resp);
    });
});
</script>
<?php endif; ?>
</body>
</html>
