import os
import datetime
import uuid
import time
from flask import Flask, render_template, request, session, redirect, url_for, send_from_directory, make_response
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

app = Flask(__name__)
app.config['SECRET_KEY'] = 'clave-super-secreta-para-sesiones'
socketio = SocketIO(app, cors_allowed_origins="*")

# Contraseña del chat (cámbiala aquí)
CHAT_PASSWORD = 'admin123'

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Historial en RAM
historial = []

# Almacenamiento de tokens de subida (válidos por 10 minutos)
upload_tokens = {}   # token -> timestamp de creación

# ---------- GENERACIÓN DE CERTIFICADO AUTOFIRMADO ----------
CERT_FILE = 'cert.pem'
KEY_FILE = 'key.pem'

def generar_certificado_si_no_existe():
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Localhost"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ChatLocal"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False,
    ).sign(key, hashes.SHA256())
    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

generar_certificado_si_no_existe()

# ---------- AUTENTICACIÓN ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('texto', '')
        if password == CHAT_PASSWORD:
            session['autenticado'] = True
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Contraseña incorrecta')
    return render_template('login.html')

# ---------- RUTA PRINCIPAL PROTEGIDA ----------
@app.route('/')
def index():
    if not session.get('autenticado'):
        return redirect(url_for('login'))

    # Generar token único para subidas
    token = str(uuid.uuid4())
    upload_tokens[token] = time.time()

    # Limpiar la sesión para forzar re-login al refrescar
    session.clear()

    # Crear respuesta y establecer cookie con el token (válida 10 min)
    resp = make_response(render_template('index.html', upload_token=token))
    resp.set_cookie('upload_token', token, max_age=600, httponly=False, samesite='Lax')
    return resp

# ---------- WEBSOCKETS ----------
@socketio.on('connect')
def handle_connect():
    emit('historial', historial)

@socketio.on('mensaje')
def manejar_mensaje(data):
    entrada = {'tipo': 'mensaje', 'datos': data}
    historial.append(entrada)
    emit('mensaje', data, broadcast=True)

# ---------- SUBIDA DE ARCHIVOS ----------
@app.route('/upload', methods=['POST'])
def upload_file():
    # Verificar token (cookie o campo del formulario)
    token = request.cookies.get('upload_token') or request.form.get('token', '')
    if not token or token not in upload_tokens:
        return 'No autorizado', 401
    # Verificar antigüedad (10 minutos)
    if time.time() - upload_tokens[token] > 600:
        del upload_tokens[token]
        return 'Token expirado', 401

    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400

    original_name = file.filename
    filename = secure_filename(original_name)

    base, ext = os.path.splitext(filename)
    counter = 1
    while os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], filename)):
        filename = f"{base}_{counter}{ext}"
        counter += 1

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    datos_archivo = {
        'nombre': request.form.get('nombre', 'Anónimo'),
        'original': original_name,
        'guardado': filename,
        'url': f'/download/{filename}',
        'size': os.path.getsize(file_path)
    }
    entrada = {'tipo': 'archivo', 'datos': datos_archivo}
    historial.append(entrada)

    socketio.emit('archivo', datos_archivo)
    return '', 204

@app.route('/download/<filename>')
def download_file(filename):
    # Para descargas seguimos usando la sesión normal, pero si no hay sesión
    # redirigimos al login. Como la descarga se pide desde la página del chat,
    # si el usuario ya está dentro, tendrá la cookie de token o podría no tener sesión.
    # Para simplificar, dejamos que cualquiera con el token válido pueda descargar.
    token = request.cookies.get('upload_token') or request.args.get('token', '')
    if not token or token not in upload_tokens:
        return redirect(url_for('login'))
    filename = secure_filename(filename)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True,
                 ssl_context=(CERT_FILE, KEY_FILE))