import os
from datetime import datetime, timedelta
from functools import wraps
import jwt

from flask import (
    Flask, request, jsonify, redirect, url_for, send_from_directory,
    make_response, render_template, flash
)
from flask_cors import CORS
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_mysqldb import MySQL
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename

from config import config
from models.ModelUser import ModelUser
from models.entities.User import User

app = Flask(__name__, template_folder='templates')
app.config.from_object(config['development'])
app.config['SECRET_KEY'] = 'clave-super-secreta-para-produccion'
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
CORS(app, supports_credentials=True)

csrf = CSRFProtect(app)
db = MySQL(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login_html'

# Usuario admin fijo para demo
USUARIO = {
    'id': 1,
    'username': 'admin',
    'password': '123'
}

class UserLogin(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    if str(user_id) == str(USUARIO['id']):
        return UserLogin(USUARIO['id'], USUARIO['username'])
    return None

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def verificar_token_cookie():
    token = request.cookies.get('token')
    if not token:
        return None
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if payload.get('user_id') == USUARIO['id']:
            return USUARIO
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None
    return None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = verificar_token_cookie()
        if not user:
            if request.path.startswith('/api/'):
                return jsonify({'message': 'Token inválido o expirado'}), 401
            return redirect(url_for('login_html'))
        return f(user, *args, **kwargs)
    return decorated

@app.route('/login', methods=['GET', 'POST'])
def login_html():
    if current_user.is_authenticated:
        return redirect(url_for('flask_home'))

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        user = User(0, username, password)
        logged_user = ModelUser.login(db, user)
        if logged_user:
            login_user(logged_user)
            flash(f"Bienvenido, {logged_user.username}!", "success")
            return redirect(url_for('flask_home'))
        else:
            flash("Usuario o contraseña incorrectos", "danger")

    return render_template('auth/login.html')

@app.route('/flask-home')
@login_required
def flask_home():
    return render_template('home.html', user=current_user)

@app.route('/flask-logout')
@login_required
def flask_logout():
    logout_user()
    flash("Has cerrado sesión correctamente.", "info")
    return redirect(url_for('login_html'))

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    if data['username'] == 'admin' and data['password'] == '123':
        resp = jsonify({'message': 'Login correcto'})
        resp.set_cookie('token', 'token_fake', httponly=True)
        return resp
    return jsonify({'message': 'Credenciales incorrectas'}), 401


@app.route('/api/logout', methods=['POST'])
@csrf.exempt
def api_logout():
    resp = make_response(jsonify({'message': 'Sesión cerrada'}))
    resp.set_cookie('token', '', expires=0)
    return resp

# Datos en memoria para ejemplo
productos = []
product_id_counter = 1

@app.route('/api/productos', methods=['GET'])
def api_productos():
    return jsonify(productos)

@app.route('/api/productos', methods=['POST'])
@token_required
def add_product(user):
    global product_id_counter
    nombre = request.form.get('nombre', '').strip()
    precio = request.form.get('precio')
    descripcion = request.form.get('descripcion', '').strip()
    imagen_url = request.form.get('imagenUrl', '').strip()

    if not nombre or precio is None:
        return jsonify({'message': 'Nombre y precio requeridos'}), 400
    try:
        precio = float(precio)
    except ValueError:
        return jsonify({'message': 'Precio inválido'}), 400

    imagen_file = request.files.get('imagenFile')
    imagen_path = ''

    if imagen_file and imagen_file.filename != '':
        if allowed_file(imagen_file.filename):
            filename = secure_filename(imagen_file.filename)
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{product_id_counter}_{filename}')
            imagen_file.save(save_path)
            imagen_path = f'/uploads/{os.path.basename(save_path)}'
        else:
            return jsonify({'message': 'Archivo de imagen no permitido'}), 400
    elif imagen_url:
        imagen_path = imagen_url

    producto = {
        'id': product_id_counter,
        'nombre': nombre,
        'descripcion': descripcion,
        'precio': precio,
        'imagen': imagen_path
    }
    productos.append(producto)
    product_id_counter += 1
    return jsonify({'message': 'Producto agregado', 'producto': producto}), 201

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
@token_required
def home_page(user):
    return render_template('home.html', user=user)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)