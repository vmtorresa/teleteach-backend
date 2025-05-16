# Proyecto: TeleTeach - Incremento 1
# Backend en Flask - Módulos: Autenticación, Curso Meet, Panel Inicial

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import datetime

app = Flask(__name__)
CORS(app)

# Configuraciones
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///teleteach.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'super-secret-key'  # Cambiar en producción

# Inicialización
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# ------------------ MODELOS ------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(100), nullable=False)

class CourseContent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    platform = db.Column(db.String(50), nullable=False)  # Ej: 'Meet'
    content = db.Column(db.Text, nullable=False)  # HTML/Markdown o URL a video

# ------------------ ENDPOINTS ------------------
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(email=data['email'], password=hashed_pw, name=data['name'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Usuario registrado correctamente."}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.id, expires_delta=datetime.timedelta(hours=1))
        return jsonify(access_token=access_token, name=user.name), 200
    return jsonify({"error": "Credenciales inválidas"}), 401

@app.route('/api/user', methods=['GET'])
@jwt_required()
def get_user():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    return jsonify({"email": user.email, "name": user.name})

@app.route('/api/courses/meet', methods=['GET'])
@jwt_required()
def get_meet_content():
    content = CourseContent.query.filter_by(platform='Meet').all()
    response = [{"title": c.title, "content": c.content} for c in content]
    return jsonify(response)

# ------------------ UTILIDAD ------------------
@app.cli.command('initdb')
def initdb():
    db.create_all()
    print('Base de datos inicializada.')

@app.cli.command('seed')
def seed():
    meet1 = CourseContent(title='Introducción a Meet', platform='Meet', content='''<h3>Crear una reunión</h3><p>Paso 1: Inicia sesión en tu cuenta de Google...</p>''')
    meet2 = CourseContent(title='Funciones principales de Meet', platform='Meet', content='''<ul><li>Silenciar micrófono</li><li>Compartir pantalla</li></ul>''')
    db.session.add_all([meet1, meet2])
    db.session.commit()
    print('Contenido inicial agregado.')

@app.route('/')
def index():
    return "Bienvenido a la API de TeleTeach"


# ------------------ MAIN ------------------
if __name__ == '__main__':
    app.run(debug=True)
