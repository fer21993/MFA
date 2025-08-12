import sys
import os
import traceback
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, jsonify, request, g
from flask_cors import CORS
import re
import pyotp
import qrcode
import io
import base64
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import time
from shared_db.db import get_db_connection, init_db, get_next_sequence

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://localhost:4200"}})
SECRET_KEY = "a8f3c9d2f021ae6b8b76935b8e7f89ad28d76f9d29e3a1cf21e8b2c91566f51a"

def validate_username(username: str) -> bool:
    return bool(username and 3 <= len(username) <= 50 and re.match(r'^[a-zA-Z0-9_]+$', username))

def validate_password(password: str) -> bool:
    return bool(password and len(password) >= 8)

def validate_email(email: str) -> bool:
    return bool(email and re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email))

@app.before_request
def start_timer():
    g.start_time = time.time()

@app.after_request
def log_request(response):
    try:
        collection = get_db_connection(collection_name='logs')
        duration = (time.time() - g.start_time) * 1000
        user = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].replace('Bearer ', '')
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
                user = payload.get('username')
            except:
                pass
        log_entry = {
            'timestamp': datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            'method': request.method,
            'endpoint': request.path,
            'status_code': response.status_code,
            'response_time_ms': round(duration, 2),
            'user': user or 'anonymous',
            'client_ip': request.remote_addr
        }
        collection.insert_one(log_entry)
    except Exception as e:
        print(f"Error logging request: {str(e)}")
        traceback.print_exc()
    return response

@app.route('/register_user', methods=['POST'])
def register_user():
    try:
        data = request.json
        if not data:
            return jsonify({
                'statusCode': 400,
                'intData': {'message': 'Cuerpo de la solicitud inválido'}
            }), 400

        username = data.get('username', '')
        email = data.get('email', '')
        password = data.get('password', '')
        confirm_password = data.get('confirmPassword', '')

        if not validate_username(username):
            return jsonify({
                'statusCode': 400,
                'intData': {'message': 'Nombre de usuario inválido (3-50 caracteres, solo letras, números y guiones bajos)'}
            }), 400
        if not validate_email(email):
            return jsonify({
                'statusCode': 400,
                'intData': {'message': 'Correo electrónico inválido'}
            }), 400
        if not validate_password(password):
            return jsonify({
                'statusCode': 400,
                'intData': {'message': 'La contraseña debe tener al menos 8 caracteres'}
            }), 400
        if password != confirm_password:
            return jsonify({
                'statusCode': 400,
                'intData': {'message': 'Las contraseñas no coinciden'}
            }), 400

        collection = get_db_connection(collection_name='users')
        existing = collection.find_one({'$or': [{'username': username}, {'email': email}]})
        if existing:
            return jsonify({
                'statusCode': 409,
                'intData': {'message': 'El usuario o email ya está registrado'}
            }), 409

        hashed_password = generate_password_hash(password)
        status = 1
        totp_secret = pyotp.random_base32()
        uri = pyotp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="TuApp2FA")

        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
        qr_data_url = f"data:image/png;base64,{qr_base64}"

        try:
            base64.b64decode(qr_base64)
        except Exception as e:
            print(f"Error decoding base64: {str(e)}")
            return jsonify({
                'statusCode': 500,
                'intData': {'message': 'Error generando el código QR'}
            }), 500

        doc = {
            '_id': get_next_sequence('users'),
            'username': username,
            'password': hashed_password,
            'email': email,
            'status': status,
            'totp_secret': totp_secret
        }
        collection.insert_one(doc)

        return jsonify({
            'statusCode': 201,
            'intData': {
                'message': 'Usuario registrado exitosamente',
                'qr': qr_data_url
            }
        })
    except Exception as e:
        print(f"Error: {str(e)}")
        traceback.print_exc()
        return jsonify({
            'statusCode': 500,
            'intData': {'message': f'Error interno: {str(e)}'}
        }), 500

@app.route('/logs', methods=['GET'])
def get_logs():
    try:
        collection = get_db_connection(collection_name='logs')
        logs = list(collection.find({}, {'_id': 0}).sort('timestamp', -1).limit(100))
        return jsonify({'statusCode': 200, 'intData': logs}), 200
    except Exception as e:
        print(f"Error en /logs: {str(e)}")
        traceback.print_exc()
        return jsonify({'statusCode': 500, 'intData': {'message': f'Error interno: {str(e)}'}}), 500

@app.route('/debug/totp/<username>', methods=['GET'])
def debug_totp(username):
    try:
        collection = get_db_connection(collection_name='users')
        user = collection.find_one({'username': username})
        
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
            
        totp_secret = user.get('totp_secret')
        if not totp_secret:
            return jsonify({'error': 'No hay TOTP secret'}), 404
            
        totp = pyotp.TOTP(totp_secret)
        current_code = totp.now()
        
        current_timestamp = int(time.time())
        
        valid_codes = []
        for offset in range(-3, 4):
            timestamp = current_timestamp + (offset * 30)
            code = totp.at(timestamp)
            valid_codes.append({
                'offset_seconds': offset * 30,
                'code': code,
                'timestamp': timestamp
            })
        
        return jsonify({
            'username': username,
            'current_code': current_code,
            'current_timestamp': current_timestamp,
            'totp_secret_preview': totp_secret[:8] + '...',
            'valid_codes_window': valid_codes
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        if not data:
            return jsonify({
                'statusCode': 400,
                'intData': {'message': 'Cuerpo de la solicitud inválido'}
            }), 400

        username = data.get('username')
        password = data.get('password')
        otp_code = data.get('otp')

        if not username or not password or not otp_code:
            return jsonify({
                'statusCode': 400,
                'intData': {'message': 'Usuario, contraseña y código TOTP son requeridos'}
            }), 400

        otp_code = str(otp_code).strip()

        collection = get_db_connection(collection_name='users')
        user = collection.find_one({'username': username})
        
        if not user:
            return jsonify({
                'statusCode': 401,
                'intData': {'message': 'Credenciales incorrectas'}
            }), 401
        
        if not check_password_hash(user['password'], password):
            return jsonify({
                'statusCode': 401,
                'intData': {'message': 'Credenciales incorrectas'}
            }), 401

        totp_secret = user.get('totp_secret')
        if not totp_secret:
            return jsonify({
                'statusCode': 500,
                'intData': {'message': 'Error de configuración 2FA'}
            }), 500
        
        totp = pyotp.TOTP(totp_secret)
        if not totp.verify(otp_code, valid_window=2):
            expected_code = totp.now()
            return jsonify({
                'statusCode': 401,
                'intData': {'message': f'Código 2FA inválido. Esperado: {expected_code}, Recibido: {otp_code}'}
            }), 401

        token = jwt.encode({
            'username': username,
            'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        }, SECRET_KEY, algorithm='HS256')

        return jsonify({
            'statusCode': 200,
            'intData': {
                'message': 'Login exitoso',
                'token': token,
                'username': username
            }
        })
    except Exception as e:
        print(f"ERROR CRÍTICO en login: {str(e)}")
        traceback.print_exc()
        return jsonify({
            'statusCode': 500,
            'intData': {'message': f'Error interno: {str(e)}'}
        }), 500

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5001, debug=True)