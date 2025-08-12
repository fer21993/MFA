import sys
import os
import traceback
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, jsonify, request, g
from flask_cors import CORS
import requests
import jwt
import datetime
import re
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from shared_db.db import get_db_connection, init_db
import time

app = Flask(__name__)
CORS(app, origins=['http://localhost:4200'])
SECRET_KEY = "a8f3c9d2f021ae6b8b76935b8e7f89ad28d76f9d29e3a1cf21e8b2c91566f51a"

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

def validate_username(username: str) -> bool:
    return bool(username and 3 <= len(username) <= 50 and re.match(r'^[a-zA-Z0-9_]+$', username))

def validate_password(password: str) -> bool:
    return bool(password and len(password) >= 8)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token requerido', 'status': 'error'}), 401
        try:
            if token.startswith("Bearer "):
                token = token.split(" ")[1]
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user = decoded
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expirado', 'status': 'error'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token inválido', 'status': 'error'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/users', methods=['GET'])
@token_required
def list_users():
    try:
        collection = get_db_connection()
        users = collection.find({}, {'_id': 1, 'username': 1, 'status': 1})
        
        return jsonify({
            "status": "success",
            "users": [{
                "id": user["_id"],
                "username": user["username"],
                "status": user["status"]
            } for user in users]
        }), 200
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}", "status": "error"}), 500

@app.route('/users/<int:user_id>', methods=['GET'])
@token_required
def get_user(user_id):
    try:
        collection = get_db_connection()
        user = collection.find_one({"_id": user_id}, {'_id': 1, 'username': 1, 'status': 1})
        
        if not user:
            return jsonify({"message": "Usuario no encontrado", "status": "error"}), 404
        
        return jsonify({
            "status": "success",
            "user": {
                "id": user["_id"],
                "username": user["username"],
                "status": user["status"]
            }
        }), 200
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}", "status": "error"}), 500

@app.route('/users/<int:user_id>/disable', methods=['PUT'])
@token_required
def disable_user(user_id):
    try:
        collection = get_db_connection()
        result = collection.update_one({"_id": user_id}, {"$set": {"status": 0}})
        
        if result.matched_count == 0:
            return jsonify({"message": "Usuario no encontrado", "status": "error"}), 404
        
        return jsonify({"message": "Usuario deshabilitado correctamente", "status": "success"}), 200
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}", "status": "error"}), 500

@app.route('/users/<int:user_id>/enable', methods=['PUT'])
@token_required
def enable_user(user_id):
    try:
        collection = get_db_connection()
        result = collection.update_one({"_id": user_id}, {"$set": {"status": 1}})
        
        if result.matched_count == 0:
            return jsonify({"message": "Usuario no encontrado", "status": "error"}), 404
        
        return jsonify({"message": "Usuario habilitado correctamente", "status": "success"}), 200
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}", "status": "error"}), 500

@app.route('/users/<int:user_id>', methods=['PUT'])
@token_required
def edit_user(user_id):
    data = request.get_json()
    
    required_fields = ['username', 'password']
    if not all(field in data for field in required_fields):
        return jsonify({"message": "Todos los campos son requeridos", "status": "error"}), 400
    
    username = data['username']
    password = data['password']
    
    if not validate_username(username):
        return jsonify({"message": "Nombre de usuario inválido (3-50 caracteres, solo letras, números y guiones bajos)", "status": "error"}), 400
    if not validate_password(password):
        return jsonify({"message": "La contraseña debe tener al menos 8 caracteres", "status": "error"}), 400
    
    try:
        collection = get_db_connection()
        
        if collection.find_one({"username": username, "_id": {"$ne": user_id}}):
            return jsonify({"message": "Nombre de usuario ya registrado", "status": "error"}), 400
        
        hashed_password = generate_password_hash(password)
        
        result = collection.update_one(
            {"_id": user_id},
            {"$set": {"username": username, "password": hashed_password}}
        )
        
        if result.matched_count == 0:
            return jsonify({"message": "Usuario no encontrado", "status": "error"}), 404
        
        return jsonify({"message": "Usuario editado correctamente", "status": "success"}), 200
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}", "status": "error"}), 500

if __name__ == '__main__':
    init_db()
    app.run(port=5002, debug=True)