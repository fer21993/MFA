import requests
import time
import logging
from flask import Flask, jsonify, request, g
from flask_cors import CORS
import jwt
from datetime import datetime
import os
from shared_db.db import get_db_connection

app = Flask(__name__)
CORS(app, origins=['http://localhost:4200'])

# Configuración de logging a archivo (como respaldo)
log_dir = '/mnt/c/Inge2/pythonOWAS/microservices/logs'
log_file = os.path.join(log_dir, 'api_gateway.log')
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("api_gateway")

AUTH_SERVICE_URL = 'http://localhost:5001'
USER_SERVICE_URL = 'http://localhost:5002'
TASK_SERVICE_URL = 'http://localhost:5003'

# Middleware para registrar el tiempo de inicio y datos iniciales
@app.before_request
def start_timer():
    g.start_time = time.time()
    g.api_service = f"{request.method} {request.path}"
    g.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Obtener usuario desde el token
    g.user = "anonymous"
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        try:
            decoded_token = jwt.decode(token, options={"verify_signature": False})
            g.user = decoded_token.get("username", "anonymous")
        except jwt.InvalidTokenError:
            g.user = "invalid_token"

@app.after_request
def log_request(response):
    response_time = (time.time() - g.start_time) * 1000  # Convertir a milisegundos
    status_code = response.status_code
    
    # Log a archivo (mantenemos como respaldo)
    log_message = (
        f"API: {g.api_service} | "
        f"User: {g.user} | "
        f"Status: {status_code} | "
        f"Response Time: {response_time:.2f}ms | "
        f"Timestamp: {g.timestamp}"
    )
    logger.info(log_message)
    
    # Log a MongoDB
    try:
        collection = get_db_connection(collection_name='logs')
        log_doc = {
            'timestamp': g.timestamp,
            'method': request.method,
            'endpoint': request.path,
            'status_code': status_code,
            'response_time_ms': round(response_time, 2),
            'user': g.user,
            'client_ip': request.remote_addr
        }
        collection.insert_one(log_doc)
    except Exception as e:
        print(f"Error guardando log en MongoDB: {str(e)}")
    
    return response

# Ruta para autenticación (auth service)
@app.route('/auth/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy_auth(path):
    method = request.method
    url = f'{AUTH_SERVICE_URL}/{path}'
    resp = requests.request(
        method=method,
        url=url,
        json=request.get_json(silent=True),
        headers={key: value for key, value in request.headers if key.lower() != 'host'}
    )
    return jsonify(resp.json()), resp.status_code

# Ruta para usuarios (user service)
@app.route('/user/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy_user(path):
    method = request.method
    url = f'{USER_SERVICE_URL}/{path}'
    resp = requests.request(
        method=method,
        url=url,
        json=request.get_json(silent=True),
        headers={key: value for key, value in request.headers if key.lower() != 'host'}
    )
    return jsonify(resp.json()), resp.status_code

# Ruta para tareas (task service)
@app.route('/task/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy_task(path):
    method = request.method
    url = f'{TASK_SERVICE_URL}/{path}'
    resp = requests.request(
        method=method,
        url=url,
        json=request.get_json(silent=True),
        headers={key: value for key, value in request.headers if key.lower() != 'host'}
    )
    return jsonify(resp.json()), resp.status_code

if __name__ == '__main__':
    app.run(port=5000, debug=True)