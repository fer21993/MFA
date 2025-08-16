import sys
import os
import datetime
import logging
from flask import Flask, jsonify, request, g
from flask_cors import CORS
import requests
import jwt
from functools import wraps
import pymongo
from pymongo import ReturnDocument, DESCENDING
import traceback
import time

app = Flask(__name__)
CORS(app, origins=['http://localhost:4200'])

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

JWT_SECRET_KEY = "a8f3c9d2f021ae6b8b76935b8e7f89ad28d76f9d29e3a1cf21e8b2c91566f51a"

MONGO_URI = "mongodb+srv://2022371103:Minyoon93@cluster0.cbdtd0g.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = pymongo.MongoClient(MONGO_URI)
db = client['shared_db']

@app.before_request
def start_timer():
    g.start_time = time.time()

@app.after_request
def log_request(response):
    try:
        collection = db['logs']
        duration = (time.time() - g.start_time) * 1000
        user = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].replace('Bearer ', '')
            try:
                payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
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

def get_next_sequence(name: str) -> int:
    counters = db['counters']
    ret = counters.find_one_and_update(
        {'_id': name},
        {'$inc': {'seq': 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER
    )
    return ret['seq']

class TaskService:
    def __init__(self):
        self.setup_database()
    
    def validate_date_format(self, date_string):
        try:
            datetime.datetime.strptime(date_string, '%Y-%m-%d')
            return True
        except ValueError:
            logger.error(f"Formato de fecha inválido: {date_string}")
            return False
    
    def create_db_connection(self):
        return db['tasks']
    
    def setup_database(self):
        try:
            collection = self.create_db_connection()
            collection.create_index('creator_id')
            sample_tasks = [
                {'task_name': 'Implementar API REST', 'task_description': 'Desarrollo de endpoints para el microservicio', 
                 'creation_date': '2024-01-15', 'deadline_date': '2024-02-15', 'current_status': 'en_progreso', 'active_flag': 1, 'creator_id': 1001,
                 'last_modified': datetime.datetime.utcnow()},
                {'task_name': 'Configurar Base de Datos', 'task_description': 'Setup inicial de SQLite y tablas', 
                 'creation_date': '2024-01-10', 'deadline_date': '2024-01-20', 'current_status': 'completado', 'active_flag': 1, 'creator_id': 1002,
                 'last_modified': datetime.datetime.utcnow()},
                {'task_name': 'Testing y Validación', 'task_description': 'Pruebas unitarias y de integración', 
                 'creation_date': '2024-02-01', 'deadline_date': '2024-02-28', 'current_status': 'pendiente', 'active_flag': 1, 'creator_id': 1001,
                 'last_modified': datetime.datetime.utcnow()}
            ]
            
            for task in sample_tasks:
                if not collection.find_one({'task_name': task['task_name'], 'creator_id': task['creator_id']}):
                    task['_id'] = get_next_sequence('tasks')
                    collection.insert_one(task)
            
            logger.info("Base de datos inicializada correctamente")
            
        except Exception as e:
            logger.error(f"Error al inicializar la base de datos: {e}")
            raise e

task_service = TaskService()

def require_jwt_token(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return jsonify({
                'statusCode': 401,
                'intData': {
                    'message': 'Token de autorización requerido',
                    'data': None
                }
            }), 401
        
        try:
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
            else:
                token = auth_header
            
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
            request.current_user = payload
            
        except jwt.ExpiredSignatureError:
            return jsonify({
                'statusCode': 401,
                'intData': {
                    'message': 'El token ha expirado',
                    'data': None
                }
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                'statusCode': 401,
                'intData': {
                    'message': 'Token inválido',
                    'data': None
                }
            }), 401
        
        return function(*args, **kwargs)
    return decorated_function

@app.route('/api/tasks', methods=['GET'])
@require_jwt_token
def get_all_tasks():
    try:
        collection = task_service.create_db_connection()
        
        tasks_data = collection.find(
            {"active_flag": 1},
            sort=[('creation_date', DESCENDING)]
        )
        
        tasks_list = []
        for task in tasks_data:
            tasks_list.append({
                "id": task["_id"],
                "name": task["task_name"],
                "description": task["task_description"],
                "created_at": task["creation_date"],
                "deadline": task["deadline_date"],
                "status": task["current_status"],
                "is_active": bool(task["active_flag"]),
                "created_by": task["creator_id"],
                "last_modified": task["last_modified"].isoformat() if 'last_modified' in task else None
            })
        
        return jsonify({
            "statusCode": 200,
            "intData": {
                "message": "Tareas obtenidas exitosamente",
                "data": tasks_list,
                "total_count": len(tasks_list)
            }
        })
        
    except Exception as e:
        logger.error(f"Error: {e}")
        return jsonify({
            "statusCode": 500,
            "intData": {
                "message": "Error interno del servidor",
                "data": None
            }
        }), 500

@app.route('/api/tasks/<int:task_id>', methods=['GET'])
@require_jwt_token
def get_task_by_id(task_id):
    try:
        collection = task_service.create_db_connection()
        
        task_data = collection.find_one({"_id": task_id, "active_flag": 1})
        
        if not task_data:
            return jsonify({
                "statusCode": 404,
                "intData": {
                    "message": "Tarea no encontrada",
                    "data": None
                }
            }), 404
        
        task_info = {
            "id": task_data["_id"],
            "name": task_data["task_name"],
            "description": task_data["task_description"],
            "created_at": task_data["creation_date"],
            "deadline": task_data["deadline_date"],
            "status": task_data["current_status"],
            "is_active": bool(task_data["active_flag"]),
            "created_by": task_data["creator_id"],
            "last_modified": task_data["last_modified"].isoformat() if 'last_modified' in task_data else None
        }
        
        return jsonify({
            "statusCode": 200,
            "intData": {
                "message": "Tarea encontrada",
                "data": task_info
            }
        })
        
    except Exception as e:
        logger.error(f"Error: {e}")
        return jsonify({
            "statusCode": 500,
            "intData": {
                "message": "Error interno del servidor",
                "data": None
            }
        }), 500

@app.route('/api/tasks/create', methods=['POST'])
@require_jwt_token
def create_new_task():
    try:
        request_data = request.get_json()
        
        required_fields = ['name', 'description', 'creation_date', 'deadline', 'status', 'creator_id']
        missing_fields = [field for field in required_fields if field not in request_data]
        
        if missing_fields:
            return jsonify({
                "statusCode": 400,
                "intData": {
                    "message": f"Campos faltantes: {', '.join(missing_fields)}",
                    "data": None
                }
            }), 400
        
        if not task_service.validate_date_format(request_data['creation_date']):
            return jsonify({
                "statusCode": 400,
                "intData": {
                    "message": "Formato de fecha de creación inválido (YYYY-MM-DD)",
                    "data": None
                }
            }), 400
        
        if not task_service.validate_date_format(request_data['deadline']):
            return jsonify({
                "statusCode": 400,
                "intData": {
                    "message": "Formato de fecha límite inválido (YYYY-MM-DD)",
                    "data": None
                }
            }), 400
        
        collection = task_service.create_db_connection()
        
        doc = {
            "_id": get_next_sequence('tasks'),
            "task_name": request_data['name'],
            "task_description": request_data['description'],
            "creation_date": request_data['creation_date'],
            "deadline_date": request_data['deadline'],
            "current_status": request_data['status'],
            "active_flag": 1,
            "creator_id": request_data['creator_id'],
            "last_modified": datetime.datetime.utcnow()
        }
        collection.insert_one(doc)
        
        new_task_id = doc['_id']
        
        return jsonify({
            "statusCode": 201,
            "intData": {
                "message": "Tarea creada exitosamente",
                "data": {"task_id": new_task_id}
            }
        })
        
    except Exception as e:
        logger.error(f"Error al crear tarea: {e}")
        return jsonify({
            "statusCode": 500,
            "intData": {
                "message": "Error al crear la tarea",
                "data": None
            }
        }), 500

@app.route('/api/tasks/<int:task_id>/update', methods=['PUT'])
@require_jwt_token
def update_existing_task(task_id):
    try:
        request_data = request.get_json()
        
        collection = task_service.create_db_connection()
        
        if not collection.find_one({"_id": task_id, "active_flag": 1}):
            return jsonify({
                "statusCode": 404,
                "intData": {
                    "message": "Tarea no encontrada",
                    "data": None
                }
            }), 404
        
        update_dict = {}
        field_mappings = {
            'name': 'task_name',
            'description': 'task_description',
            'creation_date': 'creation_date',
            'deadline': 'deadline_date',
            'status': 'current_status',
            'creator_id': 'creator_id'
        }
        
        for field, db_field in field_mappings.items():
            if field in request_data:
                if field in ['creation_date', 'deadline']:
                    if not task_service.validate_date_format(request_data[field]):
                        return jsonify({
                            "statusCode": 400,
                            "intData": {
                                "message": f"Formato de fecha inválido para {field}",
                                "data": None
                            }
                        }), 400
                update_dict[db_field] = request_data[field]
        
        if not update_dict:
            return jsonify({
                "statusCode": 400,
                "intData": {
                    "message": "No se proporcionaron campos para actualizar",
                    "data": None
                }
            }), 400
        
        update_dict["last_modified"] = datetime.datetime.utcnow()
        
        result = collection.update_one({"_id": task_id}, {"$set": update_dict})
        
        return jsonify({
            "statusCode": 200,
            "intData": {
                "message": "Tarea actualizada exitosamente",
                "data": None
            }
        })
        
    except Exception as e:
        logger.error(f"Error al actualizar tarea: {e}")
        return jsonify({
            "statusCode": 500,
            "intData": {
                "message": "Error al actualizar la tarea",
                "data": None
            }
        }), 500

@app.route('/api/tasks/<int:task_id>/deactivate', methods=['PUT'])
@require_jwt_token
def deactivate_task(task_id):
    try:
        collection = task_service.create_db_connection()
        
        result = collection.update_one(
            {"_id": task_id, "active_flag": 1},
            {"$set": {"active_flag": 0, "last_modified": datetime.datetime.utcnow()}}
        )
        
        if result.matched_count == 0:
            return jsonify({
                "statusCode": 404,
                "intData": {
                    "message": "Tarea no encontrada o ya está desactivada",
                    "data": None
                }
            }), 404
        
        return jsonify({
            "statusCode": 200,
            "intData": {
                "message": "Tarea desactivada exitosamente",
                "data": None
            }
        })
        
    except Exception as e:
        logger.error(f"Error al desactivar tarea: {e}")
        return jsonify({
            "statusCode": 500,
            "intData": {
                "message": "Error al desactivar la tarea",
                "data": None
            }
        }), 500

@app.route('/api/tasks/<int:task_id>/activate', methods=['PUT'])
@require_jwt_token
def activate_task(task_id):
    try:
        collection = task_service.create_db_connection()
        
        result = collection.update_one(
            {"_id": task_id},
            {"$set": {"active_flag": 1, "last_modified": datetime.datetime.utcnow()}}
        )
        
        if result.matched_count == 0:
            return jsonify({
                "statusCode": 404,
                "intData": {
                    "message": "Tarea no encontrada",
                    "data": None
                }
            }), 404
        
        return jsonify({
            "statusCode": 200,
            "intData": {
                "message": "Tarea activada exitosamente",
                "data": None
            }
        })
        
    except Exception as e:
        logger.error(f"Error al activar tarea: {e}")
        return jsonify({
            "statusCode": 500,
            "intData": {
                "message": "Error al activar la tarea",
                "data": None
            }
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "statusCode": 200,
        "intData": {
            "message": "Servicio de tareas funcionando correctamente",
            "service": "Task Management Service",
            "timestamp": datetime.datetime.now().isoformat()
        }
    })

if __name__ == '__main__':
    try:
        logger.info("Iniciando servicio de gestión de tareas...")
        app.run(host='0.0.0.0', port=5003, debug=True)
    except Exception as e:
        logger.error(f"Error al iniciar el servidor: {e}")
        sys.exit(1)