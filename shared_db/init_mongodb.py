import pymongo
from pymongo import ReturnDocument
from werkzeug.security import generate_password_hash
import datetime

# MongoDB connection string
MONGO_URI = "mongodb+srv://2022371103:Minyoon93@cluster0.cbdtd0g.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
DB_NAME = "shared_db"

# Connect to MongoDB
client = pymongo.MongoClient(MONGO_URI)
db = client[DB_NAME]

def get_next_sequence(collection_name: str) -> int:
    """Generates the next sequence value for auto-increment IDs."""
    counters = db['counters']
    ret = counters.find_one_and_update(
        {'_id': collection_name},
        {'$inc': {'seq': 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER
    )
    return ret['seq']

def init_users_collection():
    """Initialize the 'users' collection with indexes and sample data."""
    collection = db['users']
    
    # Create unique index on 'username'
    if 'username_1' not in collection.index_information():
        collection.create_index('username', unique=True)
    
    # Sample users (same as in original SQLite)
    users = [
        ('username1', 'Hola.123', 1),
        ('username2', 'Hola.123', 1),
        ('username3', 'Hola.123', 1),
        ('username4', 'Hola.123', 1)
    ]
    
    for username, password, status in users:
        if collection.find_one({'username': username}):
            continue  # Skip if user exists
        doc = {
            '_id': get_next_sequence('users'),
            'username': username,
            'password': generate_password_hash(password),
            'email': None,
            'status': status,
            'totp_secret': None
        }
        collection.insert_one(doc)
    print("Users collection initialized with sample data.")

def init_tasks_collection():
    """Initialize the 'tasks' collection with indexes and sample data."""
    collection = db['tasks']
    
    # Create index on 'creator_id' for faster queries
    if 'creator_id_1' not in collection.index_information():
        collection.create_index('creator_id')
    
    # Sample tasks (same as in original SQLite)
    sample_tasks = [
        {
            'task_name': 'Implementar API REST',
            'task_description': 'Desarrollo de endpoints para el microservicio',
            'creation_date': '2024-01-15',
            'deadline_date': '2024-02-15',
            'current_status': 'en_progreso',
            'active_flag': 1,
            'creator_id': 1001,
            'last_modified': datetime.datetime.utcnow()
        },
        {
            'task_name': 'Configurar Base de Datos',
            'task_description': 'Setup inicial de SQLite y tablas',
            'creation_date': '2024-01-10',
            'deadline_date': '2024-01-20',
            'current_status': 'completado',
            'active_flag': 1,
            'creator_id': 1002,
            'last_modified': datetime.datetime.utcnow()
        },
        {
            'task_name': 'Testing y Validación',
            'task_description': 'Pruebas unitarias y de integración',
            'creation_date': '2024-02-01',
            'deadline_date': '2024-02-28',
            'current_status': 'pendiente',
            'active_flag': 1,
            'creator_id': 1001,
            'last_modified': datetime.datetime.utcnow()
        }
    ]
    
    for task in sample_tasks:
        if not collection.find_one({'task_name': task['task_name'], 'creator_id': task['creator_id']}):
            task['_id'] = get_next_sequence('tasks')
            collection.insert_one(task)
    print("Tasks collection initialized with sample data.")

def init_counters_collection():
    """Initialize the 'counters' collection for auto-increment IDs."""
    collection = db['counters']
    # Ensure counters exist for 'users' and 'tasks'
    for counter_name in ['users', 'tasks']:
        if not collection.find_one({'_id': counter_name}):
            collection.insert_one({'_id': counter_name, 'seq': 0})
    print("Counters collection initialized.")

def init_db():
    """Initialize the shared_db database and all required collections."""
    try:
        init_counters_collection()
        init_users_collection()
        init_tasks_collection()
        print(f"Database '{DB_NAME}' initialized successfully.")
    except Exception as e:
        print(f"Error initializing database: {str(e)}")
        raise

if __name__ == '__main__':
    init_db()