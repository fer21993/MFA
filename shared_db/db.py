import pymongo
import os
from werkzeug.security import generate_password_hash
from pymongo.errors import DuplicateKeyError
from pymongo import ReturnDocument

# MongoDB connection string
MONGO_URI = "mongodb+srv://2022371103:Minyoon93@cluster0.cbdtd0g.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

# Database name
DB_NAME = "shared_db"

# Global client connection
client = pymongo.MongoClient(MONGO_URI)
db = client[DB_NAME]

def get_db_connection(collection_name='users') -> pymongo.collection.Collection:
    """Returns the MongoDB collection for the specified collection_name."""
    return db[collection_name]

def get_next_sequence(name: str) -> int:
    """Gets the next sequence value for auto-increment IDs."""
    counters = db['counters']
    ret = counters.find_one_and_update(
        {'_id': name},
        {'$inc': {'seq': 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER
    )
    return ret['seq']

def init_db():
    collection = get_db_connection(collection_name='users')
    
    # Ensure unique index on 'username'
    if 'username_1' not in collection.index_information():
        collection.create_index('username', unique=True)
    
    # Initial users to insert (if they don't exist based on username)
    users = [
        ('username1', 'Hola.123', 1),
        ('username2', 'Hola.123', 1),
        ('username3', 'Hola.123', 1),
        ('username4', 'Hola.123', 1)
    ]
    
    for user in users:
        username, password, status = user
        if collection.find_one({'username': username}):
            continue
        hashed_password = generate_password_hash(password)
        doc = {
            '_id': get_next_sequence('users'),
            'username': username,
            'password': hashed_password,
            'email': None,
            'status': status,
            'totp_secret': None
        }
        collection.insert_one(doc)