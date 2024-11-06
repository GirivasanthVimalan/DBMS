# config.py
import os

class Config:
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'root'
    MYSQL_PASSWORD = 'root@123'
    MYSQL_DB = 'ResourceAllocation'
    SECRET_KEY = os.urandom(24)  # Secret key for session management
