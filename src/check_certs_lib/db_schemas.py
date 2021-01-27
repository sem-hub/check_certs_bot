# Schemas for creating of TABLES in DB

users_create_statement='''CREATE TABLE IF NOT EXISTS users (
id TEXT PRIMARY KEY,
name TEXT,
full_name TEXT,
language_code TEXT,
first_met TEXT,
last_activity TEXT,
status TEXT
)'''

activity_create_statement='''CREATE TABLE IF NOT EXISTS activity (
id INTEGER PRIMARY KEY AUTOINCREMENT,
user_id TEXT,
cmd TEXT,
date TEXT
)'''

servers_create_statement='''CREATE TABLE IF NOT EXISTS servers (
id INTEGER PRIMARY KEY AUTOINCREMENT,
when_added TEXT,
url TEXT,
chat_id TEXT,
warn_before_expired INTEGER,
last_checked TEXT,
last_ok TEXT,
status TEXT,
cert_id TEXT
)'''
