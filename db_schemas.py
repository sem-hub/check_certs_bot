users_create_statement='''CREATE TABLE IF NOT EXISTS users (
name TEXT,
chat_id TEXT
)'''

periodic_create_statement='''CREATE TABLE IF NOT EXISTS periodic (
)'''

servers_create_statement='''CREATE TABLE IF NOT EXISTS servers (
when_added TEXT,
url TEXT,
chat_id TEXT,
warn_before_expired INTEGER,
last_checked TEXT,
last_ok TEXT,
status TEXT,
cert_id TEXT
)'''
