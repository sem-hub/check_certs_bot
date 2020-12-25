#!/usr/bin/env python3

import logging
from os import path
import sqlite3

prog_dir = path.dirname(path.abspath(__file__))
db_file = prog_dir+'/checkcerts.sqlite3'

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

class DB_factory:
    def __init__(self):
        self.db = dict()
    def get_db(self, table: str, dbname: str = db_file):
        if dbname not in self.db:
            self.db[dbname] = DB(table, dbname)
        return self.db[dbname]

# XXX Error checking
class DB:
    def __init__(self, table: str, dbname):
        self.table = table
        self.con = sqlite3.connect(dbname, check_same_thread=False)
        self.con.row_factory = dict_factory
        self.cur = self.con.cursor()
    def __del__(self):
        self.con.close()
    def create(self, statement: str):
        self.cur.execute(statement)
        self.con.commit()
    def select(self, what: str, where: str = 'true') -> list:
        logging.debug(f'SELECT {what} FROM {self.table} WHERE {where}')
        self.cur.execute(f'SELECT {what} FROM {self.table} WHERE {where}')
        result = list()
        return self.cur.fetchall()
    def insert(self, fields: str, values: str):
        if fields == None or fields == '':
            self.cur.execute(f'INSERT INTO {self.table} VALUES ({values})')
        else:
            self.cur.execute(f'INSERT INTO {self.table} ({fields}) VALUES ({values})')
        self.con.commit()
    def update(self, what: str, where: str):
        self.cur.execute(f'UPDATE {self.table} SET {what} WHERE {where}')
        self.con.commit()
    def delete(self, where: str):
        self.cur.execute(f'DELETE FROM {self.table} WHERE {where}')
        self.con.commit()
