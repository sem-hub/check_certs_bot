#!/usr/bin/env python3

import logging
import os
import sqlite3

DB_FILE = '/var/spool/check_certs/checkcerts.sqlite3'

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        if type(row[idx]) is str and row[idx].startswith('0000-'):
            d[col[0]] = 'Never'
        else:
            d[col[0]] = row[idx]
    return d

class DB_factory:
    def __init__(self):
        self.db_con = dict()
    def get_db(self, table: str, dbname: str = DB_FILE):
        db_dir = os.path.dirname(dbname)
        if db_dir and '.' not is db_dir:
            os.makedirs(db_dir, exist_ok=True)
        if dbname not in self.db_con:
            self.db_con[dbname] = sqlite3.connect(dbname,
                                        check_same_thread=False)
        return DB(table, self.db_con[dbname])

# XXX Error checking
class DB:
    def __init__(self, table: str, db_con):
        self.table = table
        self.con = db_con
        self.con.row_factory = dict_factory
    def __del__(self):
        self.con.close()
    def create(self, statement: str):
        logging.debug(statement)
        cur = self.con.cursor()
        cur.execute(statement)
        self.con.commit()
    def select(self, what: str, where: str = 'true') -> list:
        logging.debug(f'SELECT {what} FROM {self.table} WHERE {where}')
        cur = self.con.cursor()
        cur.execute(f'SELECT {what} FROM {self.table} WHERE {where}')
        return cur.fetchall()
    def insert(self, fields: str, values: str):
        if fields == None or fields == '':
            logging.debug(f'INSERT INTO {self.table} VALUES ({values})')
            cur = self.con.cursor()
            cur.execute(f'INSERT INTO {self.table} VALUES ({values})')
        else:
            logging.debug(f'INSERT INTO {self.table} ({fields}) VALUES ({values})')
            cur = self.con.cursor()
            cur.execute(f'INSERT INTO {self.table} ({fields}) VALUES ({values})')
        self.con.commit()
    def update(self, what: str, where: str):
        logging.debug(f'UPDATE {self.table} SET {what} WHERE {where}')
        cur = self.con.cursor()
        cur.execute(f'UPDATE {self.table} SET {what} WHERE {where}')
        self.con.commit()
    def delete(self, where: str):
        logging.debug(f'DELETE FROM {self.table} WHERE {where}')
        cur = self.con.cursor()
        cur.execute(f'DELETE FROM {self.table} WHERE {where}')
        self.con.commit()
