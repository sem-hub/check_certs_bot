#!/usr/bin/env python3

import logging
from os import path
import sqlite3

prog_dir = path.dirname(path.abspath(__file__))

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        if row[idx].isdigit():
            d[col[0]] = int(row[idx])
        else:
            d[col[0]] = row[idx]
    return d

# XXX Error checking
class DB:
    def __init__(self, dbname: str):
        self.dbname = dbname
        self.con = sqlite3.connect(prog_dir+'/checkcerts.sqlite3',
                check_same_thread=False)
        self.con.row_factory = dict_factory
        self.cur = self.con.cursor()
    def __del__(self):
        self.con.close()
    def create(self, statement: str):
        self.cur.execute(statement)
        self.con.commit()
    def select(self, what: str, where: str = 'true') -> list:
        logging.debug(f'SELECT {what} FROM {self.dbname} WHERE {where}')
        self.cur.execute(f'SELECT {what} FROM {self.dbname} WHERE {where}')
        result = list()
        return self.cur.fetchall()
    def insert(self, fields: str, values: str):
        if fields == None or fields == '':
            self.cur.execute(f'INSERT INTO {self.dbname} VALUES ({values})')
        else:
            self.cur.execute(f'INSERT INTO {self.dbname} ({fields}) VALUES ({values})')
        self.con.commit()
    def update(self, what: str, where: str):
        self.cur.execute(f'UPDATE {self.dbname} SET {what} WHERE {where}')
        self.con.commit()
    def delete(self, where: str):
        self.cur.execute(f'DELETE FROM {self.dbname} WHERE {where}')
        self.con.commit()
