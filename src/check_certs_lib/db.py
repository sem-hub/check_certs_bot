'''Simple and useful function for databases communication. Support sqslite3 now.'''

import logging
import os
import sqlite3


# Default DB file path
DB_FILE = '/var/spool/check_certs/checkcerts.sqlite3'

def dict_factory(cursor, row) -> dict:
    '''
    Row_factory function for sqlite3 module. It makes SELECT returns dict()
    Timestamps started with '0000-' returns as 'Never'
    '''
    res = {}
    for idx, col in enumerate(cursor.description):
        if isinstance(row[idx], str) and row[idx].startswith('0000-'):
            res[col[0]] = 'Never'
        else:
            res[col[0]] = row[idx]
    return res

class DB:
    '''
    Class with function for making DB connection and requests.
    You must not use this class directly. Create DBfactory class and get DB
    from it:

    db_factory = DBfactory()
    my_db = db_factory.get_db('my_table', 'my_db')
    '''
    def __init__(self, table: str, db_con):
        self.table = table
        self.con = db_con
        self.con.row_factory = dict_factory
        self.logger = logging.getLogger(__name__)
    def __del__(self):
        '''Close connection on exit.'''
        self.con.close()
    def create(self, statement: str) -> None:
        '''
        Do CREATE command to create a new table. Get a stricg as a create statement.
        '''
        self.logger.debug(statement)
        cur = self.con.cursor()
        cur.execute(statement)
        self.con.commit()
    def select(self, what: str, where: str = 'true') -> list:
        '''
        Do SELECT command.
        Get 'what' and 'where' expressions. A result command will:
        SELECT {what} FROM {self.table} WHERE {where}

        Return ROWs as a list of tuples of values.
        '''
        self.logger.debug('SELECT %s FROM %s WHERE %s', what, self.table, where)
        cur = self.con.cursor()
        cur.execute(f'SELECT {what} FROM {self.table} WHERE {where}')
        return cur.fetchall()
    def insert(self, fields: str, values: str) -> None:
        '''
        Do INSERT command.
        Get fields list and values list.
        If don't have fields list ('' or None'') the command looks lite this:
        INSERT INTO {self.table} VALUES ({values})
        otherwise:
        INSERT INTO {self.table} ({fields}) VALUES ({values})
        '''
        if fields in (None, ''):
            self.logger.debug('INSERT INTO %s VALUES (%s)', self.table, values)
            cur = self.con.cursor()
            cur.execute(f'INSERT INTO {self.table} VALUES ({values})')
        else:
            self.logger.debug('INSERT INTO %s (%s) VALUES (%s)', self.table, fields, values)
            cur = self.con.cursor()
            cur.execute(f'INSERT INTO {self.table} ({fields}) VALUES ({values})')
        self.con.commit()
    def update(self, what: str, where: str) -> None:
        '''
        Do UPDATE command.
        Get 'what' and 'where':
        UPDATE {self.table} SET {what} WHERE {where}
        '''
        self.logger.debug('UPDATE %s SET %s WHERE %s', self.table, what, where)
        cur = self.con.cursor()
        cur.execute(f'UPDATE {self.table} SET {what} WHERE {where}')
        self.con.commit()
    def delete(self, where: str) -> None:
        '''
        Do DELETE command.
        Get 'where' argument:
        DELETE FROM {self.table} WHERE {where}
        '''
        self.logger.debug('DELETE FROM %s WHERE %s', self.table, where)
        cur = self.con.cursor()
        cur.execute(f'DELETE FROM {self.table} WHERE {where}')
        self.con.commit()

class DBfactory:
    '''
    DBfactory construct DB objects. Some of them can share one connection.
    This class creates DB classes and share connection between them if possible.
    For different DB filles will created different connections.
    '''
    def __init__(self):
        self.db_con: dict = {}
    def get_db(self, table: str, dbname: str = DB_FILE) -> DB:
        '''
        Get database (really table) descriptor for this table/dbname pair.
        '''
        db_dir = os.path.dirname(dbname)
        if db_dir and '.' not in db_dir:
            os.makedirs(db_dir, exist_ok=True)
        if dbname not in self.db_con:
            self.db_con[dbname] = sqlite3.connect(dbname,
                                        check_same_thread=False)
        return DB(table, self.db_con[dbname])
