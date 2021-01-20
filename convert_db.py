#!/usr/bin/env python3

from os import sys,path
work_dir = path.dirname(path.abspath(__file__))
sys.path.append(work_dir)

from db import DB_factory
import db_schemas

db_factory = DB_factory()
servers_db = db_factory.get_db('servers')
new_servers_db = db_factory.get_db('servers', 'new_db.sqlite3')
new_servers_db.create(db_schemas.servers_create_statement)
res = servers_db.select('*')
keys = ''
values = ''
tmp = ''
for r in res:
    for k in r.keys():
        tmpk = k
        tmpval = r[k]
        if tmpval == None:
            tmpval = '0000-00-00 00:00:00'
        if k == 'hostname':
            tmp = r[k]
            continue
        if k == 'proto':
            if r[k] == 'plain':
                tmp = 'imaps://' + tmp
            else:
                tmp = r[k] + '://' + tmp
            continue
        if k == 'port':
            tmp = tmp + ':' + str(r[k])
            tmpk = 'url'
            tmpval = tmp

        keys = keys + tmpk + ', '
        if type(tmpval) is str:
            values = values + '"' + tmpval + '", '
        else:
            values = values + str(tmpval) + ', '

    keys = keys.rsplit(", ",1)[0]
    values = values.rsplit(", ",1)[0]
    print('({}) ({})'.format(keys,values))
    new_servers_db.insert(keys, values)
    keys = ''
    values = ''
