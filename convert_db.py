#!/usr/bin/env python3

import pprint
from os import sys,path
work_dir = path.dirname(path.abspath(__file__))
sys.path.append(work_dir)

from db import DB
import db_schemas

servers_db = DB('servers')
new_servers_db = DB('servers', 'new_db.sqlite3')
new_servers_db.create(db_schemas.servers_create_statement)
res = servers_db.select('*')
keys = ''
values = ''
for r in res:
    for k in r.keys():
        keys = keys + k + ', '
        if type(r[k]) is str:
            values = values + '"' + r[k] + '", '
        else:
            values = values + str(r[k]) + ', '

    keys = keys.rsplit(", ",1)[0]
    values = values.rsplit(", ",1)[0]
    print('({}) ({})'.format(keys,values))
    new_servers_db.insert(keys, values)
    keys = ''
    values = ''
