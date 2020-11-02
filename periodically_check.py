#!/usr/bin/env python3

from __future__ import print_function
import argparse
import re
import rpyc
import sqlite3
import subprocess
from os import path

parser = argparse.ArgumentParser()
parser.add_argument('--debug', action='store_true')
args = parser.parse_args()
debug = args.debug

prog_dir = path.dirname(path.abspath(__file__))
con = sqlite3.connect(prog_dir+'/checkcerts.sqlite3')
cur = con.cursor()
cur.execute('SELECT * FROM servers')
for r in cur.fetchall():
    if debug:
        print('%s %s %s' % (r[1], r[2], r[3]))
    old_cert_id = r[8]
    if r[7] == 'HOLD':
        if debug:
            print('Skipped')
        continue
    try:
        result = subprocess.check_output(['/usr/bin/python', prog_dir+'/check_certs.py', '--quiet', '--print-id', '--warn-before-expired', r[5], r[1], r[2], r[3]], stderr=subprocess.STDOUT)
    except:
        result = b''

    m = re.search(b'ID: ([0-9A-Z]+)\n', result)
    if m == None:
        rcon = rpyc.connect('localhost', 18861)
        rcon.root.add_message(r[4], '%s %s %s check certificate error:\n%s' % (r[1], r[2], r[3], result.decode('utf-8')))
        if debug:
            print('%s' % result.decode('utf-8'))
        continue
    cert_id = m.group(1)
    result = re.sub('ID: ([0-9A-Z]+)\n', '', result.decode('utf8'))
    if result[-1:] == '\n':
        result = result[:len(result)-1]
    if result != '':
        cur.execute('UPDATE servers SET last_checked=CURRENT_TIMESTAMP, status=?, cert_id=? WHERE hostname=? AND port=?', (result, cert_id, r[1], r[3]))
        con.commit()
        rcon = rpyc.connect('localhost', 18861)
        rcon.root.add_message(r[4], '%s %s %s check certificate error:\n%s' % (r[1], r[2], r[3], result))
        if debug:
            print('%s' % result)
    else:
        if cert_id == old_cert_id:
            result = 'OK'
        else:
            result = 'Certificate was changed'
        cur.execute('UPDATE servers SET last_checked=CURRENT_TIMESTAMP, status=?, cert_id=?  WHERE hostname=? AND port=?', (result, cert_id, r[1], r[3]))
        con.commit()
        if debug:
            print(result)

con.close()
