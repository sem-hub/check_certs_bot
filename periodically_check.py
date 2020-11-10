#!/usr/bin/env python3

import argparse
import re
import rpyc
import sqlite3
import subprocess
import sys
from os import sys, path

work_dir = path.dirname(path.abspath(__file__))
sys.path.append(work_dir)

from escape_markdown import escape_markdown

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
        print('*** %s %s %s' % (r[1], r[2], r[3]))
    old_cert_id = r[8]
    if r[7] == 'HOLD':
        if debug:
            print('*** Skipped')
        continue
    result = ''
    if debug:
        print('***Command to run:\n%s %s %s %s %s %s %s %s %s' % ('/usr/bin/python3', prog_dir+'/check_certs.py', '--quiet', '--print-id', '--warn-before-expired', r[5], r[1], r[2], r[3]))
    try:
        result = subprocess.check_output(['/usr/bin/python3', prog_dir+'/check_certs.py', '--quiet', '--print-id', '--warn-before-expired', r[5], r[1], r[2], r[3]], stderr=subprocess.STDOUT)
    except:
        result = 'Check command failure'
        if debug:
            print('***subprocess failure: %s' % sys.exc_info()[0])

    if type(result) == bytes:
        result = result.decode('utf-8')
    if result[-1:] == '\n':
        result = result[:len(result)-1]
    m = re.search('ID: ([0-9A-Z]+)\n?', result)
    if m == None:
        rcon = rpyc.connect('localhost', 18861)
        rcon.root.add_message(r[4], '%s %s %s check certificate error:\n%s' % (r[1], r[2], r[3], result))
        if debug:
            print('***Error: |%s|' % result)
        cur.execute('UPDATE servers SET last_checked=CURRENT_TIMESTAMP, status=? WHERE hostname=? AND port=?', (escape_markdown(result), r[1], r[3]))
        con.commit()
        continue
    cert_id = m.group(1)
    result = re.sub('ID: ([0-9A-Z]+)\n?', '', result)
    if result != '':
        cur.execute('UPDATE servers SET last_checked=CURRENT_TIMESTAMP, status=?, cert_id=? WHERE hostname=? AND port=?', (result, cert_id, r[1], r[3]))
        con.commit()
        rcon = rpyc.connect('localhost', 18861)
        rcon.root.add_message(r[4], '%s %s %s check certificate error:\n%s' % (r[1], r[2], r[3], result))
        if debug:
            print('***Error*: %s' % result)
    else:
        if cert_id == old_cert_id:
            result = 'OK'
        else:
            result = 'Certificate was changed'
        cur.execute('UPDATE servers SET last_checked=CURRENT_TIMESTAMP, status=?, cert_id=?  WHERE hostname=? AND port=?', (result, cert_id, r[1], r[3]))
        con.commit()
        if debug:
            print('***%s' % result)

con.close()
