#!/usr/bin/env python3

import argparse
import logging
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
parser.add_argument('--dry-run', action='store_true')
args = parser.parse_args()

if args.debug:
  logging.basicConfig(format='%(levelname)s:*** %(message)s', level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO)

prog_dir = path.dirname(path.abspath(__file__))
con = sqlite3.connect(prog_dir+'/checkcerts.sqlite3')
cur = con.cursor()
cur.execute('SELECT * FROM servers')
for r in cur.fetchall():
    logging.debug(f'{r[1]} {r[2]} {r[3]}')
    old_cert_id = r[8]
    if r[7] == 'HOLD':
        logging.debug('Skipped')
        continue
    result = ''
    logging.debug('Command to run:\n%s %s %s %s %s %s %s %s %s' % ('/usr/bin/python3', prog_dir+'/check_certs.py', '--quiet', '--print-id', '--warn-before-expired', r[5], r[1], r[2], r[3]))
    try:
        result = subprocess.check_output(['/usr/bin/python3', prog_dir+'/check_certs.py', '--quiet', '--print-id', '--warn-before-expired', r[5], r[1], r[2], r[3]], stderr=subprocess.STDOUT)
    except:
        result = 'Check command failure'
        logging.debug(f'subprocess failure: {sys.exc_info()[1]}')

    if args.dry_run:
        continue
    if type(result) == bytes:
        result = result.decode('utf-8')
    if result[-1:] == '\n':
        result = result[:len(result)-1]
    m = re.search('ID: ([0-9A-Z]+)\n?', result)
    if m == None:
        rcon = rpyc.connect('localhost', 18861)
        rcon.root.add_message(r[4], '%s %s %s check certificate error:\n%s' % (r[1], r[2], r[3], result))
        logging.debug(f'Error: |{result}|')
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
        logging.debug(f'Error*: {result}')
    else:
        if cert_id == old_cert_id:
            result = 'OK'
        else:
            result = 'Certificate was changed'
        cur.execute('UPDATE servers SET last_checked=CURRENT_TIMESTAMP, status=?, cert_id=?  WHERE hostname=? AND port=?', (result, cert_id, r[1], r[3]))
        con.commit()
        logging.debug(f'{result}')

con.close()
