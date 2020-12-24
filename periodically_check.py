#!/usr/bin/env python3

import argparse
import logging
from multiprocessing import Pool
from os import sys, path
import re

work_dir = path.dirname(path.abspath(__file__))
sys.path.append(work_dir)

from check_certs import check_cert
from escape_markdown import escape_markdown
from db import DB
from send_to_chat import send_to_chat

def proc_exec(rt: tuple) -> dict:
    r = rt[1]
    logging.debug(f'{r["hostname"]} {r["proto"]} {r["port"]}')
    if r['status'] == 'HOLD':
        logging.debug('Skipped')
        return dict()
    flags = dict()
    flags['quiet'] = True
    flags['print_id'] = True
    flags['warn_before_expired'] = r['warn_before_expired']
    flags['only_ipv4'] = False
    flags['only_ipv6'] = False
    flags['only_one'] = True

    res = dict()
    res['cert_id'] = r['cert_id']
    res['hostname'] = r['hostname']
    res['proto'] = r['proto']
    res['port'] = r['port']
    res['chat_id'] = r['chat_id']
    res['out_text'] = check_cert(r['hostname'], r['port'], r['proto'], flags)
    return res

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--proc-num', nargs='?', type=int, default=5, help='run simultaneous processes')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(format='%(levelname)s:*** %(message)s', level=logging.DEBUG)
    else:
        logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)

    proc_num = args.proc_num
    servers_db = DB('servers')
    res = servers_db.select('*')
    with Pool(processes=proc_num) as pool:
        pres = pool.map(proc_exec, enumerate(res))
    for r in pres:
        if args.dry_run or not r:
            continue
        result = r['out_text']
        if type(result) == bytes:
            result = result.decode('utf-8')
        if result[-1:] == '\n':
            result = result[:len(result)-1]
        m = re.search('ID: ([0-9A-Z]+)\n?', result)
        if m == None:
            send_to_chat(r['chat_id'], f'{r["hostname"]} {r["proto"]} {r["port"]} check certificate error:\n{result}')
            logging.debug(f'Error: |{result}|')
            servers_db.update(f'last_checked=CURRENT_TIMESTAMP, status="{escape_markdown(result)}"', f'hostname="{r["hostname"]}" AND port="{r["port"]}"')
            continue
        cert_id = m.group(1)
        result = re.sub('ID: ([0-9A-Z]+)\n?', '', result)
        if result != '':
            servers_db.update(f'last_checked=CURRENT_TIMESTAMP, status="{result}", cert_id="{cert_id}"', f'hostname="{r["hostname"]}" AND port="{r["port"]}"')
            send_to_chat(r['chat_id'], f'{r["hostname"]} {r["proto"]} {r["port"]} check certificate error:\n{result}')
            logging.debug(f'Error*: {result}')
        else:
            if cert_id == r['cert_id']:
                result = 'OK'
            else:
                result = 'Certificate was changed'
            servers_db.update(f'last_checked=CURRENT_TIMESTAMP, status="{result}", cert_id="{cert_id}"',  f'hostname="{r["hostname"]}" AND port="{r["port"]}"')
            logging.debug(f'{result}')

if __name__ == '__main__':
    main()
