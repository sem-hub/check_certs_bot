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
from db import DB_factory
from send_to_chat import send_to_chat

def proc_exec(rt: tuple) -> dict:
    r = rt[1]
    logging.debug(f'{r["url"]}')
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
    res['url'] = r['url']
    res['chat_id'] = r['chat_id']
    res['out_text'] = check_cert(r['url'], flags)
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
    db_factory = DB_factory()
    servers_db = db_factory.get_db('servers')
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
            send_to_chat(r['chat_id'], f'{r["url"]} check certificate error:\n{result}')
            logging.debug(f'Error: |{result}|')
            servers_db.update(f'last_checked=CURRENT_TIMESTAMP, status="{escape_markdown(result)}"', f'url="{r["url"]}"')
            continue
        cert_id = m.group(1)
        result = re.sub('ID: ([0-9A-Z]+)\n?', '', result)
        if result != '':
            send_to_chat(r['chat_id'], f'{r["url"]} check certificate error:\n{result}')
            logging.debug(f'Error*: {result}')
            servers_db.update(f'last_checked=CURRENT_TIMESTAMP, status="{escape_markdown(result)}", cert_id="{cert_id}"',  f'url="{r["url"]}"')
        else:
            if cert_id == r['cert_id']:
                result = 'OK'
            else:
                result = 'Certificate was changed'
            logging.debug(f'{result}')
            servers_db.update(f'last_checked=CURRENT_TIMESTAMP, last_ok=CURRENT_TIMESTAMP, status="{escape_markdown(result)}", cert_id="{cert_id}"',  f'url="{r["url"]}"')

if __name__ == '__main__':
    main()
