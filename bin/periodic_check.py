#!/usr/bin/env python3

import argparse
import logging
from multiprocessing import Pool
import re

from check_certs_lib.check_certs import check_cert
from check_certs_lib.escape_markdown import escape_markdown
from check_certs_lib.db import DB_factory
from check_certs_lib.send_to_chat import send_to_chat

def proc_exec(rt: tuple) -> dict:
    global dry_run
    r = rt[1]
    logging.debug(f'{r["url"]}')
    if r['status'] == 'HOLD':
        logging.debug('Skipped')
        return dict()
    flags = dict()
    flags['quiet'] = True
    flags['print_id'] = True
    flags['warn_before_expired'] = r['warn_before_expired']
    flags['only_one'] = True

    res = dict()
    res['cert_id'] = r['cert_id']
    res['url'] = r['url']
    res['chat_id'] = r['chat_id']
    res['out_text'] = check_cert(r['url'], flags)
    if not dry_run:
        process_results(res)
    return res

def process_results(r: dict):
    global servers_db

    if not r:
        return
    result = r['out_text']
    if type(result) == bytes:
        result = result.decode('utf-8')
    if result[-1:] == '\n':
        result = result[:len(result)-1]
    m = re.search('ID: ([0-9A-Z]+)\n?', result)
    if m == None:
        send_to_chat(r['chat_id'], f'{r["url"]} check certificate error:\n{result}')
        logging.debug(f'Error: |{result}|')
        servers_db.update(f'last_checked=CURRENT_TIMESTAMP, status="{escape_markdown(result)}"', f'url="{r["url"]}" AND chat_id="{r["chat_id"]}"')
        return
    cert_id = m.group(1)
    result = re.sub('ID: ([0-9A-Z]+)\n?', '', result)
    if result != '':
        send_to_chat(r['chat_id'], f'{r["url"]} check certificate error:\n{result}')
        logging.debug(f'Error*: {result}')
        servers_db.update(f'last_checked=CURRENT_TIMESTAMP, status="{escape_markdown(result)}", cert_id="{cert_id}"',  f'url="{r["url"]}" AND chat_id="{r["chat_id"]}"')
    else:
        # It;s a first check or certificate did not changed
        if r['cert_id'] == '0' or cert_id == r['cert_id']:
            result = 'OK'
        else:
            result = 'Certificate was changed'
            send_to_chat(r['chat_id'], f'{r["url"]} check certificate:\n{result}')
        logging.debug(f'{result}')
        servers_db.update(f'last_checked=CURRENT_TIMESTAMP, last_ok=CURRENT_TIMESTAMP, status="{escape_markdown(result)}", cert_id="{cert_id}"',  f'url="{r["url"]}" AND chat_id="{r["chat_id"]}"')

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

    global servers_db
    global dry_run
    dry_run = args.dry_run
    db_factory = DB_factory()
    servers_db = db_factory.get_db('servers')
    res = servers_db.select('*')
    with Pool(processes=args.proc_num) as pool:
        pres = pool.map(proc_exec, enumerate(res))

if __name__ == '__main__':
    main()
