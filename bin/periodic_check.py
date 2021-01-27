#!/usr/bin/env python3

import argparse
import logging
from multiprocessing import Pool
import re
from typing import NoReturn

from check_certs_lib.check_certs import check_cert
from check_certs_lib.db import DB_factory
from check_certs_lib.logging_black_white_lists import Blacklist, add_filter_to_all_handlers
from check_certs_lib.send_to_chat import send_to_chat

def proc_exec(rt: tuple) -> dict:
    global dry_run
    r = rt[1]
    logging.debug(f'{r["url"]}')
    if r['status'] == 'HOLD':
        logging.debug('Skipped')
        return dict()

    res = dict()
    res['cert_id'] = r['cert_id']
    res['url'] = r['url']
    res['chat_id'] = r['chat_id']
    res['out_text'] = check_cert(r['url'], quiet=True, print_id=True, warn_before_expired=r['warn_before_expired'], only_one=True)
    if not dry_run:
        process_results(res)
    return res

def process_results(r: dict) -> NoReturn:
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
        servers_db.update(f'last_checked=CURRENT_TIMESTAMP, status={result!r}', f'url={r["url"]!r} AND chat_id={r["chat_id"]!r}')
        return
    cert_id = m.group(1)
    result = re.sub('ID: ([0-9A-Z]+)\n?', '', result)
    if result != '':
        send_to_chat(r['chat_id'], f'{r["url"]} check certificate error:\n{result}')
        logging.debug(f'Error*: {result}')
        servers_db.update(f'last_checked=CURRENT_TIMESTAMP, status={result!r}, cert_id={cert_id!r}',  f'url={r["url"]!r} AND chat_id={r["chat_id"]!r}')
    else:
        # It;s a first check or certificate did not changed
        if r['cert_id'] == '0' or cert_id == r['cert_id']:
            result = 'OK'
        else:
            result = 'Certificate was changed'
            send_to_chat(r['chat_id'], f'{r["url"]} check certificate:\n{result}')
        logging.debug(f'{result}')
        servers_db.update(f'last_checked=CURRENT_TIMESTAMP, last_ok=CURRENT_TIMESTAMP, status={result!r}, cert_id={cert_id!r}',  f'url={r["url"]!r} AND chat_id={r["chat_id"]!r}')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--proc-num', nargs='?', type=int, default=5, help='run simultaneous processes')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
        add_filter_to_all_handlers(Blacklist('urllib3'))
    else:
        logging.basicConfig(level=logging.INFO)

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
