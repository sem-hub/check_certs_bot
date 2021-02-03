#!/usr/bin/env python3

'''
A command line utility to run periodic check for URLs from DB.
It must run with cron(8) for example.
All URLs check paralelly via a pool of process.
You can controll paralelly runned task with an argument.
Use --help to see all options.
'''

import argparse
import logging
from multiprocessing import Pool
import re

from check_certs_lib.check_certs import check_cert
from check_certs_lib.db import DB_factory
from check_certs_lib.logging_black_white_lists import Blacklist, add_filter_to_all_handlers
from check_certs_lib.send_to_chat import send_to_chats


def check_process_closure(db, dry_run: bool):
    '''A closure to hide arguments. Multiprocess function takes only one.'''
    global helper       # it's a dirty hack to prevent "Can't picle local object" error in multiprocessing module
    def helper(fields: tuple):
        return process_checking(db, dry_run, fields)
    return helper

def process_checking(db, dry_run, rt: tuple) -> dict:
    '''Run all checks via check_certs_lib.check_cert()'''
    r = rt[1]
    logging.debug(f'{r["url"]}')
    if r['status'] == 'HOLD':
        logging.debug('Skipped')
        return dict()

    res = dict()
    res['cert_id'] = r['cert_id']
    res['url'] = r['url']
    res['chat_id'] = r['chat_id']
    res['count'] = r['count']
    res['error'], res['out_text'] = check_cert(
            r['url'],
            quiet=True,
            print_id=True,
            warn_before_expired=r['warn_before_expired'],
            only_one=True)
    if not dry_run:
        process_results(db, res)
    return res

def process_results(servers_db, r: dict) -> None:
    '''Process results, save it to DB etc.'''
    if not r:
        return
    # we have more than one user for this url
    users = [r['chat_id']]
    if r['count']:
        users = [v['chat_id'] for v in servers_db.select('chat_id', f'url={r["url"]!r}')]
    if r['error']:
        result = r['out_text']+r['error']
    else:
        result = r['out_text']
    if type(result) == bytes:
        result = result.decode('utf-8')
    result = result.strip('\n')
    m = re.search('ID: ([0-9A-Z]+)\n?', result)
    if m is None:
        send_to_chats(f'{r["url"]} check certificate error:\n{result}', users)
        logging.debug(f'Error: |{result}|')
        servers_db.update(f'last_checked=CURRENT_TIMESTAMP, status={result!r}', f'url={r["url"]!r}')
        return
    cert_id = m.group(1)
    result = re.sub('ID: ([0-9A-Z]+)\n?', '', result)
    if result != '':
        send_to_chats(f'{r["url"]} check certificate error:\n{result}', users)
        logging.debug(f'Error*: {result}')
        servers_db.update(f'last_checked=CURRENT_TIMESTAMP, status={result!r}, cert_id={cert_id!r}',
                f'url={r["url"]!r}')
    else:
        # It's a first check or certificate did not changed
        if r['cert_id'] == '0' or cert_id == r['cert_id']:
            result = 'OK'
        else:
            result = 'Certificate was changed'
            send_to_chats(f'{r["url"]} check certificate:\n{result}', users)
        logging.debug(f'{result}')
        servers_db.update(
                f'last_checked=CURRENT_TIMESTAMP, last_ok=CURRENT_TIMESTAMP, status={result!r}, cert_id={cert_id!r}',
                f'url={r["url"]!r}')

def main():
    '''Main function'''
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--proc-num', nargs='?', type=int, default=5,
            help='run simultaneous processes')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
        add_filter_to_all_handlers(Blacklist('urllib3'))
    else:
        logging.basicConfig(level=logging.INFO)

    db_factory = DB_factory()
    servers_db = db_factory.get_db('servers')
    res = servers_db.select('*, COUNT(url) AS count', 'true GROUP BY url')

    proc_exec = check_process_closure(servers_db, args.dry_run)
    with Pool(processes=args.proc_num) as pool:
        pool.map(proc_exec, enumerate(res))

if __name__ == '__main__':
    main()
