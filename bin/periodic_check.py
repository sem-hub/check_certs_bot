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
from check_certs_lib.db import DBfactory
from check_certs_lib.logging_black_white_lists import Blacklist, add_filter_to_all_handlers
from check_certs_lib.send_to_chat import send_to_chats


def check_process_closure(db, dry_run: bool):
    '''A closure to hide arguments. Multiprocess function takes only one.'''
    global helper       # it's a dirty hack to prevent "Can't picle local object"
                        # error in multiprocessing module
    def helper(args: tuple):
        return process_checking(db, dry_run, args)
    return helper

def process_checking(db, dry_run, args: tuple) -> dict:
    '''
    Run all checks via check_certs_lib.check_cert()
    Get: DB handler, dry_run flag, enumerate() tuple
    Return: dict() with cert_id, url, chat_id, count,
                        error, out_text keys.
    '''
    col = args[1]
    logging.debug('%s', col["url"])
    if col['status'] == 'HOLD':
        logging.debug('Skipped')
        return dict()

    res = dict()
    res['cert_id'] = col['cert_id']
    res['url'] = col['url']
    res['chat_id'] = col['chat_id']
    res['count'] = col['count']
    res['error'], res['out_text'] = check_cert(
            col['url'],
            quiet=True,
            print_id=True,
            warn_before_expired=col['warn_before_expired'],
            only_one=True)
    if not dry_run:
        process_results(db, res)
    return res

def process_results(servers_db, res: dict) -> None:
    '''Process results, save it to DB etc.'''
    if not res:
        return
    # we have more than one user for this url
    users = [res['chat_id']]
    if res['count']:
        users = [v['chat_id'] for v in servers_db.select('chat_id', f'url={res["url"]!r}')]
    if res['error']:
        result = res['out_text']+res['error']
    else:
        result = res['out_text']
    if isinstance(result, bytes):
        result = result.decode('utf-8')
    result = result.strip('\n')
    match = re.search('ID: ([0-9A-Z]+)\n?', result)
    if match is None:
        send_to_chats(f'{res["url"]} check certificate error:\n{result}', users)
        logging.debug('Error: |%s|', result)
        servers_db.update(f'last_checked=CURRENT_TIMESTAMP, status={result!r}',
                f'url={res["url"]!r}')
        return
    cert_id = match.group(1)
    result = re.sub('ID: ([0-9A-Z]+)\n?', '', result)
    if result != '':
        send_to_chats(f'{res["url"]} check certificate error:\n{result}', users)
        logging.debug('Error*: %s', result)
        servers_db.update(f'last_checked=CURRENT_TIMESTAMP, status={result!r}, cert_id={cert_id!r}',
                f'url={res["url"]!r}')
    else:
        # It's a first check or certificate did not changed
        if res['cert_id'] == '0' or cert_id == res['cert_id']:
            result = 'OK'
        else:
            result = 'Certificate was changed'
            send_to_chats(f'{res["url"]} check certificate:\n{result}', users)
        logging.debug('%s', result)
        servers_db.update(
                f'last_checked=CURRENT_TIMESTAMP, last_ok=CURRENT_TIMESTAMP, '
                f'status={result!r}, cert_id={cert_id!r}',
                f'url={res["url"]!r}')

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

    db_factory = DBfactory()
    servers_db = db_factory.get_db('servers')
    res = servers_db.select('*, COUNT(url) AS count', 'true GROUP BY url')

    proc_exec = check_process_closure(servers_db, args.dry_run)
    with Pool(processes=args.proc_num) as pool:
        pool.map(proc_exec, enumerate(res))

if __name__ == '__main__':
    main()
