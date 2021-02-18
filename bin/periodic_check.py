#!/usr/bin/env python3

'''
A command line utility to run periodic check for URLs from DB.
It must run with cron(8) for example.
All URLs check paralelly via a pool of process.
You can controll paralelly runned task with an argument.
Use --help to see all options.
'''

import argparse
from collections import namedtuple
import configparser
from datetime import datetime
import logging
from multiprocessing import Pool
import re
import sys

from sqlalchemy import func

from check_certs_lib.check_certs import check_cert
from check_certs_lib.db_model import DB, Servers
from check_certs_lib.logging_black_white_lists import (
        Blacklist, add_filter_to_all_handlers)
from check_certs_lib.send_to_chat import send_to_chats


Server = namedtuple('Server',
        ['count', 'url', 'cert_id', 'warn_before_expired', 'status'])

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
    if col.status == 'HOLD':
        logging.debug('%s Skipped', col.url)
        return dict()

    res = dict()
    res['cert_id'] = col.cert_id
    res['url'] = col.url
    res['count'] = col.count
    logging.debug('%s CHECK STARTED', col.url)
    res['error'], res['out_text'] = check_cert(
            col.url,
            print_id=True,
            warn_before_expired=col.warn_before_expired,
            only_ipv4=True,
            only_one=True)
    logging.debug('%s CHECK FINISHED', col.url)
    if not dry_run:
        process_results(db, res)
    return res

def process_results(db, res: dict) -> None:
    '''Process results, save it to DB etc.'''
    if not res:
        return
    logging.debug('Processing results for %s', res['url'])
    # we have more than one user for this url
    message = ''
    session = db.get_session()
    query = session.query(Servers).filter(Servers.url==res['url'])
    users = [v.chat_id for v in query.all()]
    result = res['out_text'].strip('\n')
    match = re.search('ID: ([0-9A-Z]+)\n?', result)
    # We did not get certificat ID. It means we don't have certificate
    # and have an error on communication process.
    if match is None:
        message = f'{res["url"]} check certificate error:\n{res["error"]}'
        logging.debug('Error: |%s|', res['error'])
        query.update({Servers.last_checked: datetime.utcnow(),
            Servers.status: res['error']})
    else:
        cert_id = match.group(1)
        result = re.sub('ID: ([0-9A-Z]+)\n?', '', result)
        # We have an error in certificate
        if res['error'] != '':
            message = f'{res["url"]} check certificate error:\n{res["error"]}'
            logging.debug('Error*: %s', res['error'])
            query.update({Servers.last_checked: datetime.utcnow(),
                Servers.status: res['error'], Servers.cert_id: cert_id})
        else:
            # It's a first check or certificate did not changed
            if res['cert_id'] == '' or cert_id == res['cert_id']:
                result = 'OK'
            else:
                result = 'Certificate was changed'
                message = f'{res["url"]} check certificate:\n{result}'
            logging.debug('%s', result)
            query.update({Servers.last_checked: datetime.utcnow(),
                Servers.last_ok: datetime.utcnow(),
                Servers.status: result, Servers.cert_id: cert_id})

    session.commit()
    session.close()
    if message:
        send_to_chats(message, users)

def main():
    '''Main function'''
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-c', '--conf', type=str,
            help='Config file from check_cert_bot.py for taking DB URL')
    group.add_argument('-d', '--db', type=str,
            help='URL for DB location')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--proc-num', nargs='?', type=int, default=5,
            help='run simultaneous processes')
    args = parser.parse_args()

    db_url = ''
    if args.db is None:
        config = configparser.ConfigParser()
        if config.read(args.conf) == []:
            logging.error('Can\'t read config file: %s', args.conf)
            sys.exit(1)

        try:
            db_url = config['DB']['url']
        except KeyError:
            logging.error('You must specify DB URL in config file')
            sys.exit(1)
    else:
        db_url = args.db

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
        add_filter_to_all_handlers(Blacklist('urllib3'))
        #logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)
    else:
        logging.basicConfig(level=logging.INFO)

    db = DB(db_url)
    session = db.get_session()
    rows = session.query(func.count(Servers.url), Servers).group_by(Servers.url
                                                                        ).all()
    res_list = []
    for res in rows:
        server = Server(res[0], res[1].url, res[1].cert_id,
                res[1].warn_before_expired, res[1].status)
        res_list.append(server)
    session.close()

    proc_exec = check_process_closure(db, args.dry_run)
    with Pool(processes=args.proc_num) as pool:
        pool.map(proc_exec, enumerate(res_list))

if __name__ == '__main__':
    main()
