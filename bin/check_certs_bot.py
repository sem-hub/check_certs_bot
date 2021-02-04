#!/usr/bin/env python3

'''
Telegram Bot to check X509 certificates from sites.
Checking command line is a URL-like string: [proto://]server[:port]
Any protocols are allowed. If no proto specified, HTTPS is assumed.
If no port specified it will be got from /etc/services file.
For some protocols send extra commands like 'EHLO/STARTTLS' for SMTP.

You can add URLs to Bot's DB to run checks latter with periodic_check.py
utility.
The bot supports this commands:
    /help, /start - getting help.
    URL - check this URL.
    /add - add an URl in database for periodic checks.
    /remove - remove the URL from database.
    /list - get list all records for this user.
    /reset - to remove all records for this user.
    /hold, /unhold - stop/restore checks for this URL.
    /id - show user's ID.

An user can see only URLs he added.
The bot saves all user activity. It checks for flood and block them.
An administrator can mark user as banned and all commands will be
rejected for him.
'''

import argparse
import datetime
import logging
from multiprocessing import Process
import queue
import threading
from typing import Tuple, NoReturn

import rpyc
from rpyc.utils.server import ThreadedServer
import telegram
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters

from check_certs_lib.check_certs import check_cert
from check_certs_lib.check_validity import parse_and_check_url
from check_certs_lib.db import DBfactory
import check_certs_lib.db_schemas as db_schemas


TOKEN_FILE = '/var/spool/check_certs/TOKEN'

remote_messages: queue.Queue = queue.Queue()

HELP_TEXT='''
A bot for checking HTTP servers certificates.

Enter:
    \\[_protocol_://]_hostname_\\[:_port_] \\[no-tlsa] \\[no-ocsp]
Default protocol and port is https(443)
no-tlsa, no-ocsp flags dissallow TLSA, OCSP checks correspondly.
Example:
    *www.google.ru* will check *https://www.google.ru:443*

or a command:
/help   - show this help message.
/list \\[short]  - list server names for periodic checking.
/add \\[_protocol_://]_hostname_\\[:_port_] \\[_days_]   - add a server to periodical checking.
                        _days_ - warn if days till certificate expire will happen.
/hold \\[_protocol_://]_hostname_\\[_:port_]  - temporary stop checking this entry
/unhold \\[_protocol_://]_hostname_\\[_:port_]  - continue checking this entry
/remove \\[_protocol_://]hostname\\[:_port_] - remove a server from periodical checking list.
/reset  - reset all periodical checking list.

Allowed protocols from /etc/services
For *smtp*, *smtps* and *submission* protocols you can specify domain name not FQDN. It will be
checked for MX DNS records first.
For *smtp* protocol EHLO/STARTTLS commands will be send first to start TLS/SSL session.
'''

def parse_url(url_str: str) -> Tuple[str, str]:
    '''
    Parse and check URL.
    Return: tuple(error, result)
    '''
    url = url_str.strip().lower().encode('ASCII', 'replace').decode('utf-8')

    if '://' not in url:
        url = 'https://' + url
    err, (scheme, hostname, port) = parse_and_check_url(url)
    return (err, f'{scheme}://{hostname}:{port}')

def send_message_to_user(bot, **kwargs) -> None:
    '''
    Send message to user's chat.
    Catch exceptions on error and repeat 5 times - very often Telegram drops
    errors.
    '''
    success = False
    attemps = 0
    while not success and attemps < 5:
        try:
            bot.send_message(**kwargs)
            success = True
        except Exception as err:
            logging.error(str(err))
        attemps += 1

def send_long_message(bot, chat_id, text: str) -> None:
    '''
    Split long text and send it as separated messages.
    '''
    max_len = telegram.constants.MAX_MESSAGE_LENGTH
    for i in range(0, len(text), max_len):
        send_message_to_user(bot, chat_id=chat_id, parse_mode='HTML',
                disable_web_page_preview=1,
                text=text[i:i+max_len])

class RPyCService(rpyc.Service):
    '''RPYC service to get messages for an user. Using in periodic_check.py'''
    def exposed_add_message(self, chat_id, msg) -> None:
        '''RPC function'''
        remote_messages.put([chat_id, msg])

def check_queue(context) -> None:
    '''Check queue with messages for users got from RPYC.'''
    while not remote_messages.empty():
        chat_id, msg = remote_messages.get()
        send_message_to_user(context.bot, chat_id=chat_id, disable_web_page_preview=1, text=msg)
        remote_messages.task_done()

class CheckCertBot:
    '''Main class for the bot'''
    def __init__(self, bot_token):
        self.updater = Updater(token=bot_token)

        dispatcher = self.updater.dispatcher

        job_queue = self.updater.job_queue

        # register commands handlers
        start_cmd_handler = CommandHandler('start', self.help_cmd)
        dispatcher.add_handler(start_cmd_handler)
        start_cmd_handler = CommandHandler('help', self.help_cmd)
        dispatcher.add_handler(start_cmd_handler)
        id_cmd_handler = CommandHandler('id', self.id_cmd)
        dispatcher.add_handler(id_cmd_handler)
        list_cmd_handler = CommandHandler('list', self.list_cmd, pass_args=True)
        dispatcher.add_handler(list_cmd_handler)
        add_cmd_handler = CommandHandler('add', self.add_cmd, pass_args=True)
        dispatcher.add_handler(add_cmd_handler)
        hold_cmd_handler = CommandHandler('hold', self.hold_cmd, pass_args=True)
        dispatcher.add_handler(hold_cmd_handler)
        unhold_cmd_handler = CommandHandler('unhold', self.unhold_cmd, pass_args=True)
        dispatcher.add_handler(unhold_cmd_handler)
        remove_cmd_handler = CommandHandler('remove', self.remove_cmd, pass_args=True)
        dispatcher.add_handler(remove_cmd_handler)
        reset_cmd_handler = CommandHandler('reset', self.reset_cmd)
        dispatcher.add_handler(reset_cmd_handler)

        unknown_cmd_handler = MessageHandler(Filters.command, self.unknown_cmd)
        dispatcher.add_handler(unknown_cmd_handler)

        # Message Filter
        message_filter_handler = MessageHandler(Filters.text, self.message)
        dispatcher.add_handler(message_filter_handler)

        # Run job every 10 seconds
        job_queue.run_repeating(check_queue, interval=10, first=10)

        self.db_factory = DBfactory()
        self.servers_db = self.db_factory.get_db('servers')
        self.servers_db.create(db_schemas.servers_create_statement)
        self.users_db = self.db_factory.get_db('users')
        self.users_db.create(db_schemas.users_create_statement)
        self.activity_db = self.db_factory.get_db('activity')
        self.activity_db.create(db_schemas.activity_create_statement)

    def user_access(self, cmd, message) -> bool:
        '''Check user access'''
        res = self.users_db.select('*', f'id={message.chat_id}')
        # A new user
        if len(res) == 0:
            self.users_db.insert(
                    'id, name, full_name, language_code, first_met, last_activity',
                    f'"{message.chat_id}", "{message.chat.username}", '
                    f'"{message.chat.first_name} {message.chat.last_name}", '
                    f'"{message.from_user.language_code}", '
                    'CURRENT_TIMESTAMP, CURRENT_TIMESTAMP')
        else:
            if res[0]['status'] == 'ban':
                logging.warning('banned: %s. %s.', message.chat_id, cmd)
                return False

            # Check for flooding
            rows = self.activity_db.select('*',
                    f'user_id={message.chat_id!r} and '
                    f'date={datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")!r}')
            # Flood protect
            if len(rows) > 0:
                self.activity_db.insert('user_id, cmd, date',
                        f'{message.chat_id!r}, {"!"+cmd!r}, CURRENT_TIMESTAMP')
                logging.warning('Flood activity: %s - %d times per seconds. Blocked.',
                                        message.chat_id, len(rows))
                return False
            self.users_db.update('last_activity=CURRENT_TIMESTAMP',
                                 f'id={message.chat_id!r}')
        # Write his activity
        self.activity_db.insert('user_id, cmd, date',
                f'{message.chat_id!r}, {cmd!r}, CURRENT_TIMESTAMP')
        return True

    def start(self) -> None:
        '''Start a bot updater'''
        self.updater.start_polling()
        self.updater.idle()

    def help_cmd(self, update, context) -> None:
        '''Process /help command'''
        if not self.user_access('/help', update.message):
            send_message_to_user(context.bot,
                    chat_id=update.message.chat_id,
                    text='You are banned')
            return

        # Remove ReplyKeyboard if it was there
        #reply_markup = telegram.ReplyKeyboardRemove(remove_keyboard=True)
        #old_message = context.bot.send_message(chat_id=update.message.chat_id,
        #       text='trying', reply_markup=reply_markup,
        #       reply_to_message_id=update.message.message_id)
        send_message_to_user(context.bot, chat_id=update.message.chat_id,
                                    parse_mode='Markdown', text=HELP_TEXT)

    def id_cmd(self, update, context) -> None:
        '''Process /id command'''
        if not self.user_access('/id', update.message):
            send_message_to_user(context.bot, chat_id=update.message.chat_id,
                    text='You are banned')
            return
        text = (f'{update.message.chat_id}: {update.message.chat.username} '
                f'{update.message.chat.first_name} {update.message.chat.last_name} '
                f'{update.message.from_user.language_code}')
        send_message_to_user(context.bot, chat_id=update.message.chat_id, text=text)

    def list_cmd(self, update, context) -> None:
        '''Process /list command'''
        args = context.args
        if not self.user_access(f'/list {args}', update.message):
            return
        res = list()
        short = False
        if len(args) > 0 and args[0] == 'short':
            short = True
        if short:
            res = self.servers_db.select(
                    'url, datetime(last_checked, "localtime") as last_checked, status',
                    f'chat_id="{str(update.message.chat_id)}"')
        else:
            res = self.servers_db.select(
                    'datetime(when_added, "localtime") as when_added, url, '
                    'warn_before_expired, '
                    'datetime(last_checked, "localtime") as last_checked, status',
                    f'chat_id="{str(update.message.chat_id)}"')

        output = list()
        if len(res) == 0:
            output = ['Empty']
        else:
            line = '|'.join([str(elem) for elem in res[0].keys()])
            output.append('<b>' + line + '</b>')

        for row in res:
            line = '|'.join([str(elem) for elem in row.values()])
            # Strip start/stop tag characters
            line = line.replace('<', '').replace('>', '')
            output.append(line)

        send_long_message(context.bot, update.message.chat_id, '\n'.join(output))

    def add_cmd(self, update, context) -> None:
        '''Process /add command'''
        args = context.args
        if not self.user_access(f'/add {args}', update.message):
            return
        if len(args) < 1:
            send_message_to_user(context.bot, chat_id=update.message.chat_id,
                                        text='Use /add URL [days]')
            return
        error, url = parse_url(args[0])
        if error != '':
            send_message_to_user(context.bot, chat_id=update.message.chat_id,
                                        disable_web_page_preview=1,
                                        text=f'Parsing error: {error}')
            return
        # Default days to warn
        days = 5
        if len(args) > 1:
            if args[1].isdigit():
                days = int(args[1])
            else:
                send_message_to_user(context.bot, chat_id=update.message.chat_id,
                                            text='days must be integer')
                return
        # Check for duplicates
        res = self.servers_db.select('url',
                f'url="{url}" AND chat_id="{str(update.message.chat_id)}"')
        if len(res) > 0:
            send_message_to_user(context.bot, chat_id=update.message.chat_id,
                    disable_web_page_preview=1, text=f'{url} already exists')
            return
        # datetime('Never', 'localtime') == NoneType. So I use 0000-01-01 00:00:00 as 'never' value.
        self.servers_db.insert(
                'when_added, url, chat_id, warn_before_expired, last_checked, '
                'last_ok, status, cert_id',
                f'CURRENT_TIMESTAMP, "{url}", "{str(update.message.chat_id)}", '
                f'"{days}", "0000-01-01 00:00:00", "0000-01-01 00:00:00", "", "0"')
        send_message_to_user(context.bot, chat_id=update.message.chat_id,
                                    disable_web_page_preview=1,
                                    text=f'Successfully added: {url}')

    def hold_cmd(self, update, context) -> None:
        '''Process /hold command'''
        args = context.args
        if not self.user_access(f'/hold {args}', update.message):
            return
        if len(args) < 1:
            send_message_to_user(context.bot, chat_id=update.message.chat_id,
                                 text='Use /hold URL')
            return
        error, url = parse_url(args[0])
        if error != '':
            send_message_to_user(context.bot, chat_id=update.message.chat_id,
                                        disable_web_page_preview=1,
                                        text=f'Parsing error: {error}')
            return
        self.servers_db.update('status="HOLD"',
                f'url="{url}" and chat_id="{str(update.message.chat_id)}"')
        send_message_to_user(context.bot, chat_id=update.message.chat_id,
                                    disable_web_page_preview=1,
                                    text=f'Hold checking for: {url}')

    def unhold_cmd(self, update, context) -> None:
        '''Process /unhold command'''
        args = context.args
        if not self.user_access(f'/unhold {args}', update.message):
            return
        if len(args) < 1:
            send_message_to_user(context.bot, chat_id=update.message.chat_id,
                                        text='Use /unhold URL')
            return
        (error, url) = parse_url(args[0])
        if error != '':
            send_message_to_user(context.bot, chat_id=update.message.chat_id,
                                        disable_web_page_preview=1,
                                        text=f'Parsing error: {error}')
            return
        self.servers_db.update('status="None"',
                            f'url="{url}" and chat_id="{str(update.message.chat_id)}"')
        send_message_to_user(context.bot, chat_id=update.message.chat_id,
                                    disable_web_page_preview=1,
                                    text=f'Unhold checking for: {url}')

    def remove_cmd(self, update, context) -> None:
        '''Process /remove command'''
        args = context.args
        if not self.user_access(f'/remove {args}', update.message):
            return
        if len(args) < 1:
            send_message_to_user(context.bot, chat_id=update.message.chat_id,
                                        text='Use /remove URL')
            return
        error, url = parse_url(args[0])
        if error != '':
            send_message_to_user(context.bot, chat_id=update.message.chat_id,
                                        disable_web_page_preview=1,
                                        text=f'Parsing error: {error}')
            return
        self.servers_db.delete(
                f'url="{url}" and chat_id="{str(update.message.chat_id)}"')
        send_message_to_user(context.bot, chat_id=update.message.chat_id,
                                    disable_web_page_preview=1,
                                    text=f'Successfully removed: {url}')

    def reset_cmd(self, update, context) -> None:
        '''Process /reset command'''
        if not self.user_access('/reset', update.message):
            return
        self.servers_db.delete(f'chat_id="{str(update.message.chat_id)}"')
        send_message_to_user(context.bot, chat_id=update.message.chat_id,
                                    text='Successfully reseted')

    def unknown_cmd(self, update, context) -> None:
        '''Process user errors in command'''
        if not self.user_access('unknown', update.message):
            return
        send_message_to_user(context.bot, chat_id=update.message.chat_id,
                                    text='Unknown command. Try /help.')

    def message(self, update, context) -> None:
        '''Process not command message from the user'''
        allowed_cmd = ('no-tlsa', 'no-ocsp')
        if not self.user_access(update.message.text, update.message):
            return
        url_text, *args = update.message.text.split(' ')
        error, url = parse_url(url_text)
        if error != '':
            send_message_to_user(context.bot, chat_id=update.message.chat_id,
                                        disable_web_page_preview=1, text=error)
            return
        if len(args) > 0 and (len(args) > 2 or len(set(args)-set(allowed_cmd)) > 0):
            send_message_to_user(context.bot, chat_id=update.message.chat_id,
                                        text='wrong arguments')
            return

        # we need no_tlsa style flags. Convert it from no-tlsa.
        args = [a.replace('-', '_') for a in args]
        send_message_to_user(context.bot, chat_id=update.message.chat_id,
                                    disable_web_page_preview=1,
                                    text=f'Checking certificate for: {url}')
        proc = Process(target=async_run_func, args=(context.bot,
                                                     update.message.chat_id,
                                                     self.servers_db,
                                                     url,
                                                     *args))
        proc.start()

def async_run_func(bot, chat_id, db, url, *args) -> None:
    '''Run checks for the URL as an async job'''
    kwargs = {v: True for (_, v) in enumerate(args)}
    error, result = check_cert(url, need_markup=True, **kwargs)
    send_long_message(bot, chat_id, result+error)
    # Write result to DB if we have an entry. Don't use chat_id here, update for all users if have.
    res = db.select('*', f'url={url!r}')
    if len(res) > 0:
        if error:
            db.update(f'last_checked=CURRENT_TIMESTAMP, status={error!r}',
                    f'url={url!r} AND chat_id={chat_id!r}')
        else:
            db.update('last_checked=CURRENT_TIMESTAMP, last_ok=CURRENT_TIMESTAMP, status="OK"',
                    f'url={url!r} AND chat_id={chat_id!r}')

def main() -> NoReturn:
    '''Main function'''
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                level=logging.DEBUG)
    else:
        logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                level=logging.WARNING)

    rpyc_log = logging.getLogger('RPYC')
    rpyc_log.setLevel(logging.ERROR)
    rpyc_server = ThreadedServer(RPyCService, port=18861, logger=rpyc_log)
    thr = threading.Thread(target = rpyc_server.start)
    thr.daemon = True
    thr.start()

    token = open(TOKEN_FILE, 'r').read().rstrip('\n')
    bot = CheckCertBot(token)
    bot.start()

if __name__ == '__main__':
    main()
