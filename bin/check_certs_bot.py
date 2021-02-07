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
    /timezone - set users' timezone.
    /id - show user's ID.

An user can see only URLs he added.
The bot saves all user activity. It checks for flood and block them.
An administrator can mark user as banned and all commands will be
rejected for him.
'''

import argparse
import configparser
from datetime import datetime
import logging
from multiprocessing import Process
import queue
import re
import sys
import threading
from typing import Tuple, NoReturn

import rpyc
from rpyc.utils.server import ThreadedServer
import telegram
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters

from check_certs_lib.cert_to_text import datetime_to_user_tz_str
from check_certs_lib.check_certs import check_cert
from check_certs_lib.check_validity import parse_and_check_url
from check_certs_lib.db_model import Servers, Users, Activity, DB


TOKEN_FILE = '/var/spool/check_certs/TOKEN'

remote_messages: queue.Queue = queue.Queue()

HELP_TEXT='''
A bot for checking SSL/TLS servers certificates.

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
/hold \\[_protocol_://]_hostname_\\[_:port_]  - temporary stop checking this entry.
/unhold \\[_protocol_://]_hostname_\\[_:port_]  - continue checking this entry.
/remove \\[_protocol_://]hostname\\[:_port_] - remove a server from periodical checking list.
/reset  - reset all periodical checking list.
/timezone [+-N] - set timezone correction from UTC. In hours.

Allowed protocols: all from /etc/services.
For mail protocols you can specify domain name not FQDN. It will be checked for MX DNS records first.
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
        send_message_to_user(context.bot, chat_id=chat_id,
                disable_web_page_preview=1, text=msg)
        remote_messages.task_done()

class CheckCertBot:
    '''Main class for the bot'''
    def __init__(self, bot_token, db_url):
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
        unhold_cmd_handler = CommandHandler('unhold', self.unhold_cmd,
                pass_args=True)
        dispatcher.add_handler(unhold_cmd_handler)
        remove_cmd_handler = CommandHandler('remove', self.remove_cmd,
                pass_args=True)
        dispatcher.add_handler(remove_cmd_handler)
        reset_cmd_handler = CommandHandler('reset', self.reset_cmd)
        dispatcher.add_handler(reset_cmd_handler)
        timezone_cmd_handler = CommandHandler('timezone', self.timezone_cmd,
                pass_args=True)
        dispatcher.add_handler(timezone_cmd_handler)

        unknown_cmd_handler = MessageHandler(Filters.command, self.unknown_cmd)
        dispatcher.add_handler(unknown_cmd_handler)

        # Message Filter
        message_filter_handler = MessageHandler(Filters.text, self.message)
        dispatcher.add_handler(message_filter_handler)

        # Run job every 10 seconds
        job_queue.run_repeating(check_queue, interval=10, first=10)

        self.db = DB(db_url)
        self.db.create_db()

    def user_access(self, cmd, message) -> bool:
        '''Check user access'''
        allowed = True
        session = self.db.get_session()
        users_res = session.query(Users).filter(
                Users.id == message.chat_id).one_or_none()
        activity_res = session.query(Activity).filter(
                Activity.user_id == message.chat_id).filter(
                Activity.date.like(
                    datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')+'%')).all()
        # A new user
        if users_res is None:
            user = Users(id=message.chat_id, name=message.chat.username,
                 full_name=message.chat.first_name+' '+message.chat.last_name,
                 language_code = message.from_user.language_code,
                 first_met = datetime.utcnow(),
                 last_activity = datetime.utcnow())
            session.add(user)
        else:
            if users_res.status.lower() == 'ban':
                logging.warning('banned: %s. %s.', message.chat_id, cmd)
                allowed = False
            else:
                # Flood protect
                if len(activity_res) > 0:
                    logging.warning('Flood activity: %s - %d times per '
                        'seconds. Blocked.', message.chat_id, len(activity_res))
                    allowed = False
            users_res.last_activity = datetime.utcnow()

        if not allowed:
            cmd = '!' + cmd

        # Write his activity
        activity = Activity(user_id = message.chat_id, cmd = cmd,
                date = datetime.utcnow())
        session.add(activity)
        session.commit()
        session.close()
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
        chat_id = str(update.message.chat_id)
        if not self.user_access('/id', update.message):
            send_message_to_user(context.bot, chat_id=chat_id,
                    text='You are banned')
            return
        session = self.db.get_session()
        user = session.query(Users).filter(Users.id == chat_id).one_or_none()
        tz = user.timezone
        status = user.status
        session.close()
        if status == '':
            status = 'normal user'
        text = (f'{update.message.chat_id}: {update.message.chat.username} '
            f'{update.message.chat.first_name} {update.message.chat.last_name} '
            f'{update.message.from_user.language_code}'
            f' timezone=UTC{tz:+d} status={status}')
        send_message_to_user(context.bot, chat_id=chat_id, text=text)

    def list_cmd(self, update, context) -> None:
        '''Process /list command'''
        args = context.args
        if not self.user_access(f'/list {args}', update.message):
            return

        chat_id = str(update.message.chat_id)
        session = self.db.get_session()
        user = session.query(Users).filter(Users.id == chat_id).one()
        tz = user.timezone
        session.close()
        # Fields to show. For "full" and "short" list.
        fields: tuple = (
                'when_added', 'url', 'warn_before_expired',
                'last_checked', 'status')
        if len(args) > 0 and args[0] == 'short':
            fields = ('url', 'last_checked', 'status')

        session = self.db.get_session()
        query_res = session.query(Servers).filter(Servers.chat_id == chat_id)

        output: list = []
        line = '|'.join(fields)
        output.append('<b>' + line + '</b>')
        dt_re = re.compile(r'\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d')
        # XXX convert datetime to localzone from UTC
        for res in query_res:
            line = ''
            for field in fields:
                val = str(getattr(res, field))
                if dt_re.match(val):
                    val = datetime_to_user_tz_str(val, tz)
                line += val + '|'
            line = line[:-1]
            output.append(line)

        session.close()

        if len(output) == 1:
            output = ['Empty']

        send_long_message(context.bot, update.message.chat_id,
                '\n'.join(output))

    def add_cmd(self, update, context) -> None:
        '''Process /add command'''
        args = context.args
        chat_id = update.message.chat_id
        if not self.user_access(f'/add {args}', update.message):
            return
        if len(args) < 1:
            send_message_to_user(context.bot, chat_id=chat_id,
                    text='Use /add URL [days]')
            return
        error, url = parse_url(args[0])
        if error != '':
            send_message_to_user(context.bot, chat_id=chat_id,
                    disable_web_page_preview=1, text=f'Parsing error: {error}')
            return
        # Default days to warn
        days = 5
        if len(args) > 1:
            if args[1].isdigit():
                days = int(args[1])
            else:
                send_message_to_user(context.bot, chat_id=chat_id,
                        text='days must be integer')
                return

        # Check for duplicates
        session = self.db.get_session()
        query_res = session.query(Servers.url).filter(Servers.url == url
                             ).filter(Servers.chat_id == chat_id).one_or_none()
        if query_res is not None:
            send_message_to_user(context.bot, chat_id=chat_id,
                    disable_web_page_preview=1, text=f'{url} already exists')
            session.close()
            return
        new_server = Servers(url=url, chat_id=chat_id, warn_before_expired=days)
        session.add(new_server)
        session.commit()
        session.close()

        send_message_to_user(context.bot, chat_id=chat_id,
                                    disable_web_page_preview=1,
                                    text=f'Successfully added: {url}')

    def hold_cmd(self, update, context) -> None:
        '''Process /hold command'''
        args = context.args
        chat_id = update.message.chat_id
        if not self.user_access(f'/hold {args}', update.message):
            return
        if len(args) < 1:
            send_message_to_user(context.bot, chat_id=chat_id,
                    text='Use /hold URL')
            return
        error, url = parse_url(args[0])
        if error != '':
            send_message_to_user(context.bot, chat_id=chat_id,
                    disable_web_page_preview=1, text=f'Parsing error: {error}')
            return

        session = self.db.get_session()
        query = session.query(Servers).filter(Servers.url == url
                                    ).filter(Servers.chat_id == chat_id)
        query.update({Servers.status: 'HOLD'})
        session.commit()
        session.close()

        send_message_to_user(context.bot, chat_id=chat_id,
                                    disable_web_page_preview=1,
                                    text=f'Hold checking for: {url}')

    def unhold_cmd(self, update, context) -> None:
        '''Process /unhold command'''
        args = context.args
        chat_id = update.message.chat_id
        if not self.user_access(f'/unhold {args}', update.message):
            return
        if len(args) < 1:
            send_message_to_user(context.bot, chat_id=chat_id,
                                        text='Use /unhold URL')
            return
        (error, url) = parse_url(args[0])
        if error != '':
            send_message_to_user(context.bot, chat_id=chat_id,
                                        disable_web_page_preview=1,
                                        text=f'Parsing error: {error}')
            return

        session = self.db.get_session()
        query = session.query(Servers).filter(Servers.url == url
                                    ).filter(Servers.chat_id == chat_id)
        query.update({Servers.status: ''})
        session.commit()
        session.close()

        send_message_to_user(context.bot, chat_id=update.message.chat_id,
                                    disable_web_page_preview=1,
                                    text=f'Unhold checking for: {url}')

    def remove_cmd(self, update, context) -> None:
        '''Process /remove command'''
        args = context.args
        chat_id = update.message.chat_id
        deleted = False
        if not self.user_access(f'/remove {args}', update.message):
            return
        if len(args) < 1:
            send_message_to_user(context.bot, chat_id=chat_id,
                                        text='Use /remove URL')
            return
        error, url = parse_url(args[0])
        if error != '':
            send_message_to_user(context.bot, chat_id=chat_id,
                                        disable_web_page_preview=1,
                                        text=f'Parsing error: {error}')
            return
        session = self.db.get_session()
        delete_obj = session.query(Servers).filter(Servers.url == url).filter(
                Servers.chat_id == chat_id).one_or_none()
        if delete_obj is None:
            send_message_to_user(context.bot, chat_id=id,
                                        disable_web_page_preview=1,
                                        text=f'{url} not found')
        else:
            session.delete(delete_obj)
            deleted = True
        session.commit()
        session.close()
        if deleted:
            send_message_to_user(context.bot, chat_id=chat_id,
                                    disable_web_page_preview=1,
                                    text=f'Successfully removed: {url}')

    def reset_cmd(self, update, context) -> None:
        '''Process /reset command'''
        chat_id = update.message.chat_id
        if not self.user_access('/reset', update.message):
            return
        session = self.db.get_session()
        session.query(Servers).filter(Servers.chat_id == chat_id).delete()
        session.commit()
        session.close()
        send_message_to_user(context.bot, chat_id=chat_id,
                                    text='Successfully reseted')

    def timezone_cmd(self, update, context) -> None:
        '''Process /timezone command'''
        args = context.args
        if not self.user_access(f'/timezone {args}', update.message):
            return

        chat_id = str(update.message.chat_id)
        if len(args) != 1:
            send_message_to_user(context.bot, chat_id=chat_id,
                    text='Only one argument allowed and mandatory: +-N')
            return

        failure = False
        if not (args[0][0] in '+-' or args[0][0].isdigit()):
            failure = True
        tz = 0
        try:
            tz = int(args[0])
        except ValueError:
            failure = True

        if abs(tz) > 12:
            failure = True

        if failure:
            send_message_to_user(context.bot, chat_id=chat_id,
                    text='An argument must be: [+-]N. Where N is an integer '
                            'from 0 to 12.')
            return

        session = self.db.get_session()
        user = session.query(Users).filter(Users.id == chat_id).one()
        user.timezone = tz
        session.commit()
        session.close()
        send_message_to_user(context.bot, chat_id=chat_id,
                text=f'Timezone set as UTC{tz:+d}')

    def unknown_cmd(self, update, context) -> None:
        '''Process user errors in command'''
        if not self.user_access('unknown', update.message):
            return
        send_message_to_user(context.bot, chat_id=update.message.chat_id,
                                    text='Unknown command. Try /help.')

    def message(self, update, context) -> None:
        '''Process not command message from the user'''
        chat_id = update.message.chat_id
        allowed_cmd = ('no-tlsa', 'no-ocsp')
        if not self.user_access(update.message.text, update.message):
            return
        url_text, *args = update.message.text.split(' ')
        error, url = parse_url(url_text)
        if error != '':
            send_message_to_user(context.bot, chat_id=chat_id,
                                        disable_web_page_preview=1, text=error)
            return
        if len(args) > 0 and (len(args) > 2 or
                len(set(args)-set(allowed_cmd)) > 0):
            send_message_to_user(context.bot, chat_id=chat_id,
                                        text='wrong arguments')
            return

        # we need no_tlsa style flags. Convert it from no-tlsa.
        args = [a.replace('-', '_') for a in args]
        send_message_to_user(context.bot, chat_id=chat_id,
                                    disable_web_page_preview=1,
                                    text=f'Checking certificate for: {url}')
        proc = Process(target=async_run_func, args=(context.bot, chat_id,
                                                     self.db, url,
                                                     *args))
        proc.start()

def async_run_func(bot, chat_id, db, url, *args) -> None:
    '''Run checks for the URL as an async job'''
    kwargs = {v: True for (_, v) in enumerate(args)}
    error, result = check_cert(url, need_markup=True, **kwargs)
    send_long_message(bot, chat_id, result+error)
    # Write result to DB if we have an entry.
    # Don't use chat_id here, update for all users if have.
    session = db.get_session()
    query_res = session.query(Servers).filter(Servers.url == url).all()
    for res in query_res:
        if error:
            res.last_checked = datetime.utcnow()
            res.status = error
        else:
            res.last_checked = datetime.utcnow()
            res.status = 'OK'
            res.last_ok = datetime.utcnow()
    session.commit()
    session.close()

def main() -> NoReturn:
    '''Main function'''
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--conf', type=str, required=True)
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()

    config = configparser.ConfigParser()
    if config.read(args.conf) == []:
        logging.error('Can\'t read config file: %s', args.conf)
        sys.exit(1)

    try:
        token = config['BOT']['token']
        db_url = config['DB']['url']
    except KeyError:
        logging.error('You must specify both Bot Token and DB URL in config '
                        'file')
        sys.exit(1)

    if args.debug:
        logging.basicConfig(
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                level=logging.DEBUG)
    else:
        logging.basicConfig(
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                level=logging.WARNING)

    rpyc_log = logging.getLogger('RPYC')
    rpyc_log.setLevel(logging.ERROR)
    rpyc_server = ThreadedServer(RPyCService, port=18861, logger=rpyc_log)
    thr = threading.Thread(target = rpyc_server.start)
    thr.daemon = True
    thr.start()

    bot = CheckCertBot(token, db_url)
    bot.start()

if __name__ == '__main__':
    main()
