#!/usr/bin/env python3

import telegram
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters
import logging
import rpyc
import sqlite3
import subprocess
import queue
import threading
from urllib.parse import urlsplit
from os import sys, path

work_dir = path.dirname(path.abspath(__file__))
sys.path.append(work_dir)

from is_valid_fqdn import is_valid_fqdn

help_text='''
A bot for checking HTTP servers certificates.

Enter:
_URL_
or
_hostname_ \\[_proto_] \\[_port_]

or a command:
/help   - show this help message.
/list   - list server names for periodically checking.
/add _proto://hostname:port_
or
/add _hostname_ \\[_protocol_] \\[_port_] \\[_days_]   - add a server to periodical checking. _days_ - warn if days till certificate expire will happen.
/hold _hostname_  \\[_port_]  - temporary stop checking this entry
/unhold _hostname_ \\[_port_]  - continue checking this entry
/remove _proto://hostname:port_
or
/remove _hostname_ \\[_port_] - remove a server from periodical checking list.
/reset  - reset all periodical checking list.

Allowed protocols: *https*, *smtp* and *plain*.
For *smtp* default port is 25 and you can specify domain name not FQDN. It will be checked for MX DNS records first.
*plain* means any protocol over ssl (ssl handshake before any protocol conversation)
'''

create_table_statement='''CREATE TABLE IF NOT EXISTS servers (
when_added text,
hostname text,
proto text,
port text,
chat_id,
warn_before_expired text,
last_checked text,
status text,
cert_id text
)'''

prog_dir = path.dirname(path.abspath(__file__))

def check_validity(proto: str, fqdn: str, port: int):
    error = ''
    valid_proto = ('https', 'smtp', 'plain')
    if proto not in valid_proto:
        error = 'Unknown protocol: %s ' % proto
    if not is_valid_fqdn(fqdn):
        error = error+'Bad server FQDN: %s ' % fqdn
    if port < 1 or port > 65535:
        error = error+'Bad port number: %d ' % port
    return error

def parse_message(message):
    msg = message.strip().lower().encode('ASCII', 'replace').decode('utf-8')
    # defaults
    proto = 'https'
    fqdn = ''
    port = 443
    error = ''
    if msg.find('://') > -1:
        try:
            nt = urlsplit(msg)
            proto = nt.scheme
            fqdn = nt.hostname
            if nt.port:
                port = nt.port
        except ValueError as err:
            error = str(err)
    else:
        n=msg.find(' ')
        if n == -1:
            fqdn = msg
        else:
            (fqdn, proto) = msg.split(' ', 1)
            n = proto.find(' ')
            if n > -1:
                (proto, portStr) = proto.split(' ', 1)
                try:
                    port = int(portStr)
                except ValueError as err:
                    error = str(err)
            else:
                if proto == 'smtp':
                    port = 25
    if not error:
        error = check_validity(proto, fqdn, port)

    return (error, proto, fqdn, str(port))

class RPyCService(rpyc.Service):
    def exposed_add_message(self, chat_id, msg):
        remote_messages.put([chat_id, msg])

class CheckCertBot:
    def __init__(self, bot_token):
        self.updater = Updater(token=bot_token)

        dispatcher = self.updater.dispatcher

        job_queue = self.updater.job_queue

        # register commands handlers
        start_cmd_handler = CommandHandler('start', self.help_cmd)
        dispatcher.add_handler(start_cmd_handler)
        start_cmd_handler = CommandHandler('help', self.help_cmd)
        dispatcher.add_handler(start_cmd_handler)
        client_id_cmd_handler = CommandHandler('client_id', self.client_id_cmd)
        dispatcher.add_handler(client_id_cmd_handler)
        list_cmd_handler = CommandHandler('list', self.list_cmd)
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
        queue_job = job_queue.run_repeating(self.check_queue, interval=10, first=10)

        self.db_connect_and_create_table()

    def check_queue(self, bot, job):
        not_empty = False
        while not remote_messages.empty():
            not_empty = True
            chat_id, msg = remote_messages.get()
            bot.send_message(chat_id=chat_id, text=msg)
        if not_empty:
            remote_messages.task_done()

    def db_connect_and_create_table(self):
        self.con = sqlite3.connect(prog_dir+'/checkcerts.sqlite3',
                check_same_thread=False)
        self.cur = self.con.cursor()
        self.cur.execute(create_table_statement)
        self.con.commit()

    def start(self):
        self.updater.start_polling()
        self.updater.idle()

    def help_cmd(self, bot, update):
        # Remove ReplyKeyboard if it was there
        reply_markup = telegram.ReplyKeyboardRemove(remove_keyboard=True)
        old_message = bot.send_message(chat_id=update.message.chat_id, text='trying', reply_markup=reply_markup, reply_to_message_id=update.message.message_id)
        bot.send_message(chat_id=update.message.chat_id, parse_mode='Markdown', text=help_text)

    def client_id_cmd(self, bot, update):
        bot.send_message(chat_id=update.message.chat_id, text=update.message.chat_id)

    def list_cmd(self, bot, update):
        # XXX datetime('Never', 'localtime') == NoneType
        self.cur.execute("SELECT datetime(when_added, 'localtime'), hostname, proto, port, warn_before_expired, datetime(last_checked, 'localtime'), status FROM servers WHERE chat_id=?", (str(update.message.chat_id),))
        output = []
        for r in self.cur.fetchall():
            output.append('|'.join(r))
        if len(output) == 0:
            output = ['Empty']
        else:
            output.insert(0, '*When added|hostname|proto|port|days to warn before expire|last check date|last check status*')
        bot.send_message(chat_id=update.message.chat_id, text='\n'.join(output))

    def add_cmd(self, bot, update, args):
        (error, proto, fqdn, port) = parse_message(' '.join(args))
        if error != '':
            bot.send_message(chat_id=update.message.chat_id, text='Parsing error: %s' % error)
            return
        # XXX Check for duplicates
        # XXX days is not implemented yet
        self.cur.execute("INSERT INTO servers VALUES (CURRENT_TIMESTAMP, ?, ?, ?, ?, '5', '0000-01-01 00:00:00', 'None', '0')", (fqdn, proto, port, str(update.message.chat_id)))
        self.con.commit()
        bot.send_message(chat_id=update.message.chat_id, text='Successfully added: %s' % fqdn)

    def hold_cmd(self, bot, update, args):
        (error, proto, fqdn, port) = parse_message(' '.join(args))
        if error != '':
            bot.send_message(chat_id=update.message.chat_id, text='Parsing error: %s' % error)
            return
        self.cur.execute("UPDATE servers SET status='HOLD' WHERE hostname=? and port=? and chat_id=?",(fqdn, port, str(update.message.chat_id)))
        self.con.commit()
        bot.send_message(chat_id=update.message.chat_id, text='Hold checking for: %s:%s' % (fqdn, port))

    def unhold_cmd(self, bot, update, args):
        (error, proto, fqdn, port) = parse_message(' '.join(args))
        if error != '':
            bot.send_message(chat_id=update.message.chat_id, text='Parsing error: %s' % error)
            return
        self.cur.execute("UPDATE servers SET status='None' WHERE hostname=? and port=? and chat_id=?", (fqdn, port, str(update.message.chat_id)))
        self.con.commit()
        bot.send_message(chat_id=update.message.chat_id, text='Unhold checking for: %s:%s' % (fqdn, port))

    def remove_cmd(self, bot, update, args):
        (error, proto, fqdn, port) = parse_message(' '.join(args))
        if error != '':
            bot.send_message(chat_id=update.message.chat_id, text='Parsing error: %s' % error)
            return
        self.cur.execute("DELETE FROM servers WHERE hostname=? and port=? and chat_id=?", (fqdn, port, str(update.message.chat_id)))
        self.con.commit()
        bot.send_message(chat_id=update.message.chat_id, text='Successfully removed: %s:%s' % (fqdn, port))

    def reset_cmd(self, bot, update):
        self.cur.execute("DELETE FROM servers WHERE chat_id=?", (str(update.message.chat_id),))
        self.con.commit()
        bot.send_message(chat_id=update.message.chat_id, text='Successfully reseted')

    def unknown_cmd(self, bot, update):
        bot.send_message(chat_id=update.message.chat_id, text='Unknown command. Try /help.')

    def message(self, bot, update):
        (error, proto, fqdn, port) = parse_message(update.message.text)
        if error != '':
            bot.send_message(chat_id=update.message.chat_id, disable_web_page_preview=True, text=error)
            return

        bot.send_message(chat_id=update.message.chat_id,
                text='Checking certificate for: %s (%s %s)' % (fqdn, proto, port))
        result = subprocess.check_output([prog_dir+'/check_certs.py', fqdn, proto, port])
        for i in range(0, len(result), 4095):
            bot.send_message(chat_id=update.message.chat_id,
                    parse_mode='Markdown', disable_web_page_preview=True,
                    text=result[i:i+4094].decode('utf8'))

if __name__ == '__main__':
    from rpyc.utils.server import ThreadedServer

    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

    remote_messages = queue.Queue()

    rpyc_log = logging.getLogger('RPYC')
    rpyc_log.setLevel(logging.ERROR)
    rpyc_server = ThreadedServer(RPyCService, port=18861, logger=rpyc_log)
    t = threading.Thread(target = rpyc_server.start)
    t.daemon = True
    t.start()

    token = open(work_dir+'/TOKEN', 'r').read().rstrip('\n')
    bot = CheckCertBot(token)
    bot.start()
