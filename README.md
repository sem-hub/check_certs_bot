# CheckCertBot

Telegram bot to check SSL/TLS certificates online.

It can store hosts in DB and check them periodicaly.
Understands HTTPS, SMTPS and plain SSL/TLS conection.

Containts a few utilities and a library with useful functions.

Python3 only.

## Installation

```bash
pip install build
python -m build
pip install dist/check_certs_bot-*.tar.gz
```

## Usage

check_certs_bot.py - The bot itself. Does not daemonify.

Register own bot with BotFather, put a token in check-certs.ini file and run.
Use /start and /help for getting help.

You can use check-certs-bot.service for run it with systemd. Edit it for correct pathes.
```bash
cp check-certs-bot.service /etc/systemd/system
systemctl daemon-reload
systemctl enable check-certs-bot
systemctl start check-certs-bot
```

check_certs.py - utility to check server's certificate:
```bash
check_certs.py protocol://server.domain:port 
check_certs.py --help
```

periodic_check.py - run periodic checks for domains from DB.
Adding domains into DB with the bot mentioned above.
Use it with cron(8).
crontab -e example:
```
3 5 * * * /usr/local/bin/periodic_check.py -c check-certs.ini
```

generate_tlsa.py - Generate TLSA records for DNS server (bind format).
It takes list of URLs from file or stdin. If argument is URL it will make only
one TLS RR for it.

## License
[MIT](https://choosealicense.com/licenses/mit/)
