#!/usr/bin/env python3

import argparse
import datetime
import logging
import ssl
import sys
from pytz import UTC

from os import sys, path

work_dir = path.dirname(path.abspath(__file__))
sys.path.append(work_dir)

from get_cert_from_server import get_chain_from_server
from verify_cert import verify_cert, match_domain, get_days_before_expired
from cert_to_text import cert_to_text
from escape_markdown import escape_markdown
from dns_requests import get_dns_request, check_fqdn, get_all_dns, get_tlsa_record
from tlsa import check_tlsa
from ocsp import check_ocsp

def check_cert(fqdn: str, port: int, proto: str, flags: dict) -> str:
    message = ''
    # For fast using
    quiet = flags['quiet']

    if not check_fqdn(fqdn):
        message = message + 'Host name is invalid: %s\n' % fqdn
        return message

    addresses = list()

    if proto == 'smtp':
        if not quiet:
            message = message + 'MX records for %s:\n' % fqdn
        for rdata in get_dns_request(fqdn, 'MX', quiet):
            mx_host = rdata.exchange.to_text()[:-1]
            if not quiet:
                message = message + '  %s\n' % mx_host
            for addr in get_all_dns(rdata.exchange, flags['only_ipv4'],
                    flags['only_ipv6'], flags['only_one']):
                addresses.append((mx_host,addr))

    # if we don't have addresses from MX records
    if len(addresses) == 0:
        for addr in get_all_dns(fqdn, flags['only_ipv4'], flags['only_ipv6'], flags['only_one']):
            addresses.append((fqdn,addr))

    if len(addresses) == 0:
        message = message + 'No address records found for %s\n' % fqdn
        return message
    else:
        if not quiet:
            message = message + '%d DNS address[es] found for %s:\n' % (len(addresses), fqdn)

    cert0_id = 0
    for addr in addresses:
        # XXX if not debug
        if not quiet:
            message = message + '%s: %s\n' % addr
        error, chain = get_chain_from_server(addr[0], addr[1], port, proto)
        if error:
            message = message + 'Error: %s\n' % error
            continue
        # XXX debug only
        if not quiet:
            message = message + 'Got %d certificates in chain\n' % len(chain)
        cert = chain[0]
        is_new_cert = not cert0_id
        if is_new_cert:
            cert0_id = cert.get_serial_number()

        # Do not check the same certificate again
        if not is_new_cert and cert.get_serial_number() == cert0_id:
            if not quiet:
                message = message + 'Certificate is the same\n'
        else:
            if cert.get_serial_number() != cert0_id:
                message = message + 'Certificates are differ\n'

            error = verify_cert(chain)

            if flags['print_id']:
                message = message + 'ID: %X\n' % cert.get_serial_number()
            if not quiet:
                message = message + cert_to_text(cert) + '\n'

            # If we have bad certificate here, don't check it for matching
            if error:
                message = message + 'Certificate error: %s\n' % error
                continue
            else:
                if not match_domain(fqdn, cert):
                    # XXX print domain list from certificate if verbose or debug
                    message = message + 'Certificate error: Host name ' + \
                            'mismatched with any domain in certificate\n'
                    continue
                else:
                    days_before_expired = get_days_before_expired(cert)
                    if flags['warn_before_expired'] and \
                        days_before_expired <= flags['warn_before_expired']:
                            message = message + 'Certificate fill expired ' + \
                                'after %d days\n' % days_before_expired
                    else:
                        # ocspcheck can't check only one certificate. It needs a chain
                        if len(chain) > 1:
                            result = check_ocsp(chain)
                            if result != 'GOOD' or not quiet:
                                message = message + 'OCSP check result: *%s*\n' % result
                            if result != 'GOOD':
                                continue
                        if not quiet:
                            message = message + 'Certificate is good\n'
        # only good certificate here
        # Run TLSA check if we have TLSA record
        if get_tlsa_record(fqdn, port):
            if not check_tlsa(fqdn, port, chain[0]):
                message = message + 'TLSA is *not match*\n'
            else:
                if not quiet:
                    message = message + 'TLSA is *OK*\n'
        else:
            if not quiet:
                message = message + 'No TLSA record found. Check skipped.\n'

    return message

# MAIN ()
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('fqdn', nargs=1)
    parser.add_argument('proto', nargs='?')
    parser.add_argument('port', nargs='?', type=int)
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Print much info for debugging')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Print only error messages')
    parser.add_argument('-id', '--print-id', action='store_true',
                        help='Print certificate ID. Useful with --quiet')
    parser.add_argument('-w', '--warn-before-expired', type=int, default=5,
        help='Make a warning before certificate expired. Default: 5 days. 0 for off.')
    parser.add_argument('-4', '--only-ipv4', action='store_true',
                        help='Use only IPv4 addresses for checks')
    parser.add_argument('-6', '--only-ipv6', action='store_true',
                        help='Use only IPv6 addresses for checks')
    parser.add_argument('-1', '--only-one', action='store_true',
                        help='Use only first IP for checking')
    args = parser.parse_args()
    fqdn = args.fqdn[0]

    flags = dict()
    flags['quiet'] = args.quiet
    flags['print_id'] = args.print_id
    flags['warn_before_expired'] = args.warn_before_expired
    flags['only_ipv4'] = args.only_ipv4
    flags['only_ipv6'] = args.only_ipv6
    flags['only_one'] = args.only_one

    if args.debug:
      logging.basicConfig(level=logging.DEBUG)
    else:
      logging.basicConfig(format='%(message)s', level=logging.INFO)

    if args.proto != None:
        proto = args.proto
    else:
        proto = 'https'
    if args.port == None:
        if proto == 'plain':
            logging.error('Port is mandatory for plain protocol')
            sys.exit(1)
        if proto == 'smtp':
            port = 25
        else:
            port = 443
    else:
        port = args.port

    if not args.quiet:
        logging.info('proto=%s fqdn=%s port=%d' % (proto, fqdn, port))

    print(check_cert(fqdn, port, proto, flags), end='')
