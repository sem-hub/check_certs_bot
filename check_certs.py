#!/usr/bin/env python3

import argparse
import datetime
import dns.resolver
import ssl
import sys
from pytz import UTC

from os import sys, path

work_dir = path.dirname(path.abspath(__file__))
sys.path.append(work_dir)

from get_cert_from_server import get_chain_from_server
from verify_cert import verify_cert, match_domain
from cert_to_text import cert_to_text
from escape_markdown import escape_markdown

def get_all_dns(dname: str, only_ipv4: bool, only_ipv6: bool, only_first: bool):
    if only_ipv4:
        a1 = list()
    else:
        a1 = get_dns_request(dname, 'AAAA')
    if only_ipv6:
        a2 = list()
    else:
        a2 = get_dns_request(dname, 'A')

    r = list()
    for rdata in a1+a2:
        r.append(rdata.to_text())
        if only_first:
            break
    return r

def get_dns_request(dname: str, rtype: str):
    a = list()
    try:
        answers = dns.resolver.resolve(dname, rtype)
    except dns.resolver.NXDOMAIN:
        print('No DNS record %s found for %s' % (rtype,fqdn))
        sys.exit(0)
    except dns.resolver.NoAnswer:
        pass
    else:
        for rdata in answers:
            a.append(rdata)
    return a

def check_cert(fqdn: str, port: int, proto: str, flags):
    # For fast using
    debug = flags['debug']
    quiet = flags['quiet']

    try:
        dname = dns.name.from_text(fqdn)
    except EmptyLabel:
        print('Host name is invalid: %d' % fqdn)
        return False

    addresses = list()

    if proto == 'smtp':
        if not quiet:
            print('MX records for %s:' % fqdn)
        for rdata in get_dns_request(dname, 'MX'):
            mx_host = rdata.exchange.to_text()[:-1]
            if not quiet:
                print('  %s' % mx_host)
            for addr in get_all_dns(rdata.exchange, flags['only_ipv4'],
                    flags['only_ipv6'], flags['only_one']):
                addresses.append((mx_host,addr))

    # if we don't have addresses from MX records
    if len(addresses) == 0:
        for addr in get_all_dns(dname, flags['only_ipv4'], flags['only_ipv6'], flags['only_one']):
            addresses.append((fqdn,addr))

    if len(addresses) == 0:
        print('No address records found for %s' % fqdn)
        sys.exit(0)
    else:
        if not quiet:
            print('%d DNS address[es] found for %s:' % (len(addresses), fqdn))

    cert0_id = 0
    for addr in addresses:
        # if not debug
        if not quiet:
            print('%s: %s' % addr)
        error, chain = get_chain_from_server(addr[0], addr[1], port, proto)
        if error:
            print('Error: %s' % error)
            continue
        # XXX debug only
        if not quiet:
            print('Got %d certificates in chain' % len(chain))
        cert = chain[0]
        if not cert0_id:
            cert0_id = cert.get_serial_number()
            error = verify_cert(chain)
            if flags['print_id']:
                print('ID: %X' % cert.get_serial_number())
            if not quiet:
                print(cert_to_text(cert))
            if error:
                print('Certificate error: %s' % error)
        else:
            if cert.get_serial_number() != cert0_id:
                print('Certificates are differ')
                error = verify_cert(chain)
                if flags['print_id']:
                    print('ID: %X' % cert.get_serial_number())
                if not quiet:
                    print(cert_to_text(cert))
                if error:
                    print('Certificate error: %s' % error)
            else:
                # Do not check for hostname mismatch
                error = 'the same'
                if not quiet:
                    print('Certificate is the same')

        if not error:
            if not match_domain(fqdn, cert):
                # XXX print domain list from certificate if verbose or debug
                print('Certificate error: Host name mismatched with any ' + \
                        'domain in certificate')
            else:
                if not quiet:
                    print('Certificate is good')

    return True

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
                        help='Make a warning before certificate expired')
    parser.add_argument('-4', '--only-ipv4', action='store_true',
                        help='Use only IPv4 addresses for checks')
    parser.add_argument('-6', '--only-ipv6', action='store_true',
                        help='Use only IPv6 addresses for checks')
    parser.add_argument('-1', '--only-one', action='store_true',
                        help='Use only first IP for checking')
    args = parser.parse_args()
    fqdn = args.fqdn[0]

    flags = dict()
    flags['debug'] = args.debug
    flags['quiet'] = args.quiet
    flags['print_id'] = args.print_id
    flags['warn_before_expired'] = args.warn_before_expired
    flags['only_ipv4'] = args.only_ipv4
    flags['only_ipv6'] = args.only_ipv6
    flags['only_one'] = args.only_one

    if args.proto != None:
        proto = args.proto
    else:
        proto = 'https'
    if args.port == None:
        if proto == 'plain':
            print('Port is mandatory for plain protocol')
            sys.exit(1)
        if proto == 'smtp':
            port = 25
        else:
            port = 443
    else:
        port = args.port

    if not args.quiet:
        print('proto=%s fqdn=%s port=%d' % (proto, fqdn, port))

    check_cert(fqdn, port, proto, flags)
