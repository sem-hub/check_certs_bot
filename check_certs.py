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

def get_all_dns(dname):
    a1 = get_dns_request(dname, 'AAAA')
    a2 = get_dns_request(dname, 'A')

    r = list()
    for rdata in a1+a2:
        r.append(rdata.to_text())
    return r

def get_dns_request(dname, rtype):
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

def check_cert(fqdn: str, port: int, proto: str, debug, quiet, print_id, warn_before_expired):
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
            for addr in get_all_dns(rdata.exchange):
                addresses.append((mx_host,addr))

    # if we don't have addresses from MX records
    if len(addresses) == 0:
        for addr in get_all_dns(dname):
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
            if print_id:
                print('ID: %X' % cert.get_serial_number())
            if not quiet:
                print(cert_to_text(cert))
            if error:
                print('Certificate error: %s' % error)
        else:
            if cert.get_serial_number() != cert0_id:
                print('Certificates are differ')
                error = verify_cert(chain)
                if print_id:
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
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--quiet', action='store_true')
    parser.add_argument('--print-id', action='store_true')
    parser.add_argument('--warn-before-expired', type=int, default=5)
    args = parser.parse_args()
    fargs = list()
    fqdn = args.fqdn[0]
    debug = args.debug
    quiet = args.quiet
    print_id = args.print_id
    warn_before_expired = args.warn_before_expired
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

    if not quiet:
        print('proto=%s fqdn=%s port=%d' % (proto, fqdn, port))

    check_cert(fqdn, port, proto, debug, quiet, print_id, warn_before_expired)
