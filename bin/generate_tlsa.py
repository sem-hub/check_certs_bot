#!/usr/bin/env python3

'''
Read URLs list from file or stdin and generate TLSA records to put them to DNS.
'''

import argparse
import logging
import sys

from check_certs_lib.check_validity import parse_and_check_url
from check_certs_lib.dns_requests import check_fqdn, get_dns_request
from check_certs_lib.get_cert_from_server import get_cert_from_server
from check_certs_lib.tlsa import generate_tlsa


def tlsa(url: str):
    '''Generate TLSA record'''
    err, (proto, fqdn, port) = parse_and_check_url(url)
    if err != '':
        return err
    if not check_fqdn(fqdn):
        return f'Host name is invalid: {fqdn}\n'
    logging.debug('%s %s %s', proto, fqdn, port)

    addr = get_dns_request(fqdn, 'A')
    if len(addr) == 0:
        sys.exit(1)
    err, cert = get_cert_from_server(fqdn, addr[0].to_text(), port, proto)
    if err or cert is None:         # Checking cert only for typing check bellow
        logging.error(err)
        sys.exit(1)
    
    tlsa_value = generate_tlsa(cert, 3, 1, 1)
    return (f'_{port:d}._tcp.{fqdn}. IN TLSA 3 1 1 '
           f'{"".join("{:02x}".format(c) for c in tlsa_value)}')

def main():
    '''Main function'''
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('source', nargs='?',
                        help='URL or file with URLs list. If not specified, '
                                'read list from stdin.')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    if not args.source:
        inf = sys.stdin
    else:
        if '://' in args.source:
            print(tlsa(args.source))
            sys.exit(0)
        try:
            inf = open(args.source, 'r')
        except Exception as err:
            logging.error(str(err))
            sys.exit(1)

    urls = inf.readlines()
    for url in urls:
        print(tlsa(url.strip('\n')))

if __name__ == '__main__':
    main()
