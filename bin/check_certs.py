#!/usr/bin/env python3

import argparse
import logging

from check_certs_lib.check_certs import check_cert

# MAIN ()
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('url', nargs=1, help='protocol://hostname.domain:port')
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
    parser.add_argument('-m', '--markup', action='store_true',
                        help='Use markup for printing certificate data')
    parser.add_argument('--no-tlsa', action='store_true',
                        help='Prevent TLSA checking')
    parser.add_argument('--no-ocsp', action='store_true',
                        help='Prevent OCSP checking')
    args = parser.parse_args()
    url = args.url[0]

    flags = dict()
    flags['quiet'] = args.quiet
    flags['print_id'] = args.print_id
    flags['warn_before_expired'] = args.warn_before_expired
    flags['only_ipv4'] = args.only_ipv4
    flags['only_ipv6'] = args.only_ipv6
    flags['only_one'] = args.only_one
    flags['need_markup'] = args.markup
    flags['no_tlsa'] = args.no_tlsa
    flags['no_ocsp'] = args.no_ocsp

    if args.debug:
      logging.basicConfig(level=logging.DEBUG)
    else:
      logging.basicConfig(format='%(message)s', level=logging.INFO)

    if '://' not in url:
        url = 'https://' + url

    logging.debug(f'url={url}')

    print(check_cert(url, **flags), end='')
