'''A function for checking certificate.'''

import logging
from typing import Tuple

from check_certs_lib.check_validity import parse_and_check_url
from check_certs_lib.get_cert_from_server import get_chain_from_server
from check_certs_lib.verify_cert import verify_cert, match_domain, get_days_before_expired
from check_certs_lib.cert_to_text import cert_to_text, need_bold
from check_certs_lib.dns_requests import get_dns_request, check_fqdn, get_all_dns
from check_certs_lib.tlsa import check_tlsa
from check_certs_lib.ocsp import check_ocsp


MAIL_PROTO = ('smtp', 'smtps', 'submission')
NULL = ''

# Return (error, result)
def check_cert(url_str: str, **flags) -> Tuple[str, str]:
    '''
    Make all checks for X509 certificate

    Get a server URL and some flags as arguments.

    Flags: dict(name, value)
        Where name is a flag name, most flags are bool.
        warn_before_expired is a number days user will warn before
            certificate will expire.

    Supported flags:
        quiet - don't output anything except errors.
        need_markup - markup output with some HTML tags for telegram Bot.
        only_ipv4 - use only IPv4 addresses for checking.
        only_ipv6 - use only IPv6 addresses for checking.
        only_one - use only firsm met IP after resolve for checking.
        print_id - print certificate ID as first line. For periodic_check.py.
        warn_before_expired - add warn user if certificate will expire <= days
                                after today.
        no-tlsa - disable TLSA checks (certificate pinning in DNS).
                    These checks include DNSSEC protected requests.
        no-ocsp - disable OCSP checks (if certificate revoked or not).

        TLSA and OCSP are most long checks.

    Return: tuple(error, result)

    '''
    logger = logging.getLogger(__name__)
    # For fast using
    quiet = flags.get('quiet', False)
    need_markup = flags.get('need_markup', False)
    only_ipv4 = flags.get('only_ipv4', False)
    only_ipv6 = flags.get('only_ipv6', False)
    only_one = flags.get('only_one', False)

    b = need_bold(need_markup)

    error, (proto, fqdn, port) = parse_and_check_url(url_str)
    if error:
        return (error, NULL)
    if not check_fqdn(fqdn):
        return (f'Host name is invalid: {fqdn}\n', NULL)

    logger.debug('%s %s %s', proto, fqdn, port)

    addresses: list = []
    error_msg: str = ''
    message: str = ''

    if proto in MAIL_PROTO:
        if not quiet:
            message += f'MX records for {fqdn}:\n'
        for rdata in get_dns_request(fqdn, 'MX', quiet):
            mx_host = rdata.exchange.to_text()[:-1]
            if not quiet:
                message += f'  {mx_host}\n'
            for addr in get_all_dns(rdata.exchange, only_ipv4,
                                    only_ipv6, only_one):
                addresses.append((mx_host, addr))

    # if we don't have addresses from MX records
    if len(addresses) == 0:
        for addr in get_all_dns(fqdn, only_ipv4, only_ipv6, only_one):
            addresses.append((fqdn, addr))

    if len(addresses) == 0:
        error_msg += f'No address records found for {fqdn}\n'
        return (error_msg, NULL)
    if not quiet:
        message += f'{len(addresses)} DNS address[es] found for {fqdn}:\n'

    cert0_id = 0
    for addr in addresses:
        if not quiet:
            message += f'{addr[0]}: {addr[1]}\n'
        error, chain = get_chain_from_server(addr[0], addr[1], port, proto)
        if error:
            error_msg += f'Error: {error}\n'
            continue
        if not quiet:
            message += f'Got {len(chain)} certificates in chain\n'
        cert = chain[0]
        is_new_cert = not cert0_id
        if is_new_cert:
            cert0_id = cert.get_serial_number()

        # Do not check the same certificate again
        if not is_new_cert and cert.get_serial_number() == cert0_id:
            if not quiet:
                message += 'Certificate is the same\n'
        else:
            if cert.get_serial_number() != cert0_id:
                error_msg += 'Certificates are differ\n'

            error = verify_cert(chain)

            if flags.get('print_id'):
                message += 'ID: {:X}\n'.format(cert.get_serial_number())
            if not quiet:
                message += cert_to_text(cert, need_markup) + '\n'

            # If we have bad certificate here, don't check it for matching
            if error:
                error_msg += f'Certificate error: {error}\n'
                continue
            if not match_domain(fqdn, cert):
                error_msg += 'Certificate error: Host name ' + \
                            'mismatched with any domain in certificate\n'
                continue
            days_before_expired = get_days_before_expired(cert)
            if flags.get('warn_before_expired') and \
                    days_before_expired <= flags['warn_before_expired']:
                error_msg += 'Certificate will expired ' + \
                            f'after {days_before_expired} days\n'
            else:
                # ocspcheck can't check only one certificate. It needs a chain
                if len(chain) > 1 and not flags.get('no_ocsp'):
                    logger.debug('check OCSP')
                    error, result = check_ocsp(chain)
                    if error:
                        error += f'OCSP error: {error}\n'
                        continue
                    if result != 'GOOD':
                        error += f'OCSP error: {b(result)}\n'
                        continue
                    if not quiet:
                        message += f'OCSP check result: {b(result)}\n'
                if not quiet:
                    message += 'Certificate is good\n'
            # only good certificate here
            # Run TLSA check if we have TLSA record
            if not flags.get('no_tlsa'):
                logger.debug('check TLSA')
                error, result = check_tlsa(fqdn, port, chain[0], quiet)
                if not error:
                    if not quiet:
                        message += f'TLSA is {b("OK")}\n'
                else:
                    if error == 'not found':
                        if not quiet:
                            error_msg += 'TLSA is not found. Ignored\n'
                    else:
                        error_msg += f'TLSA is {b(result)}\n'

    return (error_msg, message)
